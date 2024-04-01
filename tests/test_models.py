import datetime

from django.contrib.auth.models import Permission, User
from django.core import mail
from django.core.mail import EmailMultiAlternatives
from django.templatetags.static import static
from django.test import TestCase
from django.utils import timezone
from django.utils.translation import gettext
from model_bakery import baker

from approvals.models import VersionApprovalConfig
from megdocs.constants import REVIEW_FREQUENCY_ANNUAL, MANAGER_CODENAMES, FOLDER_PERMISSION_APPNAMES, MANAGER, \
    REVIEWER_CODENAMES, REVIEWER, VIEWER_CODENAMES, VIEWER, EXTENSION_PDF, EXTENSIONS_IMAGE, EXTENSIONS_MS_EXCEL, \
    DOCUMENT_SEARCH_TEXT_TITLE, DOCUMENT_SEARCH_TEXT_CONTENT, DOCUMENT_SEARCH_TEXT_TAGS
from megdocs.models import Version, Document, Folder, FolderPermissionRule, DocumentLink
from megforms.models import Auditor, Institution, Team
from megforms.test_utils import IS_ENGLISH_LOCALE, AuditorInstitutionTestMixin
from megforms.utils import get_permission_by_name


class ModelTest(AuditorInstitutionTestMixin, TestCase):
    def test_version__approve(self):
        document: Document = baker.make(Document)
        version: Version = baker.make(Version, document=document, approved=False, reviewer__institution=document.institution)

        self.assertFalse(version.approved)
        self.assertIsNone(document.current_version)

        VersionApprovalConfig(version).approve(version.reviewer, True)

        self.assertTrue(version.approved)

        version = Version.objects.get(pk=version.pk)
        self.assertTrue(version.approved)

        document = Document.objects.get(pk=document.pk)
        self.assertEqual(document.current_version, version)

    def test_documents__due_for_review__exact(self):
        document: Document = baker.make(Document, review_interval=REVIEW_FREQUENCY_ANNUAL)
        version: Version = baker.make(Version, document=document, reviewer__institution=document.institution)
        VersionApprovalConfig(version).approve(version.reviewer, True)
        Version.objects.update(creation_date=timezone.localdate() - REVIEW_FREQUENCY_ANNUAL)
        document: Document = Document.objects.get()
        self.assertTrue(document.is_due_review)
        self.assertEqual(document.review_date, timezone.localdate())
        self.assertIn(document, Document.objects.due_review(exact=True))

    def test_document_due_for_review(self):
        document: Document = baker.make(Document)

        with self.subTest('document without version should not be due for review'):
            self.assertFalse(document.is_due_review)

        with self.subTest('review date should be null'):
            self.assertIsNone(document.review_date)

        version: Version = baker.make(Version, document=document, reviewer__institution=document.institution)
        VersionApprovalConfig(version).approve(version.reviewer, True)

        with self.subTest('document revision date should be a year after version creation date'):
            document = Document.objects.get()
            self.assertEqual(document.review_date, version.creation_date + REVIEW_FREQUENCY_ANNUAL)

        with self.subTest('review_date type should be date'):
            self.assertIsInstance(document.review_date, datetime.date)

        with self.subTest('document with up to date version'):
            document = Document.objects.get()
            self.assertFalse(document.is_due_review)
            self.assertNotIn(document, Document.objects.due_review())

        # Make current version older for further testing

        with self.subTest('document due for review - exact date'):
            today = datetime.date(2020, 1, 1)
            Version.objects.update(creation_date=today - REVIEW_FREQUENCY_ANNUAL)
            document = Document.objects.get()
            self.assertEqual(document.review_date, today)
            self.assertTrue(document.is_due_review)
            self.assertIn(document, Document.objects.due_review(for_date=today))
            self.assertIn(document, Document.objects.upcoming_due_review(for_date=datetime.date(2019, 12, 2)))

        with self.subTest('document due for review - past date'):
            Version.objects.update(creation_date=timezone.datetime(2001, 1, 1))
            document = Document.objects.get()
            self.assertEqual(document.review_date, timezone.datetime(2002, 1, 1).date())
            self.assertTrue(document.is_due_review)
            self.assertNotIn(document, Document.objects.due_review())
            self.assertNotIn(document, Document.objects.due_review(exact=True))
            self.assertIn(document, Document.objects.due_review(exact=False))
            self.assertIn(document, Document.objects.upcoming_due_review(for_date=datetime.date(2001, 12, 2)))

        with self.subTest('review_range method'):
            Version.objects.update(creation_date=timezone.datetime(2001, 1, 1))
            document = Document.objects.get()

            self.assertIn(document, Document.objects.review_range(datetime.date(2002, 1, 1), datetime.date(2002, 1, 30)))
            self.assertIn(document, Document.objects.review_range(datetime.date(2002, 1, 1), datetime.date(2002, 1, 1)))
            self.assertNotIn(document, Document.objects.review_range(datetime.date(2002, 1, 2), datetime.date(2002, 1, 1)))

        with self.subTest('review_map method'):
            Version.objects.update(creation_date=timezone.datetime(2001, 1, 1))
            review_date = timezone.datetime(2002, 1, 1).date()
            document = Document.objects.get()

            self.assertEqual(Document.objects.review_map(), {
                review_date: [document],
            })

    def test_get_new_revision_number(self):
        with self.subTest('first revision'):
            revision: int = Version.objects.get_new_revision_number()
            self.assertEqual(revision, 1)

        document: Document = baker.make(Document)
        baker.make(Version, document=document)
        with self.subTest('second revision'):
            revision = Version.objects.get_new_revision_number()
            self.assertEqual(revision, 2)

        baker.make(Version, document=document, revision=2)
        with self.subTest('third revision'):
            revision = Version.objects.get_new_revision_number()
            self.assertEqual(revision, 3)

        with self.subTest('first version of new document'):
            document2: Document = baker.make(Document)
            revision = Version.objects.filter(document=document2).get_new_revision_number()
            self.assertEqual(revision, 1)

    def test_search(self):
        first_doc: Document = baker.make(Document, name='Test Document', description='Test description')
        first_doc.tags.set(['tag', 'glove'])
        baker.make(Version, content='Test Content', document=first_doc, approved=True, revision=1)
        first_doc.current_version = baker.make(Version, content='More Content', document=first_doc, approved=True, revision=2)
        first_doc.save()
        second_doc = baker.make(Document, name='Another Document', description='second')
        second_doc.tags.set(['tagged', 'glove'])

        with self.subTest('Test Document'):
            result = Document.objects.search('Test Document')
            self.assertIn(first_doc, result)
            self.assertNotIn(second_doc, result)

        with self.subTest('Content'):
            result = Document.objects.search('Content')
            self.assertIn(first_doc, result)
            self.assertNotIn(second_doc, result)
            self.assertEqual(1, len(result))

        with self.subTest('More Content'):
            result = Document.objects.search('More Content')
            self.assertEqual(1, len(result))
            self.assertIn(first_doc, result)

        with self.subTest('Test Content'):
            result = Document.objects.search('Test Content')
            self.assertEqual(0, len(result))

        with self.subTest('Document'):
            result = Document.objects.search('Document')
            self.assertIn(first_doc, result)
            self.assertIn(second_doc, result)

        with self.subTest('glove'):
            result = Document.objects.search('glove')
            self.assertIn(first_doc, result)
            self.assertIn(second_doc, result)
            self.assertEqual(2, len(result))

        with self.subTest('partial tag search'):
            result = Document.objects.search('glove')
            self.assertIn(first_doc, result)
            self.assertIn(second_doc, result)
            self.assertEqual(2, len(result))

        with self.subTest('NONE'):
            result = Document.objects.search('NONE')
            self.assertNotIn(first_doc, result)
            self.assertNotIn(second_doc, result)

        with self.subTest('document name partial spelling'):
            result = Document.objects.search('Docu')
            self.assertIn(first_doc, result)

        with self.subTest('document name case insensitive'):
            self.assertIn(first_doc, list(Document.objects.search('tEsT')))
            self.assertIn(first_doc, list(Document.objects.search('tEsT', [])))
            self.assertIn(first_doc, list(Document.objects.search('tEsT', [DOCUMENT_SEARCH_TEXT_TITLE, DOCUMENT_SEARCH_TEXT_CONTENT, DOCUMENT_SEARCH_TEXT_TAGS])))
            self.assertIn(first_doc, list(Document.objects.search('tEsT', [DOCUMENT_SEARCH_TEXT_TITLE])))
            self.assertNotIn(first_doc, list(Document.objects.search('tEsT', [DOCUMENT_SEARCH_TEXT_CONTENT])))
            self.assertNotIn(first_doc, list(Document.objects.search('tEsT', [DOCUMENT_SEARCH_TEXT_TAGS])))

        with self.subTest('document content partial spelling'):
            self.assertNotIn(first_doc, Document.objects.search('Cont'))
            self.assertNotIn(first_doc, Document.objects.search('Cont', [DOCUMENT_SEARCH_TEXT_CONTENT]))

    def test_auditor_deactivated_email(self):
        auditor: Auditor = baker.make(Auditor, user__username='Old Owner')
        baker.make(Document, owner=auditor, institution=auditor.institution, name='document1')
        baker.make(Document, institution=auditor.institution, name='document2')

        baker.make(Auditor, institution=auditor.institution, user__email='test@megit.com', user__user_permissions=[get_permission_by_name('megdocs.change_document_owner')])

        auditor.user.is_active = False
        auditor.user.save()

        self.assertTrue(mail.outbox)
        email: EmailMultiAlternatives
        email, = mail.outbox
        self.assertEqual(email.subject, gettext('Document owner account has been deactivated'))
        with self.subTest('plain text'):
            if IS_ENGLISH_LOCALE:
                self.assertIn('Dear MEG Docs user,', email.body)
                self.assertIn('This is to let you know that since Old Owner account has been deactivated, the following documents need to be reassigned to a new owner:', email.body)
            self.assertIn('document1', email.body)
            self.assertNotIn('document2', email.body)
        with self.subTest('html'):
            html: str = email.alternatives[0][0]
            if IS_ENGLISH_LOCALE:
                self.assertIn('Dear MEG Docs user,', html)
                self.assertIn('This is to let you know that since Old Owner account has been deactivated, the following documents need to be reassigned to a new owner:', html)
            self.assertIn('document1', html)
            self.assertNotIn('document2', html)

    def test_auditor_deactivated_email__no_documents(self):
        auditor: Auditor = baker.make(Auditor)
        baker.make(Auditor, institution=auditor.institution, user__email='test@megit.com', user__user_permissions=[get_permission_by_name('megdocs.change_document_owner')])

        auditor.user.is_active = False
        auditor.user.save()

        self.assertFalse(mail.outbox)

    def test__folder_permission_rule__role(self):
        institution: Institution = baker.make(Institution, name='Test Institution')
        auditor: Auditor = baker.make(Auditor, institution=institution, user__username='owner')
        folder = Folder.objects.create(name="Folder", owner=auditor, institution=institution)
        team = baker.make(Team, institution=institution)
        with self.subTest("manager"):
            role_permissions = Permission.objects.filter(codename__in=MANAGER_CODENAMES, content_type__app_label__in=FOLDER_PERMISSION_APPNAMES).all()
            rule = baker.make(FolderPermissionRule, name="manager_rule", folders=[folder], teams=[team], owner=auditor, permissions=role_permissions)
            self.assertEqual(rule.role_index, 0)
            self.assertEqual(rule.role, MANAGER)
        with self.subTest("reviewer"):
            role_permissions = Permission.objects.filter(codename__in=REVIEWER_CODENAMES, content_type__app_label__in=FOLDER_PERMISSION_APPNAMES).all()
            rule = baker.make(FolderPermissionRule, name="reviewer_rule", folders=[folder], teams=[team], owner=auditor, permissions=role_permissions)
            self.assertEqual(rule.role_index, 1)
            self.assertEqual(rule.role, REVIEWER)
        with self.subTest("viewer"):
            role_permissions = Permission.objects.filter(codename__in=VIEWER_CODENAMES, content_type__app_label__in=FOLDER_PERMISSION_APPNAMES).all()
            rule = baker.make(FolderPermissionRule, name="viewer_rule", folders=[folder], teams=[team], owner=auditor, permissions=role_permissions)
            self.assertEqual(rule.role_index, 2)
            self.assertEqual(rule.role, VIEWER)

    def test_rule_folders(self):
        institution: Institution = baker.make(Institution, name='Test Institution')
        institution2: Institution = baker.make(Institution, name='Test Institution 2')
        auditor_super: Auditor = baker.make(Auditor, institution=institution, user__is_superuser=True)
        auditor: Auditor = baker.make(Auditor, institution=institution)
        folder_institution: Folder = Folder.objects.create(name="institution", owner=auditor_super, institution=institution)
        folder_super: Folder = Folder.objects.create(name="super", owner=auditor_super, institution=institution2)
        folder_owned: Folder = Folder.objects.create(name="owned", owner=auditor, institution=institution)
        folder_rule: Folder = Folder.objects.create(name="rule_folder", owner=auditor, institution=institution)

        rule: FolderPermissionRule = baker.make(FolderPermissionRule, name="rule", folders=[], institution=institution)
        with self.subTest("all folders in institution"):
            rule_folders = FolderPermissionRule.objects.filter(name="rule").folders()
            self.assertIn(folder_institution, rule_folders)
            self.assertNotIn(folder_super, rule_folders)
            self.assertIn(folder_owned, rule_folders)
            self.assertIn(folder_rule, rule_folders)

        rule.folders.add(folder_rule)
        rule.save()

        with self.subTest("rule folders"):
            rule_folders = FolderPermissionRule.objects.filter(name="rule").folders()
            self.assertNotIn(folder_institution, rule_folders)
            self.assertNotIn(folder_super, rule_folders)
            self.assertNotIn(folder_owned, rule_folders)
            self.assertIn(folder_rule, rule_folders)

        with self.subTest("super"):
            rule_folders = FolderPermissionRule.objects.filter(name="rule").folders(user=auditor_super.user)
            self.assertIn(folder_institution, rule_folders)
            self.assertNotIn(folder_super, rule_folders)
            self.assertIn(folder_owned, rule_folders)
            self.assertIn(folder_rule, rule_folders)

        with self.subTest("owned"):
            rule_folders = FolderPermissionRule.objects.filter(name="rule").folders(user=auditor.user)
            self.assertNotIn(folder_institution, rule_folders)
            self.assertNotIn(folder_super, rule_folders)
            self.assertIn(folder_owned, rule_folders)
            self.assertIn(folder_rule, rule_folders)

        with self.subTest("passed folder"):
            rule_folders = FolderPermissionRule.objects.filter(name="rule").folders(folder=folder_super)
            self.assertNotIn(folder_institution, rule_folders)
            self.assertNotIn(folder_super, rule_folders)
            self.assertNotIn(folder_owned, rule_folders)
            self.assertIn(folder_rule, rule_folders)

    def test_folder_indented_name(self):
        institution: Institution = baker.make(Institution, name='Test Institution')
        auditor: Auditor = baker.make(Auditor, institution=institution)
        folder_top: Folder = Folder.objects.create(name="top", owner=auditor, institution=institution)
        folder_sub: Folder = Folder.objects.create(name="sub", owner=auditor, institution=institution, parent=folder_top)
        folder_sub_sub: Folder = Folder.objects.create(name="sub sub", owner=auditor, institution=institution, parent=folder_sub)
        self.assertEqual(folder_top.indented_name, " top")
        self.assertEqual(folder_sub.indented_name, "--- sub")
        self.assertEqual(folder_sub_sub.indented_name, "------ sub sub")

    def test_folder_documents_count_annotation(self):
        institution: Institution = baker.make(Institution, name='Test Institution')
        auditor: Auditor = baker.make(Auditor, institution=institution)
        folder_top: Folder = Folder.objects.create(name="top", owner=auditor, institution=institution)
        baker.make(Document, institution=institution, folder=folder_top)
        folder_first_a: Folder = Folder.objects.create(name="first a", owner=auditor, institution=institution, parent=folder_top)
        baker.make(Document, institution=institution, folder=folder_first_a)
        baker.make(Document, institution=institution, folder=folder_first_a)
        baker.make(Document, institution=institution, folder=folder_first_a)
        folder_first_b: Folder = Folder.objects.create(name="first b", owner=auditor, institution=institution, parent=folder_top)
        baker.make(Document, institution=institution, folder=folder_first_b)
        baker.make(Document, institution=institution, folder=folder_first_b)

        folder_second_a: Folder = Folder.objects.create(name="second a", owner=auditor, institution=institution, parent=folder_first_a)
        baker.make(Document, institution=institution, folder=folder_second_a)

        folder_second_b: Folder = Folder.objects.create(name="second b", owner=auditor, institution=institution, parent=folder_first_a)
        baker.make(Document, institution=institution, folder=folder_second_b)
        baker.make(Document, institution=institution, folder=folder_second_b)

        folder_second_c: Folder = Folder.objects.create(name="second c", owner=auditor, institution=institution, parent=folder_first_b)

        folder_documents_count_qs = Folder.objects.annotate_documents_count()

        self.assertEqual(folder_documents_count_qs.get(id=folder_top.pk).documents_count, 9)
        self.assertEqual(folder_documents_count_qs.get(id=folder_first_a.pk).documents_count, 6)
        self.assertEqual(folder_documents_count_qs.get(id=folder_first_b.pk).documents_count, 2)
        self.assertEqual(folder_documents_count_qs.get(id=folder_second_a.pk).documents_count, 1)
        self.assertEqual(folder_documents_count_qs.get(id=folder_second_b.pk).documents_count, 2)
        self.assertEqual(folder_documents_count_qs.get(id=folder_second_c.pk).documents_count, 0)

    def test_documents_for_institution(self):
        institution: Institution = baker.make(Institution, name='Test Institution')
        document: Document = baker.make(Document, institution=institution)
        document_2: Document = baker.make(Document)
        documents = Document.objects.for_institutions([institution])
        self.assertIn(document, documents)
        self.assertNotIn(document_2, documents)

    def test_documents__for_user(self):
        institution: Institution = baker.make(Institution, name='Test Institution')
        document: Document = baker.make(Document, institution=institution)
        inaccessible_document: Document = baker.make(Document)
        user: User = baker.make(Auditor, institution=institution).user
        with self.subTest("institution ringfencing"):
            documents = Document.objects.for_user(user)
            self.assertIn(document, documents)
            self.assertNotIn(inaccessible_document, documents)
        with self.subTest("folder ringfencing"):
            document: Document = baker.make(Document, institution=institution, folder=baker.make(Folder, institution=institution))
            inaccessible_document: Document = baker.make(Document, institution=institution, folder=baker.make(Folder))
            documents = Document.objects.for_user(user)
            self.assertIn(document, documents)
            self.assertNotIn(inaccessible_document, documents)

    def test_document_links__for_institutions(self):
        institution: Institution = baker.make(Institution, name='Test Institution')
        link: DocumentLink = baker.make(DocumentLink, document__institution=institution)
        inaccessible_link: DocumentLink = baker.make(DocumentLink)
        documents = DocumentLink.objects.for_institutions([institution])
        self.assertIn(link, documents)
        self.assertNotIn(inaccessible_link, documents)

    def test_document_links__published(self):
        link: DocumentLink = baker.make(DocumentLink)
        inaccessible_link: DocumentLink = baker.make(DocumentLink)
        inaccessible_link.document.unpublish(None)
        documents = DocumentLink.objects.published()
        self.assertIn(link, documents)
        self.assertNotIn(inaccessible_link, documents)

    def test_document_links__for_user(self):
        institution: Institution = baker.make(Institution, name='Test Institution')
        link: DocumentLink = baker.make(DocumentLink, document__institution=institution)
        inaccessible_link: DocumentLink = baker.make(DocumentLink)
        user: User = baker.make(Auditor, institution=institution).user
        with self.subTest("institution ringfencing"):
            documents = DocumentLink.objects.for_user(user)
            self.assertIn(link, documents)
            self.assertNotIn(inaccessible_link, documents)
        with self.subTest("folder ringfencing"):
            link: DocumentLink = baker.make(DocumentLink, document__institution=institution, document__folder=baker.make(Folder, institution=institution))
            inaccessible_link: DocumentLink = baker.make(DocumentLink, document__institution=institution, document__folder=baker.make(Folder))
            documents = DocumentLink.objects.for_user(user)
            self.assertIn(link, documents)
            self.assertNotIn(inaccessible_link, documents)

    def test_document_links__documents(self):
        document: Document = baker.make(Document)
        inaccessible_document: Document = baker.make(Document)
        baker.make(DocumentLink, document=document)
        documents = DocumentLink.objects.documents()
        self.assertIn(document, documents)
        self.assertNotIn(inaccessible_document, documents)

    def test_archived_documents(self):
        with self.subTest("default behavior"):
            archived: Document = baker.make(Document, archived=True, institution__name="one")
            live: Document = baker.make(Document, institution=archived.institution)
            document = Document.objects.archived_documents()
            self.assertIn(archived, document)
            self.assertNotIn(live, document)
        with self.subTest("configurable status"):
            institution: Institution = baker.make(Institution)
            archived_status: Document = baker.make(Document, archived=True, institution=institution)
            live_status: Document = baker.make(Document, archived=False, institution=institution)
            document = Document.objects.archived_documents()
            self.assertIn(archived, document)
            self.assertIn(archived_status, document)
            self.assertNotIn(live, document)
            self.assertNotIn(live_status, document)

    def test_live_documents(self):
        with self.subTest("default behavior"):
            archived: Document = baker.make(Document, archived=True, institution__name="one")
            live: Document = baker.make(Document, institution=archived.institution)
            document = Document.objects.live_documents()
            self.assertNotIn(archived, document)
            self.assertIn(live, document)
        with self.subTest("configurable status"):
            institution: Institution = baker.make(Institution)
            archived_status: Document = baker.make(Document, archived=True, status__color='#ea3d2b', institution=institution, status__institution=institution)
            live_status: Document = baker.make(Document, archived=False, status__color='#ea3d2b', institution=institution, status__institution=institution)
            document = Document.objects.live_documents()
            self.assertNotIn(archived, document)
            self.assertNotIn(archived_status, document)
            self.assertIn(live, document)
            self.assertIn(live_status, document)

    def test_document_is_archived(self):
        with self.subTest("default behavior"):
            archived: Document = baker.make(Document, archived=True, institution__name="one")
            live: Document = baker.make(Document, institution=archived.institution)
            self.assertTrue(archived.is_archived)
            self.assertFalse(live.is_archived)
        with self.subTest("configurable status"):
            institution: Institution = baker.make(Institution)
            archived_status: Document = baker.make(Document, archived=True, status__color='#ea3d2b', institution=institution, status__institution=institution)
            live_status: Document = baker.make(Document, archived=False, status__color='#ea3d2b', institution=institution, status__institution=institution)
            self.assertTrue(archived_status.is_archived)
            self.assertFalse(live_status.is_archived)

    def test_version_file_methods(self):
        with self.subTest("is_pdf"):
            version: Version = baker.make(Version, file='megdocs/documents/test.pdf')
            self.assertTrue(version.is_pdf)
            self.assertEqual(version.extension, EXTENSION_PDF)
            self.assertFalse(baker.make(Version).is_pdf)
            self.assertEqual(version.icon, static('images/document_icons/pdf.svg'))
        with self.subTest("is_image"):
            version: Version = baker.make(Version, file='megforms/static/images/file.png')
            self.assertTrue(version.is_image)
            self.assertTrue(version.extension in EXTENSIONS_IMAGE)
            self.assertFalse(baker.make(Version).is_image)
            self.assertEqual(version.icon, static('images/document_icons/image.svg'))
        with self.subTest("excel"):
            version: Version = baker.make(Version, file='megforms/tests/data/test_template.xlsx')
            self.assertTrue(version.extension in EXTENSIONS_MS_EXCEL)
            self.assertEqual(version.icon, static('images/document_icons/excel.svg'))

    def test_versions__contributors(self):
        auditor_1: Auditor = baker.make(Auditor)
        auditor_2: Auditor = baker.make(Auditor)
        auditor_3: Auditor = baker.make(Auditor)
        auditor_4: Auditor = baker.make(Auditor, publish=False)
        baker.make(Version, contributors=[auditor_1, auditor_2, auditor_4])
        contributors = Version.objects.all().contributors
        self.assertIn(auditor_1, contributors)
        self.assertIn(auditor_2, contributors)
        self.assertNotIn(auditor_3, contributors)
        self.assertNotIn(auditor_4, contributors)

    def test_versions__for_user(self):
        admin: Version = baker.make(Version)
        creator: Version = baker.make(Version, creator=self.auditor)
        reviewer: Version = baker.make(Version, reviewer=self.auditor)
        contributor: Version = baker.make(Version, contributors=[self.auditor])
        document: Document = baker.make(Document, institution=self.institution)
        document_version: Version = baker.make(Version, document=document)
        document.current_version = document_version
        document.save()
        with self.subTest("doesn't have permission"):
            versions = Version.objects.for_user(self.auditor.user)
            self.assertNotIn(admin, versions)
            self.assertIn(creator, versions)
            self.assertIn(reviewer, versions)
            self.assertIn(contributor, versions)
            self.assertIn(document_version, versions)
        with self.subTest("permission added"):
            self.user.user_permissions.add(get_permission_by_name('megdocs.approve_institution_versions'))
            versions = Version.objects.for_user(User.objects.get(pk=self.auditor.user.pk))
            self.assertIn(admin, versions)
            self.assertIn(creator, versions)
            self.assertIn(reviewer, versions)
            self.assertIn(contributor, versions)
