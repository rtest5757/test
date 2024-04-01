import datetime
from pathlib import Path

from django.contrib.admin.utils import flatten
from django.test import TestCase
from django.utils import timezone
from impersonate.settings import User
from model_bakery import baker
from approvals.models import VersionApprovalConfig
from megdocs.constants import REVIEW_FREQUENCY_ANNUAL, DOCUMENT_FILTER_DATE_NEXT_REVIEW, CHANGE_REQUEST_ACTION_TYPE_NEW, \
    DOCUMENT_CHANGE_REQUEST_STATUS_PENDING, DOCUMENT_CHANGE_REQUEST_STATUS_APPROVED, \
    DOCUMENT_CHANGE_REQUEST_STATUS_FINISHED, CHANGE_REQUEST_ACTION_TYPE_EDIT, CHANGE_REQUEST_ACTION_TYPE_ARCHIVE
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils.datastructures import MultiValueDict
from megdocs.forms import CreateFolderForm, DocumentFilterForm, DocumentBulkUploadForm, DocumentEditForm, \
    DocumentShareForm, DocumentNewRequestForm, ChangeRequestNewVersionForm, DocumentEditRequestForm
from megdocs.models import Folder, FolderQuerySet, Document, VersionApproval, VersionQuerySet, Version, \
    DocumentQuerySet, FolderPermissionRule, DocumentChangeRequest
from megforms.models import Auditor, Institution, AuditorQueryset, AuditForm, Ward, Team
from megforms.test_utils import IS_ENGLISH_LOCALE, AuditorInstitutionTestMixin
from megforms.utils import get_permissions, get_permission_by_name


class FormTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.auditor: Auditor = baker.make(Auditor, institution__name='Test Institution', user__user_permissions=get_permissions([
            'megdocs.approve_version', 'megdocs.change_document_owner', 'megdocs.change_document',
        ]))
        cls.institution: Institution = cls.auditor.institution
        cls.user: User = cls.auditor.user
        cls.institution: Institution = cls.auditor.institution

    def test_create_folder_form(self):
        with self.subTest("ensure institution folder filtering"):
            folder_institution = baker.make(Folder, institution=self.auditor.institution)
            folder = baker.make(Folder)
            unpublished_child = baker.make(Folder, institution=self.auditor.institution, parent=folder_institution, publish=False)
            form = CreateFolderForm({}, user=self.user, institution=self.auditor.institution)
            folders = form.fields['parent'].queryset
            self.assertIn(folder_institution, folders)
            self.assertNotIn(folder, folders)
            self.assertNotIn(unpublished_child, folders)
        with self.subTest("ensure instance is filtered out of parent qs"):
            form = CreateFolderForm({}, user=self.user, institution=self.auditor.institution, instance=folder_institution)
            self.assertNotIn(folder_institution, form.fields['parent'].queryset)

    def test_create_folder_form__wards_ringfencing(self):
        ward_auditor = baker.make(Ward, name="auditor", department__institution=self.auditor.institution)
        ward_other = baker.make(Ward, name="other", department__institution=self.auditor.institution)
        self.auditor.wards.add(ward_auditor)
        form = CreateFolderForm({}, user=self.user, institution=self.auditor.institution)
        wards = form.fields['wards'].queryset
        self.assertIn(ward_auditor, wards)
        self.assertNotIn(ward_other, wards)

    def test_update_folder_wards_clean(self):
        ward_auditor = baker.make(Ward, name="auditor", department__institution=self.auditor.institution)
        ward_other = baker.make(Ward, name="other", department__institution=self.auditor.institution)
        self.auditor.wards.add(ward_auditor)
        folder: Folder = Folder.objects.create(name="Folder", owner=self.auditor, parent=None, institution=self.institution)
        folder.wards.add(ward_other)
        form = CreateFolderForm({
            'name': 'new name',
            'owner': folder.owner,
            'parent': folder.parent,
            'wards': [ward_auditor.pk]
        }, user=self.user, institution=self.auditor.institution, instance=folder)
        self.assertTrue(form.is_valid(), msg=form.errors.as_text())
        folder = form.save()
        self.assertEqual(set(folder.wards.all()), {ward_auditor, ward_other})

    def test_available_reviewers(self):
        document: Document = baker.make(Document, current_version__approved=True, institution=self.institution)
        versions: VersionQuerySet = Version.objects.filter(document=document)
        with self.subTest("auditor is originally in auditor queryset"):
            form1 = DocumentEditForm({}, user=self.user, institution=self.institution, instance=document, versions=versions)
            form2 = DocumentBulkUploadForm({}, auditor=self.auditor, institution=self.institution)
            forms = [form1, form2]
            for form in forms:
                available_reviewers = form.fields['reviewer'].queryset
                self.assertIn(self.auditor, available_reviewers)
        with self.subTest("auditor is now unpublished and not in reviewer queryset"):
            self.user.auditor.publish = False
            self.user.auditor.save()
            form1 = DocumentEditForm({}, user=self.user, institution=self.institution, instance=document, versions=versions)
            form2 = DocumentBulkUploadForm({}, auditor=self.auditor, institution=self.institution)
            forms = [form1, form2]
            for form in forms:
                available_reviewers = form.fields['reviewer'].queryset
                self.assertNotIn(self.auditor, available_reviewers)
        with self.subTest("auditors user account is now made inactive"):
            self.user.auditor.publish = True
            self.user.auditor.save()
            self.user.is_active = False
            self.user.save()
            form1 = DocumentEditForm({}, user=self.user, institution=self.institution, instance=document,
                                     versions=versions)
            form2 = DocumentBulkUploadForm({}, auditor=self.auditor, institution=self.institution)
            forms = [form1, form2]
            for form in forms:
                available_reviewers = form.fields['reviewer'].queryset
                self.assertNotIn(self.auditor, available_reviewers)

    def test_clean_form(self):
        pdf_file = SimpleUploadedFile("myfile.pdf", b"Some dummy data", 'document_files')
        post_dict = {
            'creation_date': datetime.datetime.now().date(),
            'initial_version': 1,
            'reviewer': self.auditor,
            'contributors': [],
            'required_approvals': 1,
            'publish': True
        }
        file_dict = MultiValueDict({'document_files': [pdf_file]})
        with self.subTest("Standard form success"):
            form = DocumentBulkUploadForm(post_dict, file_dict, auditor=self.auditor, institution=self.institution)
            self.assertTrue(form.is_valid())
        with self.subTest("Too many required_approvals fails"):
            post_dict['required_approvals'] = 3
            form = DocumentBulkUploadForm(post_dict, file_dict, auditor=self.auditor, institution=self.institution)
            self.assertFalse(form.is_valid())
        with self.subTest("required_approvals>1 and appropriate contributors succeeds and creates approvals"):
            auditor_permissions = get_permissions(['megdocs.approve_version', 'megdocs.change_document_owner', 'megdocs.change_document'])
            auditors = [baker.make(Auditor, institution=self.institution, user__user_permissions=auditor_permissions) for _ in range(0, 3)]
            post_dict['contributors'] = auditors
            form = DocumentBulkUploadForm(post_dict, file_dict, auditor=self.auditor, institution=self.institution)
            self.assertTrue(form.is_valid())
            pre_form_approvals = VersionApproval.objects.all()
            self.assertEqual(len(list(pre_form_approvals)), 0)
            form.create()
            approvals = VersionApproval.objects.all()
            self.assertEqual(len(list(approvals)), 4)

    def test_bulk_upload(self):
        form = DocumentBulkUploadForm({}, auditor=self.auditor, institution=self.institution)
        with self.subTest("field tuples"):
            self.assertEqual(form.additional_settings, ("reviewer", "contributors", "required_approvals", "publish", "review_interval", "creation_date",))
            self.assertEqual(form.advanced_settings, ('initial_version', 'audit_forms', 'documents', 'version_name', 'leads',))
        with self.subTest("form ringfencing"):
            audit_form: AuditForm = baker.make(AuditForm, institution=self.institution)
            other_form: AuditForm = baker.make(AuditForm, institution=self.institution)
            self.auditor.forms.add(audit_form)
            upload_form = DocumentBulkUploadForm({}, auditor=self.auditor, institution=self.institution)
            forms = upload_form.fields['audit_forms'].queryset
            self.assertIn(audit_form, forms)
            self.assertNotIn(other_form, forms)
        with self.subTest("leads ringfencing"):
            self.assertEqual(form.fields['reviewer'].queryset.count(), form.fields['leads'].queryset.count())
        with self.subTest("documents ringfencing"):
            document: Document = baker.make(Document, institution=self.institution)
            other_institution: Document = baker.make(Document)
            foldered: Document = baker.make(Document, institution=self.institution, folder=baker.make(Folder))
            documents: DocumentQuerySet = DocumentBulkUploadForm({}, auditor=self.auditor, institution=self.institution).fields['documents'].queryset
            self.assertIn(document, documents)
            self.assertNotIn(other_institution, documents)
            self.assertNotIn(foldered, documents)
        with self.subTest("folder qs"):
            folder_institution = baker.make(Folder, institution=self.auditor.institution)
            folder = baker.make(Folder)
            unpublished_child = baker.make(Folder, institution=self.auditor.institution, parent=folder_institution, publish=False)
            folders = DocumentBulkUploadForm({}, auditor=Auditor.objects.get(pk=self.auditor.pk), institution=self.institution).fields['folder'].queryset
            self.assertIn(folder_institution, folders)
            self.assertNotIn(folder, folders)
            self.assertNotIn(unpublished_child, folders)

    def test_edit_form(self):
        document: Document = baker.make(Document, current_version__approved=True, institution=self.institution, owner=self.auditor)
        versions: VersionQuerySet = Version.objects.filter(document=document)
        form = DocumentEditForm({}, user=self.user, institution=self.institution, instance=document, versions=versions)
        self.assertIn('archived', form.fields)
        with self.subTest("form ringfencing"):
            audit_form: AuditForm = baker.make(AuditForm, institution=self.institution)
            other_form: AuditForm = baker.make(AuditForm, institution=self.institution)
            self.auditor.forms.add(audit_form)
            form = DocumentEditForm({}, user=self.user, institution=self.institution, instance=document, versions=versions)
            forms = form.fields['forms'].queryset
            self.assertIn(audit_form, forms)
            self.assertNotIn(other_form, forms)
        with self.subTest("hidden form not affected by edit"):
            document.forms.set([other_form])
            form = DocumentEditForm({
                'name': 'new name',
                'required_approvals': '1',
                'forms': [audit_form.pk],
                'owner': document.owner.pk,
            }, user=self.user, institution=self.institution, instance=document, versions=versions)
            self.assertTrue(form.is_valid(), msg=str(form.errors))
            document = form.save()
            forms = document.forms.all()
            self.assertIn(audit_form, forms)
            self.assertIn(other_form, forms)
            form = DocumentEditForm({
                'name': 'new name',
                'required_approvals': '1',
                'forms': [],
                'owner': document.owner.pk,
            }, user=self.user, institution=self.institution, instance=document, versions=versions)
            document = form.save()
            forms = document.forms.all()
            self.assertNotIn(audit_form, forms)
            self.assertIn(other_form, forms)
        with self.subTest("leads ringfencing"):
            self.assertEqual(form.fields['reviewer'].queryset.count(), form.fields['leads'].queryset.count())
        with self.subTest("documents ringfencing"):
            doc: Document = baker.make(Document, institution=self.institution)
            other_institution: Document = baker.make(Document)
            foldered: Document = baker.make(Document, institution=self.institution, folder=baker.make(Folder))
            documents: DocumentQuerySet = DocumentEditForm({}, user=self.user, institution=self.institution, instance=document, versions=versions).fields['documents'].queryset
            self.assertIn(doc, documents)
            self.assertNotIn(document, documents)
            self.assertNotIn(other_institution, documents)
            self.assertNotIn(foldered, documents)
        with self.subTest("hidden document not affected by edit"):
            document.documents.set([other_institution])
            form = DocumentEditForm({
                'name': 'new name',
                'required_approvals': '1',
                'documents': [doc.pk],
                'owner': document.owner.pk,
            }, user=self.user, institution=self.institution, instance=document, versions=versions)
            self.assertTrue(form.is_valid(), msg=str(form.errors))
            document = form.save()
            documents = document.documents.all()
            self.assertIn(doc, documents)
            self.assertIn(other_institution, documents)
            form = DocumentEditForm({
                'name': 'new name',
                'required_approvals': '1',
                'forms': [],
                'owner': document.owner.pk,
            }, user=self.user, institution=self.institution, instance=document, versions=versions)
            self.assertTrue(form.is_valid(), msg=str(form.errors))
            document = form.save()
            forms = document.documents.all()
            self.assertNotIn(doc, forms)
            self.assertIn(other_institution, forms)
        with self.subTest("folder qs"):
            folder_institution = baker.make(Folder, institution=self.auditor.institution)
            folder = baker.make(Folder)
            unpublished_child = baker.make(Folder, institution=self.auditor.institution, parent=folder_institution, publish=False)
            form = DocumentEditForm({
                'name': 'new name',
                'required_approvals': '1',
                'forms': [],
                'owner': document.owner.pk,
            }, user=self.user, institution=self.institution, instance=document, versions=versions)
            folders = form.fields['folder'].queryset
            self.assertIn(folder_institution, folders)
            self.assertNotIn(folder, folders)
            self.assertNotIn(unpublished_child, folders)

    def test_edit_form_initial_data(self):
        with self.subTest("document contributors selected with published version"):
            doc: Document = baker.make(
                Document,
                current_version__approved=True,
                current_version__contributors=[self.auditor],
                institution=self.institution
            )
            doc_versions: VersionQuerySet = Version.objects.filter(document=doc)
            form = DocumentEditForm({
                'name': 'new name',
                'required_approvals': '1',
                'forms': []
            }, user=self.user, institution=self.institution, instance=doc, versions=doc_versions)
            self.assertEqual(list(form.fields['contributors'].initial), [self.auditor])
            self.assertEqual(form.get_current_version().pk, doc.current_version.pk)

        with self.subTest("document contributors selected with only unpublished version"):
            doc: Document = baker.make(Document, institution=self.institution)
            version: Version = baker.make(Version, approved=False, document=doc, contributors=[self.auditor])

            doc_versions: VersionQuerySet = Version.objects.filter(document=doc)
            form = DocumentEditForm({
                'name': 'new name',
                'required_approvals': '1',
                'forms': []
            }, user=self.user, institution=self.institution, instance=doc, versions=doc_versions)
            self.assertEqual(list(form.fields['contributors'].initial), [self.auditor])
            self.assertEqual(form.get_current_version().pk, version.pk)

        with self.subTest("document reviewer selected with published version"):
            doc: Document = baker.make(
                Document,
                current_version__approved=True,
                current_version__reviewer=self.auditor,
                institution=self.institution
            )
            doc_versions: VersionQuerySet = Version.objects.filter(document=doc)
            form = DocumentEditForm({
                'name': 'new name',
                'required_approvals': '1',
                'forms': []
            }, user=self.user, institution=self.institution, instance=doc, versions=doc_versions)
            self.assertEqual(form.fields['reviewer'].initial, self.auditor)
            self.assertEqual(form.get_current_version().pk, doc.current_version.pk)

        with self.subTest("document reviewer selected with only unpublished version"):
            doc: Document = baker.make(Document, institution=self.institution)
            version: Version = baker.make(Version, approved=False, document=doc, reviewer=self.auditor)

            doc_versions: VersionQuerySet = Version.objects.filter(document=doc)
            form = DocumentEditForm({
                'name': 'new name',
                'required_approvals': '1',
                'forms': []
            }, user=self.user, institution=self.institution, instance=doc, versions=doc_versions)
            self.assertEqual(form.fields['reviewer'].initial, self.auditor)
            self.assertEqual(form.get_current_version().pk, version.pk)

        with self.subTest("document reviewer selected with both published and unpublished versions"):
            doc: Document = baker.make(Document, institution=self.institution)
            published_version: Version = baker.make(Version, approved=True, document=doc, revision=1, reviewer=self.auditor)
            unpublished_version: Version = baker.make(Version, approved=False, document=doc, revision=2, reviewer=self.auditor)
            doc.current_version = published_version
            doc.save()

            doc_versions: VersionQuerySet = Version.objects.filter(document=doc)
            form = DocumentEditForm({
                'name': 'new name',
                'required_approvals': '1',
                'forms': []
            }, user=self.user, institution=self.institution, instance=doc, versions=doc_versions)
            self.assertEqual(form.fields['reviewer'].initial, self.auditor)
            self.assertEqual(form.get_current_version().pk, published_version.pk)
            self.assertNotEqual(form.get_current_version().pk, unpublished_version.pk)

    def test_document_filter_form__init(self):
        form = DocumentFilterForm(data={}, user=self.user, institution=self.institution)
        with self.subTest("properties"):
            self.assertEqual(form.user, self.user)
            self.assertEqual(form.institution, self.institution)
        with self.subTest("initial"):
            self.assertEqual(form.initial['folders'].count(), 0)
            self.assertEqual(form.initial['owners'].count(), 0)
            self.assertEqual(form.initial['reviewers'].count(), 0)
            self.assertIsInstance(form.initial['folders'], FolderQuerySet)
            self.assertIsInstance(form.initial['owners'], AuditorQueryset)
            self.assertIsInstance(form.initial['reviewers'], AuditorQueryset)
        with self.subTest("initial override"):
            form = DocumentFilterForm(data={}, user=self.user, institution=self.institution, initial={'owners': Auditor.objects.filter(pk=self.auditor.pk)})
            self.assertEqual(form.initial['owners'].count(), 1)
            self.assertIn(self.auditor, form.initial['owners'])
        with self.subTest("model select queryset ringfencing"):
            folder_institution = baker.make(Folder, institution=self.institution)
            folder = baker.make(Folder)
            form = DocumentFilterForm(data={}, user=self.user, institution=self.institution)
            folders = form.fields['folders'].queryset
            self.assertIn(folder_institution, folders)
            self.assertNotIn(folder, folders)
            if IS_ENGLISH_LOCALE:
                self.assertEqual(form.fields['date_range'].help_text, 'Filter by modified date')
            self.assertEqual(form.fields['reviewers'].queryset.count(), 0)
            baker.make(Document, current_version__reviewer=self.auditor, institution=self.institution)
            form = DocumentFilterForm(data={}, user=self.user, institution=self.institution)
            self.assertEqual(form.fields['reviewers'].queryset.count(), 1)
            self.assertIn(self.auditor, form.fields['reviewers'].queryset)

    def test_document_filter_form__filter_documents(self):
        named: Document = baker.make(Document, name="verbose_name", institution=self.institution)
        document: Document = baker.make(Document, institution=self.institution)
        now = timezone.now()
        data = {
            'date_range': (now - datetime.timedelta(days=1), now),
        }
        with self.subTest("search"):
            form = DocumentFilterForm(data={'q': 'verbose', **data}, user=self.user, institution=self.institution)
            self.assertTrue(form.is_valid(), msg=str(form.errors))
            documents = form.filter(Document.objects.all())
            self.assertIn(named, documents)
            self.assertNotIn(document, documents)
        with self.subTest("owner"):
            document.owner = self.auditor
            document.save()
            form = DocumentFilterForm(data={'owners': [self.auditor.pk], **data}, user=self.user, institution=self.institution)
            self.assertTrue(form.is_valid(), msg=str(form.errors))
            documents = form.filter(Document.objects.all())
            self.assertNotIn(named, documents)
            self.assertIn(document, documents)
        with self.subTest("reviewer"):
            reviewed: Document = baker.make(Document, current_version__reviewer=self.auditor, institution=self.institution)
            form = DocumentFilterForm(data={'reviewers': [self.auditor.pk], **data}, user=self.user, institution=self.institution)
            self.assertTrue(form.is_valid(), msg=str(form.errors))
            documents = form.filter(Document.objects.all())
            self.assertIn(reviewed, documents)
            self.assertNotIn(document, documents)
            self.assertNotIn(named, documents)
        with self.subTest("folder filtering"):
            folder: Folder = Folder.objects.create(
                name="test folder 1",
                description="",
                owner=self.auditor,
                institution=self.institution,
            )
            foldered: Document = baker.make(Document, folder=folder, institution=self.institution)
            form = DocumentFilterForm(data={'folders': [folder], **data}, user=self.user, institution=self.institution)
            self.assertTrue(form.is_valid(), msg=str(form.errors))
            documents = form.filter(Document.objects.all())
            self.assertIn(foldered, documents)
            self.assertNotIn(document, documents)
            self.assertNotIn(named, documents)
            self.assertNotIn(reviewed, documents)

    def test_document_filter_form__filter_versions(self):
        named: Version = baker.make(Version, document__name="verbose_name", document__institution=self.institution)
        version: Version = baker.make(Version, document__institution=self.institution)
        now = timezone.now()
        data = {
            'date_range': (now - datetime.timedelta(days=1), now),
        }
        with self.subTest("search"):
            form = DocumentFilterForm(data={'q': 'verbose', **data}, user=self.user, institution=self.institution)
            self.assertTrue(form.is_valid(), msg=str(form.errors))
            versions = form.filter(Version.objects.all())
            self.assertIn(named, versions)
            self.assertNotIn(version, versions)
        with self.subTest("owner"):
            document = version.document
            document.owner = self.auditor
            document.save()
            form = DocumentFilterForm(data={'owners': [self.auditor.pk], **data}, user=self.user, institution=self.institution)
            self.assertTrue(form.is_valid(), msg=str(form.errors))
            versions = form.filter(Version.objects.all())
            self.assertNotIn(named, versions)
            self.assertIn(version, versions)
        with self.subTest("reviewer"):
            document = baker.make(Document, current_version__reviewer=self.auditor, institution=self.institution)
            reviewed: Version = document.current_version
            reviewed.document = document
            reviewed.save()
            form = DocumentFilterForm(data={'reviewers': [self.auditor.pk], **data}, user=self.user, institution=self.institution)
            self.assertTrue(form.is_valid(), msg=str(form.errors))
            versions = form.filter(Version.objects.all())
            self.assertEqual(reviewed.document.institution, self.institution)
            self.assertIn(reviewed, versions)
            self.assertNotIn(version, versions)
            self.assertNotIn(named, versions)
        with self.subTest("folder filtering"):
            folder: Folder = Folder.objects.create(
                name="test folder 1",
                description="",
                owner=self.auditor,
                institution=self.institution,
            )
            foldered: Document = baker.make(Document, folder=folder, institution=self.institution, current_version__publish=True)
            foldered_version = foldered.current_version
            foldered_version.document = foldered
            foldered_version.save()
            form = DocumentFilterForm(data={'folders': [folder], **data}, user=self.user, institution=self.institution)
            self.assertTrue(form.is_valid(), msg=str(form.errors))
            versions = form.filter(Version.objects.all())
            self.assertIn(foldered_version, versions)
            self.assertNotIn(version, versions)
            self.assertNotIn(named, versions)
            self.assertNotIn(reviewed, versions)

    def test_document_filter_form__next_review(self):
        # create a document due for review
        due_review: Document = baker.make(Document, review_interval=REVIEW_FREQUENCY_ANNUAL, institution=self.institution)
        version: Version = baker.make(Version, document=due_review, reviewer=self.auditor)
        VersionApprovalConfig(version).approve(self.auditor, True)
        Version.objects.update(creation_date=timezone.localtime() - REVIEW_FREQUENCY_ANNUAL)
        due_review: Document = Document.objects.get()
        not_due_review: Document = baker.make(Document, institution=self.institution)
        self.assertTrue(due_review.is_due_review)
        now = timezone.localdate()
        data = {
            'date_range': (now - datetime.timedelta(days=1), now),
        }
        form = DocumentFilterForm(data={'date_type': [DOCUMENT_FILTER_DATE_NEXT_REVIEW], **data}, user=self.user, institution=self.institution)
        self.assertTrue(form.is_valid(), msg=str(form.errors))
        documents = form.filter(Document.objects.all())
        self.assertIn(due_review, documents)
        self.assertNotIn(not_due_review, documents)

    def test_edit_form_field_groups_include_all_fields(self):
        document: Document = baker.make(Document, institution=self.institution)
        form: DocumentEditForm = DocumentEditForm({}, user=self.user, institution=self.institution, instance=document, versions=document.versions)
        fields: set[str] = set(form.fields.keys())
        fields.add('links')
        self.assertEqual(
            fields,
            set(flatten([fields for layout, fields in form.field_groups]))
        )


class ShareDocumentFormTest(AuditorInstitutionTestMixin, TestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.document: Document = baker.make(Document, institution=cls.institution, owner=cls.auditor, folder__institution=cls.institution)
        cls.another: Auditor = baker.make(Auditor)
        cls.team: Team = baker.make(Team, institution=cls.institution, auditors=[cls.auditor, cls.another], name="team")

    def test_no_users_no_teams_selected(self):
        form = DocumentShareForm(data={}, user=self.user, instance=self.document)
        self.assertFalse(form.is_valid())
        if IS_ENGLISH_LOCALE:
            self.assertIn('Either users or teams should be chosen for sharing a document', form.errors['users'][0])

    def test_share_document(self):
        with self.subTest("invalid user selection"):
            data = {
                'users': [self.user.auditor.pk, self.another.pk],
                'teams': [self.team.pk]
            }
            form = DocumentShareForm(data=data, user=self.user, instance=self.document)
            self.assertFalse(form.is_valid())
            if IS_ENGLISH_LOCALE:
                self.assertIn(f'Select a valid choice. {self.another.pk} is not one of the available choices.', str(form.errors))
        with self.subTest("valid user selection"):
            data = {
                'users': [self.user.auditor.pk],
                'teams': [self.team.pk]
            }
            form = DocumentShareForm(data=data, user=self.user, instance=self.document)
            self.assertTrue(form.is_valid())
            self.assertEqual({self.auditor}, set(form.share_document()))

    def test_teams__qs_filtering(self):
        document: Document = baker.make(Document, institution=self.institution, folder__institution=self.institution)
        with self.subTest("institution ringfencing"):
            baker.make(Team)
            with self.assertNumQueries(2):
                self.assertEqual({self.team}, set(DocumentShareForm(user=self.user, instance=document).fields['teams'].queryset))
        with self.subTest("protected document"):
            view_perm = get_permission_by_name('megdocs.view_document')
            permitted = baker.make(Team, institution=self.institution, name="permitted")
            baker.make(FolderPermissionRule, teams=[permitted], permissions=[view_perm], folders=[document.folder])
            document = Document.objects.get(pk=document.pk)
            with self.assertNumQueries(5):
                self.assertEqual({permitted}, set(DocumentShareForm(user=self.user, instance=document).fields['teams'].queryset))
        with self.subTest("team with permitted user"):
            self.user.user_permissions.add(view_perm)
            baker.make(FolderPermissionRule, folders=[document.folder], users=[self.user], permissions=[view_perm])
            document = Document.objects.get(pk=document.pk)
            with self.assertNumQueries(5):
                self.assertEqual({permitted, self.team}, set(DocumentShareForm(user=self.user, instance=document).fields['teams'].queryset))


class ChangeRequestFormsTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.auditor: Auditor = baker.make(Auditor, institution__name='Test Institution')
        cls.institution: Institution = cls.auditor.institution
        cls.user: User = cls.auditor.user
        cls.institution: Institution = cls.auditor.institution
        cls.document = baker.make(Document, current_version__reviewer=cls.auditor, institution=cls.institution)
        with open(Path.joinpath(Path(__file__).parent, '../scripts/pdf/hand hygiene.pdf'), 'rb') as data_file:
            cls.files = {'file': SimpleUploadedFile('hand_hygiene.pdf', data_file.read(), content_type='application/pdf')}

        reviewed: Version = cls.document.current_version
        reviewed.document = cls.document
        reviewed.save()

    def test_edit_change_request_form(self):
        form = DocumentEditRequestForm(
            instance=DocumentChangeRequest(
                institution=self.institution,
                document=self.document,
                auditor=self.auditor,
            ),
            data=dict(
                description='test desc',
                reason='test reason',
            ),
        )

        form.is_valid()
        change_request: DocumentChangeRequest = form.save()
        self.assertIsInstance(change_request, DocumentChangeRequest)
        self.assertEqual(change_request.description, 'test desc')
        self.assertEqual(change_request.reason, 'test reason')
        self.assertEqual(change_request.is_archive, False)
        self.assertEqual(change_request.is_edit, True)
        self.assertEqual(change_request.type, CHANGE_REQUEST_ACTION_TYPE_EDIT)
        self.assertEqual(change_request.auditor.pk, self.auditor.pk)
        self.assertEqual(change_request.document.pk, self.document.pk)
        self.assertEqual(change_request.version, None)
        self.assertEqual(change_request.status, DOCUMENT_CHANGE_REQUEST_STATUS_PENDING)

        change_request.status = DOCUMENT_CHANGE_REQUEST_STATUS_APPROVED
        change_request.save()

        new_version_form = ChangeRequestNewVersionForm(
            change_request=change_request,
            auditor=self.auditor,
            data=dict(),
            files=self.files
        )

        new_version_form.is_valid()
        version: 'Version' = new_version_form.save()
        self.assertIsInstance(version, Version)

        change_request.refresh_from_db()

        self.assertEqual(change_request.status, DOCUMENT_CHANGE_REQUEST_STATUS_FINISHED)
        self.assertEqual(change_request.version.pk, version.pk)
        self.assertEqual(version.document, self.document)
        self.assertEqual(version.creator, self.auditor)
        self.assertEqual(version.reviewer, self.document.owner)
        self.assertEqual(version.revision, 2)
        self.assertEqual(Path(version.file.name).name, 'hand_hygiene.pdf')

    def test_archive_change_request_form(self):
        form = DocumentEditRequestForm(
            instance=DocumentChangeRequest(
                institution=self.institution,
                document=self.document,
                auditor=self.auditor,
            ),
            data=dict(
                description='test desc',
                reason='test reason',
                is_archived=True
            ),
        )

        form.is_valid()
        change_request: DocumentChangeRequest = form.save()
        self.assertIsInstance(change_request, DocumentChangeRequest)
        self.assertEqual(change_request.description, 'test desc')
        self.assertEqual(change_request.reason, 'test reason')
        self.assertEqual(change_request.is_archive, True)
        self.assertEqual(change_request.is_edit, False)
        self.assertEqual(change_request.type, CHANGE_REQUEST_ACTION_TYPE_ARCHIVE)
        self.assertEqual(change_request.auditor.pk, self.auditor.pk)
        self.assertEqual(change_request.document.pk, self.document.pk)
        self.assertEqual(change_request.version, None)
        self.assertEqual(change_request.status, DOCUMENT_CHANGE_REQUEST_STATUS_PENDING)

        change_request.status = DOCUMENT_CHANGE_REQUEST_STATUS_APPROVED
        change_request.save()

        change_request.archive(self.auditor)

        change_request.refresh_from_db()
        self.document.refresh_from_db()

        self.assertEqual(change_request.status, DOCUMENT_CHANGE_REQUEST_STATUS_FINISHED)
        self.assertEqual(self.document.is_archived, True)
        self.assertEqual(self.document.archived, True)


class NewDocumentRequestFormTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.auditor: Auditor = baker.make(Auditor, institution__name='Test Institution')
        cls.institution: Institution = cls.auditor.institution
        cls.owner: Auditor = baker.make(Auditor, user__username='document_owner', user__is_active=True, institution=cls.institution, user__user_permissions=get_permissions([
            'megdocs.change_document',
        ]))
        cls.user: User = cls.auditor.user
        cls.institution: Institution = cls.auditor.institution
        with open(Path.joinpath(Path(__file__).parent, '../scripts/pdf/hand hygiene.pdf'), 'rb') as data_file:
            cls.files = {'file': SimpleUploadedFile('hand_hygiene.pdf', data_file.read(), content_type='application/pdf')}

    def test_create_new_request_form(self):
        form = DocumentNewRequestForm(
            instance=DocumentChangeRequest(
                institution=self.institution,
                auditor=self.auditor,
                type=CHANGE_REQUEST_ACTION_TYPE_NEW,
            ),
            data=dict(
                description='test desc',
                reason='test reason',
                owner=self.owner.pk,
            ),
        )

        self.assertTrue(form.is_valid(), msg=form.errors)
        change_request: DocumentChangeRequest = form.save()

        self.assertIsInstance(change_request, DocumentChangeRequest)
        self.assertEqual(change_request.description, 'test desc')
        self.assertEqual(change_request.reason, 'test reason')
        self.assertEqual(change_request.is_new, True)
        self.assertEqual(change_request.is_edit, False)
        self.assertEqual(change_request.type, CHANGE_REQUEST_ACTION_TYPE_NEW)
        self.assertEqual(change_request.auditor.pk, self.auditor.pk)
        self.assertEqual(change_request.document, None)
        self.assertEqual(change_request.version, None)
        self.assertEqual(change_request.status, DOCUMENT_CHANGE_REQUEST_STATUS_PENDING)

        # Manually approve
        change_request.status = DOCUMENT_CHANGE_REQUEST_STATUS_APPROVED
        change_request.save()

        new_version_form = ChangeRequestNewVersionForm(
            change_request=change_request,
            auditor=self.auditor,
            data=dict(),
            files=self.files
        )

        new_version_form.is_valid()
        new_version_form.save()
        change_request.refresh_from_db()
        document: Document = change_request.document
        version: Version = change_request.version

        self.assertEqual(document.name, 'hand_hygiene.pdf')
        self.assertEqual(document.description, 'test desc')
        self.assertEqual(document.institution, self.institution)

        self.assertEqual(change_request.status, DOCUMENT_CHANGE_REQUEST_STATUS_FINISHED)
        self.assertEqual(change_request.version.pk, version.pk)
        self.assertEqual(version.document, document)
        self.assertEqual(version.creator, self.auditor)
        self.assertEqual(version.reviewer, document.owner)
        self.assertEqual(version.revision, 1)
        self.assertEqual(Path(version.file.name).name, 'hand_hygiene.pdf')
