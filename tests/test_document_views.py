import datetime

from django.conf import settings
from django.contrib.auth.models import User
from django.template.response import SimpleTemplateResponse, TemplateResponse
from django.test import TestCase
from django.urls import reverse_lazy, reverse
from django.utils import timezone
from django_otp.plugins.otp_totp.models import TOTPDevice
from model_bakery import baker
from rest_framework.status import HTTP_200_OK, HTTP_404_NOT_FOUND, HTTP_403_FORBIDDEN

from analytics.models import AnalyticsEntry
from approvals.models import VersionApprovalConfig, ApprovalConfig
from megdocs.models import Document, Version, DocumentRelationQuerySet, DocumentQuerySet, Bookmark, Folder, \
    DocumentLink, DocumentCheckbox, DocumentCheckboxState
from megforms.models import Institution, Auditor, AuditForm
from megforms.templatetags.megforms_extras import icon_css_class
from megforms.test_utils import english_test
from megforms.utils import get_permissions, get_permission_by_name
from utils.htmx_test import HTMXTestMixin


class DocumentViewsTest(HTMXTestMixin, TestCase):
    permissions = 'megdocs.view_document', 'megdocs.view_folder'

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.institution: Institution = baker.make(Institution, name='Test Institution', megdocs_enabled=True)
        cls.auditor: Auditor = baker.make(Auditor, institution=cls.institution, user__username='junior', user__user_permissions=get_permissions(cls.permissions, validate=True))
        cls.document_list_url = reverse_lazy('docs:view:doc-list', kwargs={'institution_slug': cls.institution.slug})
        cls.document_list_fullscreen_url = reverse_lazy('docs:view:doc-list-fullscreen', kwargs={'institution_slug': cls.institution.slug})
        cls.doc_list_bookmarks = reverse_lazy('docs:manage:doc-list-bookmarks', kwargs={'institution_slug': cls.institution.slug})

    def setUp(self) -> None:
        super().setUp()
        self.client.force_login(self.auditor.user)
        self.htmx_client.force_login(self.auditor.user)

    @english_test
    def test_document_list(self):
        with self.subTest('Empty list'):
            response = self.client.get(self.document_list_url)
            self.assertEqual(response.status_code, HTTP_200_OK)
            self.assertContains(response, 'Could not find any documents')

        document: Document = baker.make(Document, name='Mopping instructions', institution=self.institution, _fill_optional=['current_version'])
        document.current_version.approved = True
        document.current_version.save()
        document_without_version: Document = baker.make(Document, name='Hand Hygiene Guidelines', institution=self.institution)
        document_other_institution: Document = baker.make(Document, name='Hidden document', _fill_optional=['current_version'])

        # Sanity check
        self.assertNotEqual(document_other_institution.institution, self.institution)

        response: SimpleTemplateResponse = self.client.get(self.document_list_url)
        with self.subTest('Should contain document belonging to this institution'):
            self.assertContains(response, document.name)
        with self.subTest('Should not contain document without version'):
            # Document should not appear until it has a published version
            self.assertNotContains(response, document_without_version.name)
        with self.subTest('Should not contain document belonging to another institution'):
            self.assertNotContains(response, document_other_institution.name)
        with self.subTest('bookmarks'):
            with self.subTest('bookmarks qs should be empty'):
                self.assertIsInstance(response.context_data['bookmarks'], DocumentRelationQuerySet)
                self.assertQuerysetEqual(response.context_data['bookmarks'], Bookmark.objects.none())
            with self.subTest('bookmarks doc ids should be an empty set'):
                self.assertIsInstance(response.context_data['bookmarked_document_ids'], set)
                self.assertEqual(response.context_data['bookmarked_document_ids'], set())
            with self.subTest('document qs should be empty'):
                self.assertIsInstance(response.context_data['bookmarked_documents'], DocumentQuerySet)
                self.assertQuerysetEqual(response.context_data['bookmarked_documents'], Document.objects.none())
            with self.subTest('Add bookmark option should be rendered'):
                self.assertContains(response, 'add_bookmark')
        with self.subTest('Search'):
            another: Document = baker.make(Document, name='Another document', institution=self.institution, _fill_optional=['current_version'])
            now = timezone.now()
            data = {
                'q': 'Mopping',
                'filter_form': 'Apply',
                'date_range': f'{(now - datetime.timedelta(days=1)).strftime("%Y-%m-%d")} - {now.strftime("%Y-%m-%d")}',
            }
            response = self.client.post(self.document_list_url, data=data, follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, 'has-error')
            self.assertContains(response, document.name)
            self.assertNotContains(response, document_other_institution.name)
            self.assertNotContains(response, another.name)

        with self.subTest("bookmark add"):
            response = self.client.post(self.document_list_url, data={
                'add_bookmark': str(document.pk),
            })
            with self.subTest('response'):
                self.assertRedirects(response, self.document_list_url)
            with self.subTest('bookmark should be created'):
                self.assertEqual(1, Bookmark.objects.filter(user=self.auditor.user, document=document).count())

    def test_document_list__bookmarked(self):
        document: Document = baker.make(Document, name='Mopping instructions', institution=self.institution, current_version__approved=True)
        Bookmark.objects.create(user=self.auditor.user, document=document)

        with self.subTest("bookmark render"):
            response: SimpleTemplateResponse = self.client.get(self.document_list_url)
            with self.subTest('bookmarks qs should contain the document'):
                self.assertEqual(list(response.context_data['bookmarks']), list(Bookmark.objects.filter(document_id=document.pk)))
            with self.subTest('bookmarks doc ids should contain document id'):
                self.assertEqual(response.context_data['bookmarked_document_ids'], {document.pk})
            with self.subTest('document qs should contain the document'):
                self.assertEqual(list(response.context_data['bookmarked_documents']), list(Document.objects.filter(pk=document.pk)))
            with self.subTest('Remove bookmark option should be rendered'):
                self.assertContains(response, 'remove_bookmark')

        with self.subTest("bookmark removal"):
            response = self.client.post(self.document_list_url, data={
                'remove_bookmark': str(document.pk),
            })
            with self.subTest('response'):
                self.assertRedirects(response, self.document_list_url)
            with self.subTest('bookmark should be removed'):
                self.assertFalse(Bookmark.objects.count())

    def test_bookmark_list_view(self):
        document: Document = baker.make(Document, name='Mopping instructions', institution=self.institution, _fill_optional=['current_version'], current_version__revision=1)
        Bookmark.objects.create(user=self.auditor.user, document=document)

        response: TemplateResponse = self.client.get(self.doc_list_bookmarks)

        self.assertContains(response, 'Mopping instructions')
        self.assertNotContains(response, 'pending)')

    @english_test
    def test_document_list__full_screen(self):
        with self.subTest('Empty list'):
            response = self.client.get(self.document_list_fullscreen_url)
            self.assertEqual(response.status_code, HTTP_200_OK)
            self.assertContains(response, 'Could not find any documents')

        document: Document = baker.make(Document, name='Mopping instructions', institution=self.institution, _fill_optional=['current_version'], _create_files=True)
        document.current_version.approved = True
        document.current_version.save()
        document_without_version: Document = baker.make(Document, name='Hand Hygiene Guidelines', institution=self.institution)
        document_other_institution: Document = baker.make(Document, name='Hidden document', _fill_optional=['current_version'], _create_files=True)

        # Sanity check
        self.assertNotEqual(document_other_institution.institution, self.institution)

        response = self.client.get(self.document_list_fullscreen_url)
        with self.subTest('Should contain document belonging to this institution'):
            self.assertContains(response, document.name)
        with self.subTest('Should not contain document without version'):
            # Document should not appear until it has a published version
            self.assertNotContains(response, document_without_version.name)
        with self.subTest('Should not contain document belonging to another institution'):
            self.assertNotContains(response, document_other_institution.name)
        with self.subTest('Search'):
            another: Document = baker.make(Document, name='Another document', institution=self.institution, _fill_optional=['current_version'], _create_files=True)
            now = timezone.now()
            data = {
                'q': 'Mopping',
                'filter_form': 'Apply',
                'date_range': f'{(now - datetime.timedelta(days=1)).strftime("%Y-%m-%d")} - {now.strftime("%Y-%m-%d")}',
            }
            response = self.client.post(self.document_list_fullscreen_url, data=data, follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, 'has-error')
            self.assertContains(response, document.name)
            self.assertNotContains(response, document_other_institution.name)
            self.assertNotContains(response, another.name)

    def test_document_list__anonymous(self):
        self.client.logout()

        response = self.client.get(self.document_list_url)
        self.assertRedirects(response, f"{settings.LOGIN_URL}?next={self.document_list_url}")

    def test_document_list__no_view_perm(self):
        self.auditor.user.user_permissions.clear()
        response = self.client.get(self.document_list_url)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

    def test_document_detail__checkbox(self):
        document: Document = baker.make(Document, institution=self.institution, name='Hand Hygiene Guidelines')
        version: Version = baker.make(Version, document=document, approved=False, reviewer=self.auditor, _create_files=True)
        VersionApprovalConfig(version).approve(self.auditor, True)
        url = reverse('docs:view:doc-detail', kwargs={
            'institution_slug': document.institution.slug,
            'pk': document.pk,
        })

        checkbox: DocumentCheckbox = baker.make(DocumentCheckbox, document=document, required=True, label="Please confirm")

        with self.subTest('view document'):
            response = self.client.get(url)
            self.assertContains(response, "Please confirm")
        with self.subTest('tick checkbox'):
            response = self.htmx_client.post(url, data={
                'checkbox_id': checkbox.pk,
            })
            self.assertEqual(response.status_code, HTTP_200_OK)
            state: DocumentCheckboxState = checkbox.states.get()
            self.assertEqual(state.version, version)
            self.assertEqual(state.user, self.auditor)

    @english_test
    def test_document_detail(self):
        document: Document = baker.make(Document, institution=self.institution, name='Hand Hygiene Guidelines')
        url = reverse('docs:view:doc-detail', kwargs={
            'institution_slug': document.institution.slug,
            'pk': document.pk,
        })

        with self.subTest('Should raise 404 because document has no published version'):
            response = self.client.get(url)
            self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)

        version: Version = baker.make(Version, document=document, approved=False, reviewer=self.auditor, _create_files=True)

        with self.subTest('Should not render document if current version is not approved'):
            response = self.client.get(url)
            self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)

        VersionApprovalConfig(version).approve(self.auditor, True)
        with self.subTest('Should render published and approved document'):
            response = self.client.get(url)
            self.assertContains(response, document.name)

            with self.subTest("analytics"):
                entry: AnalyticsEntry = AnalyticsEntry.objects.get()
                self.assertEqual(entry.content_object, document)
                self.assertEqual(entry.detail_counts.get('web'), 1)

            with self.subTest('bookmarks'):
                with self.subTest('bookmarks qs should be empty'):
                    self.assertIsInstance(response.context_data['bookmarks'], DocumentRelationQuerySet)
                    self.assertQuerysetEqual(response.context_data['bookmarks'], Bookmark.objects.none())
                with self.subTest('bookmarks doc ids should be an empty set'):
                    self.assertIsInstance(response.context_data['bookmarked_document_ids'], set)
                    self.assertEqual(response.context_data['bookmarked_document_ids'], set())
                with self.subTest('document qs should be empty'):
                    self.assertIsInstance(response.context_data['bookmarked_documents'], DocumentQuerySet)
                    self.assertQuerysetEqual(response.context_data['bookmarked_documents'], Document.objects.none())
                with self.subTest('Add bookmark option should be rendered'):
                    self.assertContains(response, 'Bookmark')
                    self.assertContains(response, 'add_bookmark')
                    self.assertContains(response, icon_css_class('star-empty'))
                with self.subTest('Remove bookmark option should not be rendered'):
                    self.assertNotContains(response, 'remove_bookmark')
        with self.subTest("document links"):
            self.assertNotContains(response, 'class="document-links section-links"')
            link = baker.make(DocumentLink, document=document)
            # forms
            form: AuditForm = baker.make(AuditForm, institution=self.institution)
            self.auditor.forms.add(form)
            hidden_form: AuditForm = baker.make(AuditForm, institution=self.institution)
            document.forms.set([form, hidden_form])
            # documents
            doc: Document = baker.make(Document, institution=self.institution, name="doc")
            hidden_doc: Document = baker.make(Document, institution=self.institution, folder=baker.make(Folder), name="hidden")
            doc_version: Version = baker.make(Version, reviewer=self.auditor, document=doc, approved=False)
            hidden_doc_version: Version = baker.make(Version, reviewer=self.auditor, document=hidden_doc, approved=False)
            baker.make(ApprovalConfig, name='approval config', institution=self.institution, steps=[{
                "approvers": [self.auditor.user.username],
                "approvals_required": 1,
            }])
            version_approval_config = VersionApprovalConfig(version)
            self.assertIn(self.auditor, version_approval_config.auditors)
            VersionApprovalConfig(doc_version).approve(self.auditor, True)
            VersionApprovalConfig(hidden_doc_version).approve(self.auditor, True)
            document.documents.set([doc, hidden_doc])
            response = self.client.get(url)
            with self.subTest("linked forms"):
                self.assertContains(response, form.name)
                self.assertContains(response, reverse('dashboard_reports_form', kwargs={'current_form_id': form.pk, 'institution_slug': self.institution.slug}))
                self.assertContains(response, icon_css_class('stats'))
                self.assertContains(response, hidden_form.name)
                self.assertNotContains(response, reverse('dashboard_reports_form', kwargs={'current_form_id': hidden_form.pk, 'institution_slug': self.institution.slug}))
            with self.subTest("linked documents"):
                self.assertContains(response, doc.name)
                self.assertContains(response, reverse('docs:view:doc-detail', kwargs={
                    'pk': doc.pk,
                    'institution_slug': doc.institution.slug,
                }))
                self.assertContains(response, icon_css_class('file'))
                self.assertContains(response, hidden_doc.name)
                self.assertNotContains(response, reverse('docs:view:doc-detail', kwargs={
                    'pk': hidden_doc.pk,
                    'institution_slug': hidden_doc.institution.slug,
                }))
            with self.subTest("links"):
                self.assertNotContains(response, link.name)
                self.auditor.user.user_permissions.add(get_permission_by_name("megdocs.view_documentlink"))
                response = self.client.get(url)
                self.assertContains(response, link.name)
                self.assertContains(response, link.url)
                self.assertContains(response, icon_css_class('new-window'))

    @english_test
    def test_version_revision_summary(self):
        document: Document = baker.make(Document, institution=self.institution, name='Hand Hygiene Guidelines')
        url = reverse('docs:view:doc-detail', kwargs={
            'institution_slug': document.institution.slug,
            'pk': document.pk,
        })
        with self.subTest('Initial version wont render revision summary'):
            version: Version = baker.make(Version, reviewer=self.auditor, revision=1, document=document, approved=False, _create_files=True)
            VersionApprovalConfig(version).approve(self.auditor, True)
            response = self.client.get(url)
            self.assertNotContains(response, "Revision summary:")
        with self.subTest('Version2 will render revision summary'):
            version2: Version = baker.make(Version, reviewer=self.auditor, revision=2, document=document, approved=False, _create_files=True, summary="HSE updated guidance")
            VersionApprovalConfig(version2).approve(self.auditor, True)
            response = self.client.get(url)
            self.assertContains(response, "Revision summary:")
            self.assertContains(response, "HSE updated guidance")
        with self.subTest('Version 3 will render a different revision summary'):
            version3: Version = baker.make(Version, reviewer=self.auditor, revision=3, document=document, approved=False, _create_files=True, summary="Local policy update")
            VersionApprovalConfig(version3).approve(self.auditor, True)
            response = self.client.get(url)
            self.assertContains(response, "Revision summary:")
            self.assertNotContains(response, "HSE updated guidance")
            self.assertContains(response, "Local policy update")

    def test_document_detail__bookmarked(self):
        document: Document = baker.make(Document, institution=self.institution, name='Hand Hygiene Guidelines')
        version: Version = baker.make(Version, document=document, approved=False, reviewer=self.auditor, _create_files=True)
        VersionApprovalConfig(version).approve(self.auditor, True)
        Bookmark.objects.create(user=self.auditor.user, document=document)

        url = reverse('docs:view:doc-detail', kwargs={
            'institution_slug': document.institution.slug,
            'pk': document.pk,
        })

        with self.subTest("bookmark render"):
            response = self.client.get(url)
            with self.subTest('bookmarks qs should contain the document'):
                self.assertEqual(list(response.context_data['bookmarks']), list(Bookmark.objects.filter(document_id=document.pk)))
            with self.subTest('bookmarks doc ids should contain document id'):
                self.assertEqual(response.context_data['bookmarked_document_ids'], {document.pk})
            with self.subTest('document qs should contain the document'):
                self.assertEqual(list(response.context_data['bookmarked_documents']), list(Document.objects.filter(pk=document.pk)))
            with self.subTest('Remove bookmark option should be rendered'):
                self.assertContains(response, 'remove_bookmark')
                self.assertContains(response, icon_css_class('star'))

        with self.subTest("bookmark removal"):
            response = self.client.post(url, data={
                'remove_bookmark': str(document.pk),
            })
            with self.subTest('response'):
                self.assertRedirects(response, url)
            with self.subTest('bookmark should be removed'):
                self.assertFalse(Bookmark.objects.count())

    def test__folder_list__superuser(self):
        baker.make(Folder, institution=self.institution, name="verbose_folder_name_for_testing")
        response = self.client.get(self.document_list_url)

        with self.subTest("user has view only permissions to see institution folders"):
            self.assertContains(response, "verbose_folder_name_for_testing")

        # Log in with superuser
        self.client.logout()
        user = User.objects.create_superuser(username='superuser', email=None, password='pass')
        baker.make(TOTPDevice, user=user)
        baker.make(Auditor, user=user, institution=self.institution)
        self.client.login(username='superuser', password='pass')

        with self.subTest("super user can view"):
            response = self.client.get(self.document_list_url)
            self.assertContains(response, "verbose_folder_name_for_testing")

    def test_all_documents_visible_at_root(self):
        folder = Folder.objects.create(institution=self.institution, owner=self.auditor, name="folder")
        unowned_folder = Folder.objects.create(institution=self.institution, owner=baker.make(Auditor, institution=self.institution), name="folder")

        with self.subTest("orphaned documents"):
            orphan_doc: Document = baker.make(Document, folder=None, name='orphan_doc', institution=self.institution, current_version__approved=True)
            response = self.client.get(self.document_list_url, follow=True)
            self.assertIn(orphan_doc, response.context_data['document_list'])

        with self.subTest("folder documents"):
            folder_doc: Document = baker.make(Document, folder=folder, name='folder_doc', institution=self.institution, current_version__approved=True)
            no_perm_folder_doc: Document = baker.make(Document, folder=unowned_folder, name='folder_doc2', institution=self.institution, current_version__approved=True)
            response = self.client.get(self.document_list_url, follow=True)
            self.assertIn(folder_doc, response.context_data['document_list'])
            self.assertIn(no_perm_folder_doc, response.context_data['document_list'])

    def test_folder_sub_folder_list(self):
        folder: Folder = Folder.objects.create(name="folder", owner=self.auditor, parent=None, institution=self.institution)
        sub_folder: Folder = Folder.objects.create(name="verbose_sub_folder_name", owner=self.auditor, parent=folder, institution=self.institution)
        sub_folder_doc: Document = baker.make(Document, name='Doc', institution=self.institution, current_version__approved=True, folder=sub_folder)
        parent_doc: Document = baker.make(Document, name='Doc2', institution=self.institution, current_version__approved=True, folder=folder)
        folder_url = reverse_lazy('docs:view:doc-list', kwargs={'institution_slug': self.institution.slug, 'folder': folder.pk})
        response: TemplateResponse = self.client.get(folder_url)
        self.assertContains(response, sub_folder.name, count=4)
        self.assertIn(parent_doc, response.context_data['document_list'])
        self.assertNotIn(sub_folder_doc, response.context_data['document_list'])

    def test_archived_documents_not_visible(self):
        folder: Folder = Folder.objects.create(name="subfolder", owner=self.auditor, parent=None, institution=self.institution)
        archived_doc: Document = baker.make(Document, archived=True, name='archived_doc', institution=self.institution, _fill_optional=['current_version'], folder=folder)
        folder_url = reverse_lazy('docs:view:doc-list', kwargs={'institution_slug': self.institution.slug, 'folder': folder.pk})
        response = self.client.get(folder_url, follow=True)
        self.assertNotIn(archived_doc, response.context_data['document_list'])

    def test_fullscreen_views(self):
        folder: Folder = Folder.objects.create(name="folder", owner=self.auditor, parent=None, institution=self.institution)
        sub_folder: Folder = Folder.objects.create(name="verbose_sub_folder_name", owner=self.auditor, parent=folder, institution=self.institution)
        document: Document = baker.make(Document, name='Mopping instructions', institution=self.institution, folder=folder)
        document_no_version: Document = baker.make(Document, name='Mopping instructions 2', institution=self.institution, folder=folder)
        baker.make(Version, document=document, approved=True, _create_files=True, revision=1)
        baker.make(Bookmark, document=document, user=self.auditor.user)

        bookmarks_url = reverse('docs:view:doc-list-bookmarks', kwargs={'institution_slug': self.institution.slug})
        folder_url = reverse('docs:view:doc-list', kwargs={'institution_slug': self.institution.slug, 'folder': folder.pk})
        sub_folder_url = reverse('docs:view:doc-list', kwargs={'institution_slug': self.institution.slug, 'folder': sub_folder.pk})
        doc_url = reverse('docs:view:doc-detail', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})
        doc_no_version_url = reverse('docs:view:doc-detail', kwargs={'institution_slug': self.institution.slug, 'pk': document_no_version.pk})

        bookmarks_fullscreen_url = reverse('docs:view:doc-list-bookmarks-fullscreen', kwargs={'institution_slug': self.institution.slug})
        folder_fullscreen_url = reverse('docs:view:doc-list-fullscreen', kwargs={'institution_slug': self.institution.slug, 'folder': folder.pk})
        sub_folder_fullscreen_url = reverse('docs:view:doc-list-fullscreen', kwargs={'institution_slug': self.institution.slug, 'folder': sub_folder.pk})

        with self.subTest("bookmarks"):
            response: TemplateResponse = self.client.get(reverse('docs:view:doc-list-bookmarks-fullscreen', kwargs={'institution_slug': self.institution.slug}))
            self.assertTrue(response.context_data['full_screen'])
            self.assertContains(response, bookmarks_fullscreen_url)
            self.assertContains(response, folder_fullscreen_url)
            self.assertNotContains(response, bookmarks_url)
            self.assertNotContains(response, self.document_list_url + '" ')
            self.assertNotContains(response, folder_url)
            self.assertNotContains(response, doc_url)
            self.assertNotContains(response, doc_no_version_url)

        with self.subTest("doc list"):
            response: TemplateResponse = self.client.get(reverse('docs:view:doc-list-fullscreen', kwargs={'institution_slug': self.institution.slug, 'folder': folder.pk}))
            self.assertTrue(response.context_data['full_screen'])
            self.assertContains(response, bookmarks_fullscreen_url)
            self.assertContains(response, folder_fullscreen_url)
            self.assertContains(response, sub_folder_fullscreen_url)
            self.assertNotContains(response, bookmarks_url)
            self.assertNotContains(response, self.document_list_url + '" ')
            self.assertNotContains(response, folder_url)
            self.assertNotContains(response, sub_folder_url)
            self.assertNotContains(response, doc_url)
            self.assertNotContains(response, doc_no_version_url)
