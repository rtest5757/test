import datetime
import os
from typing import Sequence
from django.conf import settings
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import LogEntry
from django.contrib.auth.models import Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.mail import EmailMultiAlternatives
from django.forms import ModelForm
from django.http import HttpResponse
from django.template.response import TemplateResponse
from django.test import TestCase, override_settings
from django.urls import reverse_lazy, reverse
from django.utils import timezone
from django.utils.translation import gettext
from django_otp.plugins.otp_totp.models import TOTPDevice
from model_bakery import baker
from rest_framework.status import HTTP_200_OK, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND

from action_audit.constants import VIEW_DETAIL
from approvals.models import VersionApprovalConfig
from emails.constants import EMAIL_TYPE_DOCUMENT_REVIEWER_ASSIGNMENT, EMAIL_TYPE_DOCUMENT_OWNER_ASSIGNMENT
from emails.models import EmailContext
from files.utils import create_field_file_url
from megdocs.constants import REVIEW_FREQUENCY_CHOICES, MANAGE_PERMS
from megdocs.forms import DocumentBulkUploadForm
from megdocs.models import Document, Version, Folder, Bookmark, DocumentRelationQuerySet, DocumentQuerySet, \
    FolderPermissionRule, FIRST_REVISION, DocumentLink, VersionApproval, DocumentCheckbox, DocumentCheckboxState
from megforms.comments.models import Comment
from megforms.models import Institution, Auditor, Team, AuditForm
from megforms.templatetags.megforms_extras import icon
from megforms.test_utils import english_test, IS_ENGLISH_LOCALE
from megforms.utils import get_permissions, get_permission_by_name, make_absolute_url
from pdf_viewer.templatetags.pdf import pdf_viewer_url
from utils.htmx_test import HTMXTestMixin


class DocumentManagementViewTest(HTMXTestMixin, TestCase):
    test_pdf_document = os.path.join(settings.BASE_DIR, 'megdocs/scripts/pdf/hand hygiene.pdf')
    permissions = (
        'megdocs.add_document',
        'megdocs.change_document',
        'megdocs.delete_document',
        'megdocs.view_document',
        'megdocs.view_version',
        'megdocs.add_version',
        'megdocs.change_version',
        'megdocs.delete_version',
        'megdocs.approve_version',
        'megdocs.view_folder',
        'megdocs.add_folder',
        'megdocs.change_folder',
        'megdocs.delete_folder',
        'comments.view_comment',
        'comments.add_comment',
    )
    test_pdf_content: bytes

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.institution: Institution = baker.make(Institution, name='Test Institution', megdocs_enabled=True)
        cls.auditor: Auditor = baker.make(Auditor, user__email='auditor@test.com', institution=cls.institution, user__username='lead', user__user_permissions=get_permissions(cls.permissions, validate=True))
        cls.document_list_url = reverse_lazy('docs:manage:doc-list', kwargs={'institution_slug': cls.institution.slug})
        cls.awaiting_publish_versions_url = reverse_lazy('docs:manage:awaiting-publish-list', kwargs={'institution_slug': cls.institution.slug})
        cls.review_versions_url = reverse_lazy('docs:manage:assigned-list', kwargs={'institution_slug': cls.institution.slug})
        cls.my_review_versions_url = reverse_lazy('docs:manage:user-assigned-list', kwargs={'institution_slug': cls.institution.slug})
        cls.bulk_upload_url = reverse_lazy('docs:manage:doc-bulk-upload', kwargs={'institution_slug': cls.institution.slug})
        cls.folder: Folder = Folder.objects.create(name="Folder", owner=cls.auditor, parent=None, institution=cls.institution)
        cls.folder_create_url = reverse_lazy('docs:manage:folder-create', kwargs={'institution_slug': cls.institution.slug})
        cls.folder_update_url = reverse_lazy('docs:manage:folder-update', kwargs={'institution_slug': cls.institution.slug, 'pk': cls.folder.pk})
        cls.landing_url = reverse_lazy('docs:doc-landing', kwargs={'institution_slug': cls.institution.slug})

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with open(cls.test_pdf_document, 'rb') as test_document:
            cls.test_pdf_content = test_document.read()

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
            self.assertContains(response, 'Review')
            self.assertContains(response, 'Upload')

        document: Document = baker.make(Document, name='Mopping instructions', institution=self.institution, _fill_optional=['current_version'])
        document_without_version: Document = baker.make(Document, name='Hand Hygiene Guidelines', institution=self.institution)
        document_other_institution: Document = baker.make(Document, name='Hidden document', _fill_optional=['current_version'])

        # Sanity check
        self.assertNotEqual(document_other_institution.institution, self.institution)

        response = self.client.get(self.document_list_url)

        with self.subTest('Should contain Upload button'):
            self.assertContains(response, 'Upload')
            # Make sure when no folder selected, upload url has no folder parameter
            self.assertNotContains(response, f'{self.bulk_upload_url}?folder=')
            self.assertContains(response, self.bulk_upload_url)
        with self.subTest('Should contain document belonging to this institution'):
            self.assertContains(response, document.name)
        with self.subTest('Should contain document without version'):
            # Document without version should appear in management list to allow managers to upload initial version
            self.assertContains(response, document_without_version.name)
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
            self.assertContains(response, 'id="filter-form"')

    def test_document_detail__upload_btn(self):
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document')
        version: Version = baker.make(Version, document=document, approved=True, _create_files=True, revision=1)
        document.current_version = version
        document.save()
        url = reverse('docs:manage:doc-detail', kwargs={'pk': document.pk, 'institution_slug': document.institution.slug})

        with self.subTest('Document manage upload url with no folder'):
            response = self.client.get(url)
            self.assertNotContains(response, f'{self.bulk_upload_url}?folder=')
            self.assertContains(response, f'{self.bulk_upload_url}')

        with self.subTest('Document manage upload url has folder id'):
            document.folder = self.folder
            document.save()
            response = self.client.get(url)
            self.assertContains(response, f'{self.bulk_upload_url}?folder=')

    def test_document_list__anonymous(self):
        self.client.logout()

        response = self.client.get(self.document_list_url)
        self.assertRedirects(response, f"{settings.LOGIN_URL}?next={self.document_list_url}")

    @english_test
    def test_document_list__no_view_perm(self):
        self.auditor.user.user_permissions.clear()

        response = self.client.get(self.document_list_url)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        self.assertIn("It looks like you don\\\'t have permission to carry out this action", str(response.content))

    @english_test
    def test_document_edit_view(self):
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document', folder=self.folder)
        url = reverse('docs:manage:doc-edit', kwargs={
            'institution_slug': self.institution.slug,
            'pk': document.pk,
        })

        with self.subTest('Document without version'):
            response = self.client.get(url)
            with self.subTest('Dont show audit log button - user doesnt have the permission'):
                self.assertNotContains(response, 'Audit log')
            self.assertContains(response, 'Test Document')
            self.assertContains(response, 'Awaiting initial publishing')
            self.assertContains(response, 'Document contents will display here once a version is created.')
            self.assertContains(response, 'This document does not currently have any versions.')
            self.assertFalse(response.context_data['versions'])
            self.assertIsNone(response.context_data['version'])
        with self.subTest('Document without version'):
            self.auditor.user.user_permissions.add(get_permission_by_name('admin.view_logentry'))
            response: TemplateResponse = self.client.get(url)
            self.assertContains(response, 'Audit log')

        with self.subTest('Saving document'):
            response = self.client.post(url, data={
                'name': 'New Document Name',
                'description': 'New Description',
                'tags': 'test,document',
                'folder': self.folder.id,
                'required_approvals': '1',
                'checkbox-TOTAL_FORMS': 0,
                'checkbox-INITIAL_FORMS': 0,
            }, follow=True)
            self.assertContains(response, 'Successfully saved New Document Name')
            self.assertRedirects(response, url)
            document = Document.objects.get()
            self.assertEqual(document.name, 'New Document Name')
            self.assertEqual(document.description, 'New Description')
            self.assertEqual(0, len(mail.outbox), msg="change reviewer notification not sent")

        version: Version = baker.make(Version, document=document, approved=False, _create_files=True, revision=1)
        with self.subTest('Document with unapproved unpublished version'):
            response = self.client.get(url)
            self.assertContains(response, 'Awaiting initial publishing')
            self.assertNotContains(response, 'Document contents will display here once a version is created.')
            self.assertNotContains(response, 'This document does not currently have any versions.')
            self.assertIn(version, response.context_data['versions'])
            self.assertEqual(version, response.context_data['version'])

        version: Version = baker.make(Version, document=document, approved=True, _create_files=True, revision=2)
        with self.subTest('Document with approved unpublished version'):
            response = self.client.get(url)
            self.assertContains(response, 'Awaiting initial publishing')
            self.assertIn(version, response.context_data['versions'])
            # latest version should be shown
            self.assertEqual(version, response.context_data['version'])

        version: Version = baker.make(Version, document=document, approved=True, _create_files=True, revision=3, reviewer=self.auditor)
        with self.subTest('Document with approved published version'):
            VersionApprovalConfig(version).approve(self.auditor, True)
            response = self.client.get(url)
            self.assertNotContains(response, 'Awaiting initial publishing')
            self.assertIn(version, response.context_data['versions'])
            # latest version should be shown
            self.assertEqual(version, response.context_data['version'])

        draft_version: Version = baker.make(Version, document=document, approved=True, _create_files=True, revision=4)
        with self.subTest('Document with approved published version and draft'):
            # Draft version is created, but current version to be displayed by default
            response = self.client.get(url)
            self.assertNotContains(response, 'Awaiting initial publishing')
            self.assertIn(draft_version, response.context_data['versions'])
            # latest version should be shown
            self.assertEqual(version, response.context_data['version'])

        with self.subTest('View a draft version of the document'):
            draft_url = reverse('docs:manage:doc-edit', kwargs={
                'institution_slug': self.institution.slug,
                'pk': document.pk,
                'revision': draft_version.revision,
            })
            response = self.client.get(draft_url)
            self.assertEqual(draft_version, response.context_data['version'])

    @english_test
    def test_document_edit__change_reviewer(self):
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document', folder=self.folder)
        version: Version = baker.make(Version, document=document, approved=True, _create_files=True, revision=1, reviewer=None)
        document.current_version = version
        document.save()
        reviewer: Auditor = baker.make(Auditor, user__email='test@institution.com', user__username="reviewer", institution=self.institution, user__user_permissions=[get_permission_by_name('megdocs.approve_version')])
        url = reverse('docs:manage:doc-edit', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})
        email_context: str = baker.make(EmailContext, institution=self.institution, email_type=EMAIL_TYPE_DOCUMENT_REVIEWER_ASSIGNMENT, text="you have been made a reviewer").text
        response = self.client.post(url, data={
            'name': 'New Document Name',
            'description': 'New Description',
            'tags': 'test,document',
            'folder': self.folder.id,
            'current_version': version.pk,
            'reviewer': reviewer.pk,
            'required_approvals': '1',
            'checkbox-TOTAL_FORMS': 0,
            'checkbox-INITIAL_FORMS': 0,
        }, follow=True)
        self.assertContains(response, 'Successfully saved New Document Name')
        self.assertEqual(Version.objects.get(pk=document.current_version.pk).reviewer, reviewer)
        with self.subTest("reviewer notification email"):
            self.assertEqual(1, len(mail.outbox))
            email = mail.outbox[0]
            html = email.alternatives[0][0]
            self.assertEqual("You have been assigned to approve New Document Name", email.subject)
            self.assertEqual([reviewer.user.email], email.to)
            version_url = reverse("docs:manage:version-review", kwargs={'institution_slug': self.institution.slug, 'pk': version.pk})
            self.assertIn(version_url, email.body)
            updated_document: Document = Document.objects.get(pk=document.pk)
            self.assertIn("{0} has uploaded a new version of {1} and assigned its approval to you. You can find the new version here:".format(version.creator.user.username, updated_document.name), email.body)
            self.assertIn(email_context, email.body)
            self.assertIn(email_context, html)

    @english_test
    def test_document_edit_view__change_owner(self):
        self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.change_document_owner'))
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document', folder=self.folder)
        url = reverse('docs:manage:doc-edit', kwargs={
            'institution_slug': self.institution.slug,
            'pk': document.pk,
        })
        email_context: EmailContext = baker.make(EmailContext, institution=self.institution, text='you have been made an owner', email_type=EMAIL_TYPE_DOCUMENT_OWNER_ASSIGNMENT).text

        with self.subTest('Document without version'):
            response = self.client.get(url)
            self.assertIn('owner', response.context_data['form'].fields)

        with self.subTest('Saving document'):
            new_owner: Auditor = Auditor.objects.create_auditor(
                "new_owner",
                "pass",
                self.institution,
                user_kwargs={"email": "new@test.com"},
                permissions=['megdocs.change_document', 'megdocs.delete_document'],
            )
            response = self.client.post(url, data={
                'name': 'New Document Name',
                'description': 'New Description',
                'tags': 'test,document',
                'owner': new_owner.pk,
                'folder': self.folder.id,
                'required_approvals': '1',
                'checkbox-TOTAL_FORMS': 0,
                'checkbox-INITIAL_FORMS': 0,
            }, follow=True)
            self.assertEqual(response.status_code, HTTP_200_OK)
            self.assertContains(response, 'Successfully saved New Document Name')
            self.assertRedirects(response, url)
            document = Document.objects.get()
            self.assertEqual(document.name, 'New Document Name')
            self.assertEqual(document.description, 'New Description')

        with self.subTest("new owner assignment email"):
            email = mail.outbox[0]
            html = email.alternatives[0][0]
            self.assertIn(new_owner.email, email.to)
            self.assertEqual(email.subject, gettext('You have been assigned as an owner of {}').format(document.name))
            body_text = gettext('%(editor_name)s has made you the owner of %(document_name)s. You can find the document here:') % dict(
                editor_name=self.auditor.user.username, document_name=document.name
            )
            document_url = make_absolute_url(reverse('docs:manage:doc-detail', kwargs={
                'pk': document.pk,
                'institution_slug': document.institution.slug,
            }))
            self.assertIn(body_text, email.body)
            self.assertIn(body_text, html)
            self.assertIn(document_url, email.body)
            self.assertIn(document_url, html)
            self.assertIn(email_context, email.body)
            self.assertIn(email_context, html)

        with self.subTest('Saving document - junior auditor'):
            new_owner: Auditor = baker.make(Auditor, institution=self.institution)
            response: TemplateResponse = self.client.post(url, data={
                'name': 'New Document Name',
                'description': 'New Description',
                'tags': 'test,document',
                'owner': new_owner.pk,
                'folder': self.folder.id,
                'required_approvals': '1',
                'checkbox-TOTAL_FORMS': 0,
                'checkbox-INITIAL_FORMS': 0,
            }, follow=True)
            self.assertTrue(response.context_data['form'].errors)

    @english_test
    def test_document_edit_view__no_version_perm(self):
        self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.view_version'))
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document')
        url = reverse('docs:manage:doc-edit', kwargs={
            'institution_slug': self.institution.slug,
            'pk': document.pk,
        })

        with self.subTest('Document without version'):
            response = self.client.get(url)
            self.assertContains(response, 'Test Document')
            self.assertContains(response, 'Awaiting initial publishing')
            self.assertContains(response, 'Document contents will display here once a version is created.')
            self.assertContains(response, 'This document does not currently have any versions.')
            self.assertFalse(response.context_data['versions'])
            self.assertIsNone(response.context_data['version'])

        baker.make(Version, document=document, approved=False, _create_files=True, revision=1)
        with self.subTest('Document with unapproved unpublished version'):
            response = self.client.get(url)
            self.assertContains(response, 'Awaiting initial publishing')
            self.assertContains(response, 'Document contents will display here once a version is created.')
            self.assertContains(response, 'This document does not currently have any versions.')
            self.assertFalse(response.context_data['versions'])
            self.assertIsNone(response.context_data['version'])

        baker.make(Version, document=document, approved=True, _create_files=True, revision=2)
        with self.subTest('Document with approved unpublished version'):
            response = self.client.get(url)
            self.assertContains(response, 'Awaiting initial publishing')
            self.assertContains(response, 'Document contents will display here once a version is created.')
            self.assertContains(response, 'This document does not currently have any versions.')
            self.assertFalse(response.context_data['versions'])
            self.assertIsNone(response.context_data['version'])

        version: Version = baker.make(Version, document=document, approved=True, _create_files=True, revision=3, reviewer=self.auditor)
        with self.subTest('Document with approved published version'):
            VersionApprovalConfig(version).approve(self.auditor, True)
            response = self.client.get(url)
            self.assertNotContains(response, 'Awaiting initial publishing')
            self.assertIn(version, response.context_data['versions'])
            # latest version should be shown
            self.assertEqual(version, response.context_data['version'])

        draft_version: Version = baker.make(Version, document=document, approved=True, _create_files=True, revision=4)
        with self.subTest('Document with approved published version and draft'):
            # Draft version is created, but current version to be displayed by default
            response = self.client.get(url)
            self.assertNotContains(response, 'Awaiting initial publishing')
            self.assertNotIn(draft_version, response.context_data['versions'])
            # latest version should be shown
            self.assertEqual(version, response.context_data['version'])

        with self.subTest('Attempt to view a draft version of the document'):
            draft_url = reverse('docs:manage:doc-edit', kwargs={
                'institution_slug': self.institution.slug,
                'pk': document.pk,
                'revision': draft_version.revision,
            })
            response = self.client.get(draft_url)
            self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)

    @english_test
    def test_document_edit_view__no_document_perm(self):
        self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.change_document'))
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document')
        url = reverse('docs:manage:doc-edit', kwargs={
            'institution_slug': self.institution.slug,
            'pk': document.pk,
        })
        with self.subTest('Cannot view page'):
            response = self.client.get(url)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
            self.assertIn("It looks like you don\\\'t have permission to carry out this action", str(response.content))
        with self.subTest('Cannot submit page'):
            response = self.client.post(url, data={
                'name': 'New test document',
                'description': '',
            })
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
            self.assertIn("It looks like you don\\\'t have permission to carry out this action", str(response.content))

    @english_test
    def test_document_edit__change_folder(self):
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document', folder=None)
        url = reverse('docs:manage:doc-edit', kwargs={
            'institution_slug': self.institution.slug,
            'pk': document.pk,
        })
        user: Auditor = baker.make(Auditor, institution=self.institution)
        folder = Folder.objects.create(name="Folder", owner=user, institution=self.institution)
        folder2 = Folder.objects.create(name="Folder2", owner=user, institution=self.institution)
        # protect folder
        rule: FolderPermissionRule = baker.make(FolderPermissionRule, institution=self.institution, folders=[folder], users=[user.user], permissions=[
            Permission.objects.get(codename="change_document", content_type__app_label="megdocs"),
            Permission.objects.get(codename="change_folder", content_type__app_label="megdocs"),
        ])
        with self.subTest('Saving document - unautorized'):
            self.client.post(url, data={
                'name': 'New Document Name',
                'description': 'New Description',
                'tags': 'test,document',
                'folder': folder.id,
                'required_approvals': '1',
                'checkbox-TOTAL_FORMS': 0,
                'checkbox-INITIAL_FORMS': 0,
            }, follow=True)
            self.assertFalse(Document.objects.filter(name="New Document Name").exists())

        with self.subTest('Saving document - team authorized'):
            team = baker.make(Team, institution=self.institution)
            team.auditors.add(self.auditor)
            rule.teams.add(team)
            response = self.client.post(url, data={
                'name': 'New Document Name',
                'description': 'New Description',
                'tags': 'test,document',
                'folder': folder.id,
                'required_approvals': '1',
                'checkbox-TOTAL_FORMS': 0,
                'checkbox-INITIAL_FORMS': 0,
            }, follow=True)
            self.assertContains(response, 'Successfully saved New Document Name')
            document: Document = Document.objects.get(name="New Document Name")
            self.assertEqual(document.folder, folder)

        with self.subTest('Saving document - user authorized'):
            baker.make(FolderPermissionRule, institution=self.institution, folders=[folder2], users=[self.auditor.user], permissions=[
                Permission.objects.get(codename="change_document", content_type__app_label="megdocs"),
                Permission.objects.get(codename="change_folder", content_type__app_label="megdocs"),
            ])
            response = self.client.post(url, data={
                'name': 'Another New Document Name',
                'description': 'New Description',
                'tags': 'test,document',
                'folder': folder2.id,
                'required_approvals': '1',
                'checkbox-TOTAL_FORMS': 0,
                'checkbox-INITIAL_FORMS': 0,
            }, follow=True)
            self.assertContains(response, 'Successfully saved Another New Document Name')
            document: Document = Document.objects.get(name="Another New Document Name")
            self.assertEqual(document.folder, folder2)

    @english_test
    def test_version_create(self):
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document')
        reviewer: Auditor = baker.make(Auditor, institution=self.institution, user__user_permissions=get_permissions(['megdocs.approve_version'], True))
        other_reviewer: Auditor = baker.make(Auditor, user__user_permissions=get_permissions(['megdocs.approve_version'], True))

        url = reverse('docs:manage:version-create', kwargs={
            'institution_slug': self.institution.slug,
            'pk': document.pk,
        })
        with self.subTest('View form'):
            response = self.client.get(url)
            with self.subTest('content'):
                self.assertContains(response, 'Test Document')
                self.assertContains(response, 'Create revision 1')
            with self.subTest('context data'):
                data = response.context_data
                self.assertEqual(document, data['document'])
                form: ModelForm = data['form']
                version: Version = form.instance
                self.assertFalse(version.approved)
                self.assertEqual(version.document, document)
                self.assertIn(reviewer, form.fields['reviewer'].queryset)
                self.assertNotIn(other_reviewer, form.fields['reviewer'].queryset)
        with self.subTest('Submit version'):
            response: TemplateResponse = self.client.post(url, data={
                'file': SimpleUploadedFile('file.pdf', self.test_pdf_content, content_type='application/pdf'),
                'reviewer': reviewer.pk,
                'version_name': '1.0',
            }, follow=True)
            self.assertTrue(document.versions)
            version: Version = Version.objects.get()
            self.assertContains(response, 'Successfully uploaded new version of the document')
            # Should redirect to review page
            self.assertRedirects(response, reverse('docs:manage:version-review', kwargs={
                'institution_slug': self.institution.slug,
                'pk': version.pk,
            }))
            self.assertEqual(reviewer, version.reviewer)
            self.assertEqual(1, version.revision)
        with self.subTest('Submit version with same version name'):
            response: TemplateResponse = self.client.post(url, data={
                'file': SimpleUploadedFile('file.pdf', self.test_pdf_content, content_type='application/pdf'),
                'reviewer': reviewer.pk,
                'version_name': '1.0',
            }, follow=True)
            self.assertTrue(document.versions)
            self.assertContains(response, 'Please enter a unique version number for the new version.')
        with self.subTest('Submit version with same version name of a deleted version'):
            version: Version = Version.objects.get(version_name='1.0')
            version.publish = False
            version.save()

            response: TemplateResponse = self.client.post(url, data={
                'file': SimpleUploadedFile('file.pdf', self.test_pdf_content, content_type='application/pdf'),
                'reviewer': reviewer.pk,
                'version_name': '1.0',
            }, follow=True)
            self.assertTrue(document.versions)
            self.assertContains(response, 'Successfully uploaded new version of the document')

        self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.approve_version'))
        with self.subTest('Submit second version'):
            response = self.client.post(url, data={
                'file': SimpleUploadedFile('file.pdf', self.test_pdf_content, content_type='application/pdf'),
                'reviewer': reviewer.pk,
            }, follow=True)
            self.assertContains(response, 'Successfully uploaded new version of the document')
            self.assertTrue(document.versions)
            version: Version = Version.objects.last()
            # Should redirect to document detail because user no longer has the perm
            self.assertRedirects(response, reverse('docs:manage:doc-edit', kwargs={
                'institution_slug': self.institution.slug,
                'pk': document.pk,
                'revision': version.revision,
            }))
            self.assertEqual(3, version.revision)

    @english_test
    def test_version_create_send_reviewer_email(self):
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document')
        reviewer: Auditor = baker.make(Auditor, institution=self.institution, user__email='test@megit.com', user__user_permissions=get_permissions(['megdocs.approve_version'], True), user__username='reviewer')

        url = reverse('docs:manage:version-create', kwargs={
            'institution_slug': self.institution.slug,
            'pk': document.pk,
        })

        response: TemplateResponse = self.client.post(url, data={
            'file': SimpleUploadedFile('file.pdf', b'Test content', content_type='application/pdf'),
            'reviewer': reviewer.pk,
        }, follow=True)

        version = Version.objects.get()
        with self.subTest('test response'):
            self.assertContains(response, 'Successfully uploaded new version of the document')
            self.assertEqual(len(mail.outbox), 1)
        with self.subTest('test email'):
            email: EmailMultiAlternatives
            email, = mail.outbox
            with self.subTest('html'):
                self.assertIn(reverse('docs:manage:version-review', kwargs={'institution_slug': self.institution.slug, 'pk': version.pk}), email.body)
                self.assertIn('Dear reviewer', email.body)
                self.assertIn('lead has uploaded', email.body)
                self.assertEqual(email.subject, 'You have been assigned to approve Test Document')
                self.assertEqual(email.to, [reviewer.user.email])

    @english_test
    def test_version_create__no_perm(self):
        self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.add_version'))
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document')
        url = reverse('docs:manage:version-create', kwargs={
            'institution_slug': self.institution.slug,
            'pk': document.pk,
        })
        response = self.client.get(url)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        self.assertIn("It looks like you don\\\'t have permission to carry out this action", str(response.content))

    def test_versions_list__no_perm(self):
        self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.view_version'))
        with self.subTest('no assigned versions'):
            response = self.client.get(self.review_versions_url)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

    @english_test
    def test_versions_list(self):
        with self.subTest('no assigned versions'):
            response = self.client.get(self.review_versions_url)
            self.assertContains(response, 'There are no documents awaiting approval')

        with self.subTest('with assigned versions'):
            unapproved_doc = baker.make(Version, document__institution=self.institution, reviewer=self.auditor, approved=False)
            approved_expired_doc = baker.make(Version, document__institution=self.institution, reviewer=self.auditor, approved=False, document__review_interval=datetime.timedelta(days=30))
            Version.objects.filter(pk=approved_expired_doc.pk).update(created=datetime.datetime(2010, 1, 1, tzinfo=timezone.get_current_timezone()))
            baker.make(Version, reviewer=self.auditor, approved=False)
            doc2 = baker.make(Version, document__institution=self.institution, approved=False, reviewer=self.auditor)
            baker.make(Version, document__institution=self.institution, reviewer=self.auditor, approved=True)

            response: TemplateResponse = self.client.get(self.review_versions_url)
            self.assertNotContains(response, 'There are no documents awaiting your approval')
            versions = set(response.context_data['version_list'])
            self.assertEqual(versions, {unapproved_doc, doc2, approved_expired_doc})
            self.assertFalse(response.context_data['my_waiting_approval'])

        with self.subTest("test search"):
            unapproved_ver = baker.make(Version, document__name='random name', document__institution=self.institution, reviewer=self.auditor, approved=False)
            now = timezone.now()
            data = {
                'q': 'random',
                'filter_form': 'Apply',
                'date_range': f'{(now - datetime.timedelta(days=1)).strftime("%Y-%m-%d")} - {now.strftime("%Y-%m-%d")}',
            }
            response = self.client.post(self.review_versions_url, data=data, follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, 'has-error')
            self.assertContains(response, unapproved_ver.document.name)
            data.update(q="Mopping")
            response = self.client.post(self.review_versions_url, data=data, follow=True)
            self.assertNotContains(response, unapproved_ver.document.name)

    def test_my_versions_list(self):
        perms = get_permissions(['megdocs.view_version', 'megdocs.approve_institution_versions'], validate=True)
        reviewer: Auditor = baker.make(
            Auditor, institution=self.institution, user__email='test@megit.com', user__user_permissions=perms, user__username='reviewer',
        )

        self.client.force_login(reviewer.user)
        with self.subTest('no assigned versions'):
            baker.make(Version, document__institution=self.institution, contributors=[self.auditor], approved=False)
            response = self.client.get(self.my_review_versions_url)
            self.assertTrue(response.context_data.get('show_review_tabs'))
            self.assertContains(response, gettext('There are no documents awaiting approval'))

        with self.subTest('with reviewer assigned versions'):
            unapproved_doc = baker.make(Version, document__institution=self.institution, contributors=[reviewer],
                                        approved=False)
            approved_expired_doc = baker.make(Version, document__institution=self.institution, reviewer=self.auditor,
                                              approved=False, document__review_interval=datetime.timedelta(days=30))
            Version.objects.filter(pk=approved_expired_doc.pk).update(
                created=datetime.datetime(2010, 1, 1, tzinfo=timezone.get_current_timezone()))
            baker.make(Version, reviewer=self.auditor, approved=False)
            baker.make(Version, document__institution=self.institution, approved=False, reviewer=self.auditor)
            baker.make(Version, document__institution=self.institution, reviewer=self.auditor, approved=True)

            response: TemplateResponse = self.client.get(self.my_review_versions_url)
            self.assertNotContains(response, gettext('There are no documents awaiting your approval'))
            versions = set(response.context_data['version_list'])
            self.assertEqual(versions, {unapproved_doc})
            self.assertTrue(response.context_data['my_waiting_approval'])

        with self.subTest('with approver assigned versions'):
            baker.make(Version, document__institution=self.institution, reviewer=reviewer, approved=False)

            response: TemplateResponse = self.client.get(self.my_review_versions_url)
            self.assertNotContains(response, gettext('There are no documents awaiting your approval'))
            versions = set(response.context_data['version_list'])
            self.assertEqual(len(versions), 2)
            self.assertTrue(response.context_data['my_waiting_approval'])

    @english_test
    def test_versions_waiting_to_be_published_list(self):
        with self.subTest('no assigned versions'):
            response = self.client.get(self.awaiting_publish_versions_url)
            self.assertContains(response, 'There are no documents waiting to be published')
            self.assertIsNone(response.context_data.get('show_review_tabs'))
            self.assertNotContains(response, 'my reviews')

        with self.subTest('with assigned versions'):
            unapproved_doc = baker.make(Version, document__institution=self.institution, reviewer=self.auditor, approved=False)
            approved_doc = baker.make(Version, document__institution=self.institution, reviewer=self.auditor, approved=True)

            response: TemplateResponse = self.client.get(self.awaiting_publish_versions_url)
            self.assertNotContains(response, 'There are no documents waiting to be published')
            versions = set(response.context_data['version_list'])
            self.assertEqual(versions, {approved_doc})
            self.assertNotEqual(versions, {unapproved_doc})

        with self.subTest("test search"):
            document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document', folder=self.folder)
            current_version: Version = baker.make(Version, document=document, approved=True, _create_files=True, revision=1, reviewer=None)
            new_version: Version = baker.make(Version, document=document, approved=True, _create_files=True, revision=2, reviewer=None)
            document.current_version = current_version
            document.save()

            now = timezone.now()
            data = {
                'q': 'Test Document',
                'filter_form': 'Apply',
                'date_range': f'{(now - datetime.timedelta(days=1)).strftime("%Y-%m-%d")} - {now.strftime("%Y-%m-%d")}',
            }
            response = self.client.post(self.review_versions_url, data=data, follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, 'has-error')
            self.assertContains(response, new_version.document.name)
            data.update(q="Mopping")
            response = self.client.post(self.review_versions_url, data=data, follow=True)
            self.assertNotContains(response, new_version.document.name)

    @english_test
    def test_upload_view__no_approve_perm(self):
        self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.approve_version'))
        reviewer: Auditor = baker.make(Auditor, institution=self.institution, user__user_permissions=get_permissions(['megdocs.view_version', 'megdocs.change_version', 'megdocs.approve_version'], True))

        with self.subTest('View page'):
            baker.make(Auditor, institution=self.institution, user__user_permissions=get_permissions(['megdocs.view_version', 'megdocs.change_version'], True))
            response: TemplateResponse = self.client.get(self.bulk_upload_url)
            self.assertContains(response, 'Upload')
            self.assertContains(response, 'Cancel')
            form: DocumentBulkUploadForm = response.context_data['form']
            self.assertTrue(form.fields['publish'].disabled)
            self.assertEqual(set(form.fields['reviewer'].queryset), {reviewer})

        with self.subTest('Submit pdf + publish'):
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': SimpleUploadedFile('Hand Hygiene Guidelines.pdf', self.test_pdf_content, content_type='application/pdf'),
                'reviewer': reviewer.pk,
                # Setting publish to True should have no effect
                'publish': True,
                'creation_date': '2020-10-1',
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': FIRST_REVISION,
                'checkbox-TOTAL_FORMS': 0,
                'checkbox-INITIAL_FORMS': 0,
            }, follow=True)
            self.assertRedirects(response, reverse('docs:manage:doc-edit', kwargs={
                'institution_slug': self.institution.slug,
                'pk': Document.objects.get().pk,
            }))
            self.assertContains(response, 'Successfully uploaded documents: Hand Hygiene Guidelines')

            document: Document = Document.objects.get()
            self.assertIsNone(document.current_version)
            version = document.versions.get()
            self.assertFalse(version.approved)
            self.assertTrue(version.file)

    @english_test
    def test_upload_view(self):
        # Additional auditor bu they should not show up as reviewer because they dont have a review perm
        contributor: Auditor = baker.make(Auditor, user__email='contributor@test.com', institution=self.institution, user__username='contributor', user__user_permissions=get_permissions(self.permissions, validate=True))
        review_permission = get_permission_by_name('megdocs.approve_version')
        with self.subTest('View page'):
            baker.make(Auditor, institution=self.institution, user__user_permissions=get_permissions(['megdocs.view_version', 'megdocs.change_version'], True))
            response: TemplateResponse = self.client.get(self.bulk_upload_url)
            self.assertContains(response, 'Upload')
            self.assertContains(response, 'Cancel')
            form: DocumentBulkUploadForm = response.context_data['form']
            self.assertEqual(form.fields['reviewer'].initial, None)
            self.assertEqual(set(form.fields['reviewer'].queryset), {self.auditor, contributor})
            self.assertFalse(form.fields['publish'].disabled)
            self.assertEqual(set(form.fields['contributors'].queryset), set(Auditor.objects.for_institution(self.institution).with_permission(review_permission).active_users()))
            self.assertEqual(set(form.fields['review_interval'].choices), set(((None, "---------"),) + REVIEW_FREQUENCY_CHOICES))
            self.assertEqual(set(form.fields['folder'].queryset), set(self.auditor.allowed_folders(permissions=["change_folder"])))

        with self.subTest('Upload page with preselected folder'):
            baker.make(Auditor, institution=self.institution, user__user_permissions=get_permissions(['megdocs.view_version', 'megdocs.change_version'], True))
            response: TemplateResponse = self.client.get(f'{self.bulk_upload_url}?folder={self.folder.pk}')
            form: DocumentBulkUploadForm = response.context_data['form']
            self.assertEqual(form.initial['folder'], str(self.folder.pk))
            self.assertContains(response, f'<option value="{self.folder.pk}" selected> {self.folder}</option>')

        with self.subTest('Submit pdf'):
            lead: Auditor = baker.make(Auditor, institution=self.institution, user__user_permissions=get_permissions(['megdocs.approve_version'], True))
            self.assertEqual(0, len(mail.outbox))
            form: AuditForm = baker.make(AuditForm, institution=self.institution)
            self.auditor.forms.add(form)
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': SimpleUploadedFile('Hand Hygiene Guidelines.pdf', self.test_pdf_content, content_type='application/pdf'),
                'reviewer': self.auditor.pk,
                'contributors': [contributor.pk],
                'publish': False,
                'creation_date': '2020-10-1',
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': FIRST_REVISION,
                'audit_forms': [form.pk],
                'leads': [lead.pk],
                'checkbox-TOTAL_FORMS': 0,
                'checkbox-INITIAL_FORMS': 0,
            }, follow=True)
            self.assertRedirects(response, reverse('docs:manage:doc-edit', kwargs={
                'institution_slug': self.institution.slug,
                'pk': Document.objects.get().pk,
            }))
            self.assertContains(response, 'Successfully uploaded documents: Hand Hygiene Guidelines')

            document: Document = Document.objects.get()
            self.assertIsNone(document.current_version)
            self.assertEqual(document.review_interval, REVIEW_FREQUENCY_CHOICES[0][0])
            self.assertIn(form, document.forms.all())
            self.assertIn(lead, document.leads.all())
            version = document.versions.get()
            self.assertFalse(version.approved)
            self.assertTrue(version.file)
            with self.subTest("email sent"):
                self.assertEqual(2, len(mail.outbox))
                email = mail.outbox[0]
                self.assertEqual("You have been assigned to approve uploaded documents", email.subject)
                self.assertEqual([self.auditor.user.email], email.to)
                version_url = reverse("docs:manage:version-review", kwargs={'institution_slug': self.institution.slug, 'pk': version.pk})
                self.assertIn(version_url, email.body)
                self.assertIn("{0} has uploaded new documents and assigned you as the approver. You can find the new documents here:".format(self.auditor.user.username), email.body)
            with self.subTest("contributor email"):
                email = mail.outbox[1]
                self.assertEqual("You have been assigned to review uploaded documents", email.subject)
                self.assertEqual([contributor.user.email], email.to)
                version_url = reverse("docs:manage:version-review", kwargs={'institution_slug': self.institution.slug, 'pk': version.pk})
                self.assertIn(version_url, email.body)
                self.assertIn("{0} has uploaded new documents and assigned you as a reviewer. You can find the new documents here:".format(self.auditor.user.username), email.body)
        with self.subTest('Submit pdf and optional fields'):
            Document.objects.all().delete()
            contributor: Auditor = baker.make(Auditor, institution=self.institution, user__user_permissions=get_permissions(['megdocs.approve_version']))
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': SimpleUploadedFile('Hand Hygiene Guidelines.pdf', self.test_pdf_content, content_type='application/pdf'),
                'reviewer': self.auditor.pk,
                'publish': False,
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'creation_date': '2020-10-1',
                'contributors': contributor.pk,
                'folder': self.folder.pk,
                'initial_version': FIRST_REVISION,
            }, follow=True)
            self.assertRedirects(response, reverse('docs:manage:doc-edit', kwargs={
                'institution_slug': self.institution.slug,
                'pk': Document.objects.get().pk,
            }))
            self.assertContains(response, 'Successfully uploaded documents: Hand Hygiene Guidelines')

            document: Document = Document.objects.get()
            self.assertEqual(document.folder, self.folder)

            version = document.versions.get()
            self.assertEqual(set(version.contributors.all()), {contributor})
        with self.subTest('Submit pdf long name'):
            Document.objects.all().delete()
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': SimpleUploadedFile('A' * 80 + '.pdf', self.test_pdf_content, content_type='application/pdf'),
                'reviewer': self.auditor.pk,
                'publish': False,
                'creation_date': '2020-10-1',
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': FIRST_REVISION,
            }, follow=True)
            self.assertRedirects(response, reverse('docs:manage:doc-edit', kwargs={
                'institution_slug': self.institution.slug,
                'pk': Document.objects.get().pk,
            }))
            self.assertContains(response, 'Successfully uploaded documents: ' + ('A' * 70))
        with self.subTest('Submit pdf + publish'):
            Document.objects.all().delete()
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': SimpleUploadedFile('Hand Hygiene Guidelines.pdf', self.test_pdf_content, content_type='application/pdf'),
                'reviewer': self.auditor.pk,
                'publish': True,
                'creation_date': '2020-10-1',
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': 4,
            }, follow=True)
            self.assertRedirects(response, reverse('docs:manage:doc-edit', kwargs={
                'institution_slug': self.institution.slug,
                'pk': Document.objects.get().pk,
            }))
            self.assertContains(response, 'Successfully uploaded documents: Hand Hygiene Guidelines')

            document: Document = Document.objects.get()
            version = document.versions.get()
            self.assertEqual(document.current_version, version)
            self.assertEqual(version.revision, 4)
            self.assertTrue(version.approved)

        with self.subTest('Submit multiple pdfs'):
            Document.objects.all().delete()
            LogEntry.objects.all().delete()
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': [
                    SimpleUploadedFile('IPS.pdf', self.test_pdf_content, content_type='application/pdf'),
                    SimpleUploadedFile('HIQA Guidelines.pdf', self.test_pdf_content, content_type='application/pdf'),
                ],
                'reviewer': self.auditor.pk,
                'publish': False,
                'creation_date': '2020-10-1',
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': FIRST_REVISION,
                'audit_forms': [form.pk],
                'leads': [lead.pk],
            }, follow=True)
            self.assertRedirects(response, self.document_list_url)
            self.assertContains(response, 'Successfully uploaded documents: HIQA Guidelines, IPS')
            self.assertEqual(2, Document.objects.count())
            for document in Document.objects.all():
                self.assertIn(form, document.forms.all())
                self.assertIn(lead, document.leads.all())
            # Should log addition for each element
            self.assertTrue(LogEntry.objects.filter(content_type__model='document').exists())

        with self.subTest('Submit multiple pdfs and gifs'):
            # Should not save any document if some of them are not valid file types
            Document.objects.all().delete()
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': [
                    SimpleUploadedFile('IPS.pdf', self.test_pdf_content, content_type='application/pdf'),
                    SimpleUploadedFile('image.gif', self.test_pdf_content, content_type='image/gif'),
                    SimpleUploadedFile('HIQA Guidelines.pdf', self.test_pdf_content, content_type='application/pdf'),
                ],
                'reviewer': self.auditor.pk,
                'publish': False,
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': FIRST_REVISION,
            }, follow=True)
            form: DocumentBulkUploadForm = response.context_data['form']
            self.assertTrue(form['document_files'].errors)
            self.assertNotContains(response, 'Successfully uploaded documents: IPS, HIQA Guidelines')
            self.assertEqual(0, Document.objects.count())

        with self.subTest('Submit jpg'):
            Document.objects.all().delete()
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': SimpleUploadedFile('image.gif', self.test_pdf_content, content_type='image/gif'),
                'reviewer': self.auditor.pk,
                'publish': False,
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': FIRST_REVISION,
            }, follow=True)
            form: DocumentBulkUploadForm = response.context_data['form']
            self.assertTrue(form['document_files'].errors)
            self.assertEqual(0, Document.objects.count())

        with self.subTest('Submit multiple docs with source - validation'):
            Document.objects.all().delete()
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': [
                    SimpleUploadedFile('IPS.pdf', self.test_pdf_content, content_type='application/pdf'),
                    SimpleUploadedFile('HIQA Guidelines.pdf', self.test_pdf_content, content_type='application/pdf'),
                ],
                'source_file': SimpleUploadedFile('source.docx', self.test_pdf_content, content_type='application/docx'),
                'reviewer': self.auditor.pk,
                'publish': False,
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': FIRST_REVISION,
            }, follow=True)
            form: DocumentBulkUploadForm = response.context_data['form']
            self.assertFalse(form.is_valid())
            if IS_ENGLISH_LOCALE:
                self.assertIn("Cannot upload a word document with more than one file in Files.", form.errors['source_file'])

        with self.subTest('submit source file'):
            Document.objects.all().delete()
            self.client.post(self.bulk_upload_url, data={
                'document_files': [
                    SimpleUploadedFile('IPS.pdf', self.test_pdf_content, content_type='application/pdf'),
                ],
                'source_file': SimpleUploadedFile('source.docx', self.test_pdf_content, content_type='application/docx'),
                'reviewer': self.auditor.pk,
                'publish': False,
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': FIRST_REVISION,
                'creation_date': '2020-10-1',
            }, follow=True)
            document: Document = Document.objects.get()
            version = document.versions.get()
            self.assertTrue(version.file)
            self.assertTrue(version.source)

    @english_test
    def test_upload_view__single_document(self):
        with self.subTest('Submit pdf'):
            contributor: Auditor = baker.make(Auditor, institution=self.institution, user__user_permissions=get_permissions(['megdocs.approve_version']))
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': SimpleUploadedFile('Hand Hygiene Guidelines.pdf', self.test_pdf_content, content_type='application/pdf'),
                'source_file': SimpleUploadedFile('source.docx', self.test_pdf_content, content_type='application/docx'),
                'reviewer': self.auditor.pk,
                'publish': False,
                'single_document': True,
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'creation_date': '2020-10-1',
                'contributors': contributor.pk,
                'folder': self.folder.pk,
                'initial_version': 6,
            }, follow=True)
            with self.subTest('response'):
                self.assertRedirects(response, reverse('docs:manage:doc-edit', kwargs={
                    'institution_slug': self.institution.slug,
                    'pk': Document.objects.get().pk,
                }))
                self.assertContains(response, 'Successfully uploaded documents: Hand Hygiene Guidelines')

            with self.subTest('document'):
                document: Document = Document.objects.get()
                self.assertIsNone(document.current_version)
                self.assertEqual(document.name, 'Hand Hygiene Guidelines')
                self.assertEqual(document.review_interval, REVIEW_FREQUENCY_CHOICES[0][0])
            with self.subTest('version'):
                version = document.versions.get()
                self.assertFalse(version.approved)
                self.assertTrue(version.file)
                self.assertTrue(version.source)
                self.assertEqual(set(version.contributors.all()), {contributor})
                self.assertEqual(version.revision, 6)
        with self.subTest('Submit pdf + publish'):
            Document.objects.all().delete()
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': SimpleUploadedFile('Hand Hygiene Guidelines.pdf', self.test_pdf_content, content_type='application/pdf'),
                'reviewer': self.auditor.pk,
                'publish': True,
                'single_document': True,
                'creation_date': '2020-10-1',
                'required_approvals': 1,
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'initial_version': FIRST_REVISION,
            }, follow=True)
            with self.subTest('response'):
                self.assertRedirects(response, reverse('docs:manage:doc-edit', kwargs={
                    'institution_slug': self.institution.slug,
                    'pk': Document.objects.get().pk,
                }))
                self.assertContains(response, 'Successfully uploaded documents: Hand Hygiene Guidelines')
            with self.subTest('document'):
                document: Document = Document.objects.get()
                self.assertEqual(document.name, 'Hand Hygiene Guidelines')
            with self.subTest('version'):
                version = document.versions.get()
                self.assertEqual(document.current_version, version)
                self.assertTrue(version.approved)

        with self.subTest('Submit multiple pdfs'):
            Document.objects.all().delete()
            LogEntry.objects.all().delete()
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': [
                    SimpleUploadedFile('Hand hygiene guidelines 10.pdf', self.test_pdf_content, content_type='application/pdf'),
                    SimpleUploadedFile('Hand hygiene guidelines 1.pdf', self.test_pdf_content, content_type='application/pdf'),
                    SimpleUploadedFile('Hand hygiene guidelines 2.pdf', self.test_pdf_content, content_type='application/pdf'),
                ],
                'reviewer': self.auditor.pk,
                'publish': False,
                'single_document': True,
                'creation_date': '2020-10-1',
                'required_approvals': 1,
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'initial_version': FIRST_REVISION,
            }, follow=True)
            with self.subTest('response'):
                self.assertRedirects(response, reverse('docs:manage:doc-edit', kwargs={
                    'institution_slug': self.institution.slug,
                    'pk': Document.objects.get().pk,
                }))

                self.assertContains(response, 'Successfully uploaded documents: Hand hygiene guidelines')

            with self.subTest('document'):
                self.assertEqual(1, Document.objects.count())
                document: Document = Document.objects.get()
                self.assertEqual(document.name, 'Hand hygiene guidelines')
            with self.subTest('versions'):
                self.assertEqual(3, Version.objects.count())
                versions: Sequence[Version] = Version.objects.all().order_by('revision')
                self.assertEqual([v.revision for v in versions], [1, 2, 3])
            with self.subTest('log entry'):
                # Should log addition for each element
                self.assertTrue(LogEntry.objects.filter(content_type__model='document').exists())

        with self.subTest('Submit multiple pdfs with varying names'):
            Document.objects.all().delete()
            LogEntry.objects.all().delete()
            self.client.post(self.bulk_upload_url, data={
                'document_files': [
                    SimpleUploadedFile('some document.pdf', self.test_pdf_content, content_type='application/pdf'),
                    SimpleUploadedFile('another document.pdf', self.test_pdf_content, content_type='application/pdf'),
                ],
                'reviewer': self.auditor.pk,
                'publish': False,
                'single_document': True,
                'creation_date': '2020-10-1',
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': FIRST_REVISION,
            }, follow=True)

            self.assertEqual(1, Document.objects.count())
            document: Document = Document.objects.get()
            self.assertEqual(document.name, 'another document')

        with self.subTest('Submit multiple pdfs and gifs'):
            # Should not save any document if some of them are not valid file types
            Document.objects.all().delete()
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': [
                    SimpleUploadedFile('IPS.pdf', self.test_pdf_content, content_type='application/pdf'),
                    SimpleUploadedFile('image.gif', self.test_pdf_content, content_type='image/gif'),
                    SimpleUploadedFile('HIQA Guidelines.pdf', self.test_pdf_content, content_type='application/pdf'),
                ],
                'reviewer': self.auditor.pk,
                'publish': False,
                'single_document': True,
                'creation_date': '2020-10-1',
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': FIRST_REVISION,
            }, follow=True)
            form: DocumentBulkUploadForm = response.context_data['form']
            self.assertTrue(form['document_files'].errors)
            self.assertNotContains(response, 'Successfully uploaded documents: IPS, HIQA Guidelines')
            self.assertEqual(0, Document.objects.count())

        with self.subTest('Submit multiple pdfs and version name specified'):
            # Should not save any document if some of them are not valid file types
            Document.objects.all().delete()
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': [
                    SimpleUploadedFile('IPS.pdf', self.test_pdf_content, content_type='application/pdf'),
                    SimpleUploadedFile('HIQA Guidelines.pdf', self.test_pdf_content, content_type='application/pdf'),
                ],
                'reviewer': self.auditor.pk,
                'publish': False,
                'single_document': True,
                'creation_date': '2020-10-1',
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': FIRST_REVISION,
                'version_name': '1.0',
            }, follow=True)
            form: DocumentBulkUploadForm = response.context_data['form']
            self.assertTrue(form['version_name'].errors)
            self.assertContains(response, 'Cannot upload multiple documents with the same version name')
            self.assertNotContains(response, 'Successfully uploaded documents: IPS, HIQA Guidelines')
            self.assertEqual(0, Document.objects.count())

        with self.subTest('Submit gifs'):
            Document.objects.all().delete()
            response: TemplateResponse = self.client.post(self.bulk_upload_url, data={
                'document_files': SimpleUploadedFile('image.gifs', self.test_pdf_content, content_type='image/gif'),
                'reviewer': self.auditor.pk,
                'publish': False,
                'single_document': True,
                'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
                'required_approvals': 1,
                'initial_version': FIRST_REVISION,
            }, follow=True)
            form: DocumentBulkUploadForm = response.context_data['form']
            self.assertTrue(form['document_files'].errors)
            self.assertEqual(0, Document.objects.count())

    def test_upload_view__multiple_docs__emails(self):
        self.client.post(self.bulk_upload_url, data={
            'document_files': [
                SimpleUploadedFile('IPS.pdf', self.test_pdf_content, content_type='application/pdf'),
                SimpleUploadedFile('HIQA Guidelines.pdf', self.test_pdf_content, content_type='application/pdf'),
            ],
            'reviewer': self.auditor.pk,
            'publish': False,
            'creation_date': '2020-10-1',
            'review_interval': str(REVIEW_FREQUENCY_CHOICES[0][0]),
            'required_approvals': 1,
            'initial_version': FIRST_REVISION,
        }, follow=True)
        self.assertEqual(2, Document.objects.count())
        self.assertEqual(1, len(mail.outbox))
        email = mail.outbox[0]
        self.assertEqual([self.auditor.user.email], email.to)
        version_1 = Version.objects.filter(document__name='IPS').first()
        version_2 = Version.objects.filter(document__name='HIQA Guidelines').first()
        version_1_url = reverse("docs:manage:version-review", kwargs={'institution_slug': self.institution.slug, 'pk': version_1.pk})
        version_2_url = reverse("docs:manage:version-review", kwargs={'institution_slug': self.institution.slug, 'pk': version_2.pk})
        self.assertIn(version_1_url, email.body)
        self.assertIn(version_2_url, email.body)

    @override_settings(FULL_ACTION_AUDIT=True)
    @english_test
    def test_review_page(self):
        self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.approve_institution_versions'))
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document')
        version: Version = baker.make(Version, document=document, reviewer=self.auditor, _create_files=True)
        Comment.objects.create(
            user=self.auditor.user,
            subject=version,
            comment='Test comment',
        )

        url = reverse('docs:manage:version-review', kwargs={
            'institution_slug': self.institution.slug,
            'pk': version.pk,
        })
        with self.subTest('First version'):
            response: TemplateResponse = self.client.get(url)
            with self.subTest('Dont show audit log button - user doesnt have the permission'):
                self.assertNotContains(response, 'Audit log')
            self.assertContains(response, 'Approve')
            self.assertContains(response, 'Proposed version: v1')
            self.assertContains(response, 'Test Document v1')
            self.assertContains(response, 'Comments')
            self.assertContains(response, 'Test comment')
            self.assertContains(response, 'Add comment')
            self.assertContains(response, 'Yet to be approved by')
            self.assertTrue(response.context_data['can_edit'])
            log_entry = LogEntry.objects.get(object_id=version.pk, content_type=ContentType.objects.get_for_model(version), action_flag=VIEW_DETAIL)
            self.assertEqual(log_entry.user, self.auditor.user)
        with self.subTest('First version with log view permission'):
            self.auditor.user.user_permissions.add(get_permission_by_name('admin.view_logentry'))
            response: TemplateResponse = self.client.get(url)
            self.assertContains(response, 'Audit log')
        with self.subTest('First version - edit'):
            new_reviewer = baker.make(Auditor, institution=self.institution, user__user_permissions=[get_permission_by_name('megdocs.approve_version')])
            response: TemplateResponse = self.client.post(url, data={
                'reviewer': new_reviewer.pk,
            }, follow=True)
            self.assertRedirects(response, url)
            self.assertContains(response, 'Successfully updated')
            updated_version: Version = Version.objects.get(pk=version.pk)
            self.assertEqual(updated_version.reviewer, new_reviewer)
            log_entries = LogEntry.objects.filter(
                action_flag=CHANGE,
                content_type=ContentType.objects.get_for_model(Version),
                object_id=version.pk,
            )
            self.assertTrue(log_entries.exists(), msg='reviewer change was not logged')
        with self.subTest('Foreign version'):
            v: Version = baker.make(Version, reviewer=self.auditor, _create_files=True)
            response: TemplateResponse = self.client.get(reverse('docs:manage:version-review', kwargs={
                'institution_slug': self.institution.slug,
                'pk': v.pk,
            }))
            self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)
        with self.subTest('First version - approved'):
            VersionApprovalConfig(version).approve(self.auditor, True)
            response: TemplateResponse = self.client.get(url)
            self.assertNotContains(response, 'Approve')
            self.assertContains(response, 'Proposed version: v1')
            self.assertContains(response, 'Test Document v1')

        proposed_version: Version = baker.make(Version, document=document, reviewer=self.auditor, revision=2, _create_files=True)
        url = reverse('docs:manage:version-review', kwargs={
            'institution_slug': self.institution.slug,
            'pk': proposed_version.pk,
        })

        with self.subTest('Subsequent version'):
            response: TemplateResponse = self.client.get(url)
            self.assertContains(response, 'Test Document v2')
            self.assertContains(response, 'Approve')
            self.assertContains(response, 'Proposed version: v2')
            self.assertContains(response, 'Current version: v1')
            self.assertNotContains(response, 'Share')

        with self.subTest('Approval'):
            response: TemplateResponse = self.client.post(url, data={'approve': 'true'}, follow=True)
            with self.subTest('Approval response'):
                self.assertContains(response, 'Your approval has been added')
                self.assertNotContains(response, 'Yet to be approved by')
                self.assertContains(response, 'Approved by')
                self.assertNotContains(response, 'Share')
            with self.subTest('Approval object created'):
                approvals = VersionApproval.objects.filter(version=proposed_version, reviewer=self.auditor)
                self.assertEqual(1, approvals.count())
            with self.subTest('Version approval should be logged'):
                version_log_entry = LogEntry.objects.get(object_id=proposed_version.pk, content_type=ContentType.objects.get_for_model(proposed_version), action_flag=CHANGE)
                self.assertEqual(version_log_entry.user, self.auditor.user)
            with self.subTest("Email to reviewer"):
                self.assertEqual(len(mail.outbox), 1)
                email = mail.outbox[0]
                html = email.alternatives[0][0]
                self.assertIn(proposed_version.reviewer.email, email.to)
                self.assertEqual(settings.DEFAULT_FROM_EMAIL, email.from_email)
                if IS_ENGLISH_LOCALE:
                    self.assertEqual(email.subject, f'Version has been approved: {proposed_version}')
                    for content in (email.body, html):
                        self.assertIn(f"Dear {proposed_version.reviewer.user.first_name}", content)
                        self.assertIn(f"The document version '{proposed_version}' has been fully approved by the following users and is ready to be published:", content)
                        self.assertIn("You can view the version here:", content)
                        self.assertIn(url, content)

        with self.subTest('Publishing'):
            response: TemplateResponse = self.client.post(url, data={'publish': 'true'}, follow=True)
            with self.subTest('Publish response'):
                self.assertContains(response, ' is approved and published')
                self.assertRedirects(response, reverse('docs:manage:doc-detail', kwargs={
                    'pk': document.pk,
                    'institution_slug': self.institution.slug,
                }))
                self.assertContains(response, 'Share')

                with self.subTest('No share btn when no manage doc permission'):
                    self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.change_document'))
                    response: TemplateResponse = self.client.get(reverse('docs:manage:doc-detail', kwargs={
                        'pk': document.pk,
                        'institution_slug': self.institution.slug,
                    }), follow=True)
                    self.assertNotContains(response, 'Share')
            with self.subTest('Document version change should be logged'):
                document_log_entry = LogEntry.objects.get(object_id=document.pk, content_type=ContentType.objects.get_for_model(Document), action_flag=CHANGE)
                self.assertEqual(document_log_entry.user, self.auditor.user)

            proposed_version = Version.objects.get(pk=proposed_version.pk)
            document = Document.objects.get(pk=document.pk)
            with self.subTest('Approval model changes'):
                self.assertTrue(proposed_version.approved)
                self.assertEqual(document.current_version, proposed_version)

            with self.subTest('Approval action should be logged'):
                logs = LogEntry.objects.filter(change_message__contains='approved')
                self.assertTrue(logs)

    def test_document_share(self):
        view_perm = get_permission_by_name('megdocs.view_document')
        auditor: Auditor = baker.make(Auditor, institution=self.institution, user__email='first@example.co', user__username='first', user__user_permissions=[view_perm])
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document')
        version: Version = baker.make(Version, document=document, reviewer=self.auditor, _create_files=True)
        VersionApprovalConfig(version).approve(self.auditor, True)
        url = reverse('docs:manage:doc-detail', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})

        response = self.htmx_client.post(url + '?_action=share', data={'users': [auditor.pk]}, follow=True)
        message = response.context['status_message']
        if IS_ENGLISH_LOCALE:
            self.assertEqual('Successfully shared document with 1 users', message['message'])
            self.assertEqual('success', message['status'])

    def test_review_page__approve_email_not_sent(self):
        auditor: Auditor = baker.make(Auditor, institution=self.institution)
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document', required_approvals=2)
        proposed_version: Version = baker.make(Version, document=document, reviewer=self.auditor, revision=2, _create_files=True, contributors=(
            self.auditor, auditor
        ))
        response: TemplateResponse = self.client.post(reverse('docs:manage:version-review', kwargs={
            'institution_slug': self.institution.slug,
            'pk': proposed_version.pk,
        }), data={'approve': 'true'}, follow=True)
        if IS_ENGLISH_LOCALE:
            self.assertContains(response, 'Your approval has been added')
        self.assertFalse(mail.outbox)

    def test_review_page__leads(self):
        self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.approve_institution_versions'))
        document: Document = baker.make(Document, institution=self.institution, name='Test Document')
        version: Version = baker.make(Version, document=document, _create_files=True)
        url = reverse('docs:manage:version-review', kwargs={
            'institution_slug': self.institution.slug,
            'pk': version.pk,
        })
        with self.subTest("no permission"):
            response: TemplateResponse = self.client.get(url)
            self.assertFalse(response.context_data['can_edit'])
            self.assertFalse(response.context_data['can_approve_or_decline'])
        with self.subTest("user is document lead"):
            document.leads.add(self.auditor)
            response: TemplateResponse = self.client.get(url)
            self.assertTrue(response.context_data['can_edit'])
            self.assertTrue(response.context_data['can_approve_or_decline'])

    @english_test
    def test_review_page__set_owner_as_reviewer(self):
        self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.approve_institution_versions'))
        self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.approve_version'))
        self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.change_version'))
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document')
        version: Version = baker.make(Version, document=document, _create_files=True)
        url = reverse('docs:manage:version-review', kwargs={
            'institution_slug': self.institution.slug,
            'pk': version.pk,
        })
        response: TemplateResponse = self.client.post(url, data={
            'reviewer': self.auditor.pk,
        }, follow=True)
        self.assertRedirects(response, url)
        self.assertContains(response, 'Successfully updated')
        updated_version: Version = Version.objects.get(pk=version.pk)
        self.assertEqual(updated_version.reviewer, self.auditor)
        with self.subTest("reviewer notification sent"):
            self.assertEqual(1, len(mail.outbox))
            email = mail.outbox[0]
            self.assertEqual("You have been assigned to approve {0}".format(document.name), email.subject)
            self.assertEqual([self.auditor.user.email], email.to)
            version_url = reverse("docs:manage:version-review", kwargs={'institution_slug': self.institution.slug, 'pk': version.pk})
            self.assertIn(version_url, email.body)
            self.assertIn("{0} has uploaded a new version of {1} and assigned its approval to you. You can find the new version here:".format(version.creator.user.username, document.name), email.body)

    def test_review_page__no_perm(self):
        self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.approve_version'), get_permission_by_name('megdocs.view_version'))
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document')
        version: Version = baker.make(Version, document=document, reviewer=self.auditor, _create_files=True)

        url = reverse('docs:manage:version-review', kwargs={
            'institution_slug': self.institution.slug,
            'pk': version.pk,
        })
        with self.subTest('View version'):
            response: TemplateResponse = self.client.get(url)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

        with self.subTest('Approval'):
            response: TemplateResponse = self.client.post(url, data={'approve': 'true'}, follow=True)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

            version = Version.objects.get(pk=version.pk)
            document = Document.objects.get(pk=document.pk)
            self.assertFalse(version.approved)
            self.assertIsNone(document.current_version)

    def test_review_page__change_reviewer__no_perm(self):
        self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.change_version'))
        document: Document = baker.make(Document, institution=self.institution, owner__institution=self.institution, name='Test Document')
        version: Version = baker.make(Version, document=document, reviewer=self.auditor, _create_files=True)

        url = reverse('docs:manage:version-review', kwargs={
            'institution_slug': self.institution.slug,
            'pk': version.pk,
        })
        with self.subTest('View version'):
            response: TemplateResponse = self.client.get(url)
            self.assertNotContains(response, 'Save')

        with self.subTest('change owner'):
            new_reviewer = baker.make(Auditor, institution=self.institution, user__user_permissions=[get_permission_by_name('megdocs.approve_version')])
            response: TemplateResponse = self.client.post(url, data={
                'reviewer': new_reviewer.pk,
            }, follow=True)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
            updated_version: Version = Version.objects.get(pk=version.pk)
            self.assertNotEqual(updated_version.reviewer, new_reviewer)

    @english_test
    def test_review_page__change_reviewer__no_perm__owner(self):
        self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.change_version'))
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='Test Document')
        version: Version = baker.make(Version, document=document, reviewer=self.auditor, _create_files=True)

        url = reverse('docs:manage:version-review', kwargs={
            'institution_slug': self.institution.slug,
            'pk': version.pk,
        })
        with self.subTest('View version'):
            response: TemplateResponse = self.client.get(url)
            self.assertContains(response, 'Save')

        with self.subTest('change owner'):
            new_reviewer = baker.make(Auditor, institution=self.institution, user__user_permissions=[get_permission_by_name('megdocs.approve_version')], user__username='new_reviewer')
            self.client.post(url, data={
                'reviewer': new_reviewer.pk,
            }, follow=True)
            updated_version: Version = Version.objects.get(pk=version.pk)
            self.assertEqual(updated_version.reviewer, new_reviewer)

    @english_test
    def test_folder_create(self):
        self.assertFalse(Folder.objects.filter(name="created folder").exists())
        baker.make(FolderPermissionRule, institution=self.institution, folders=[self.folder], users=[self.auditor.user], permissions=[
            Permission.objects.get(codename="add_folder", content_type__app_label="megdocs"),
        ])

        response = self.client.post(self.folder_create_url, data={
            "name": "created folder",
            "description": "test description",
            "parent": self.folder.pk,
        }, follow=True)

        folder: Folder = Folder.objects.get(name="created folder")

        with self.subTest('Created folder'):
            self.assertEqual(folder.name, 'created folder')
            self.assertEqual(folder.description, 'test description')
            self.assertEqual(folder.owner, self.auditor)
            self.assertEqual(folder.institution, self.institution)
            self.assertEqual(folder.parent, self.folder)

        with self.subTest('Response'):
            self.assertRedirects(response, reverse('docs:manage:doc-list', kwargs={
                'institution_slug': self.institution.slug,
                'folder': folder.pk,
            }))
            self.assertContains(response, 'Successfully created created folder')

    @english_test
    def test_folder_update(self):
        self.assertFalse(Folder.objects.filter(name="updated folder").exists())
        response = self.client.post(self.folder_update_url, data={
            "name": "updated folder",
            "description": "test description",
        }, follow=True)
        folder: Folder = Folder.objects.filter(name="updated folder").first()

        with self.subTest('Updated folder'):
            self.assertEqual(folder.name, 'updated folder')
            self.assertEqual(folder.description, 'test description')
            self.assertEqual(folder.owner, self.auditor)
            self.assertEqual(folder.institution, self.institution)
            self.assertIsNone(folder.parent)

        with self.subTest('Response'):
            self.assertRedirects(response, reverse('docs:manage:doc-list', kwargs={
                'institution_slug': self.institution.slug,
                'folder': folder.pk,
            }))
            self.assertContains(response, 'Successfully saved updated folder')

    def test_folder_delete__owner_unauthorized(self):
        self.assertTrue(Folder.objects.first().publish)
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        baker.make(FolderPermissionRule, institution=self.institution, folders=[self.folder])
        response = self.client.post(self.folder_update_url, data={"save": "remove"}, follow=True)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        self.assertTrue(Folder.objects.first().publish)

    def test_folder_delete__owner_authorized(self):
        self.assertTrue(Folder.objects.first().publish)
        response = self.client.post(self.folder_update_url, data={"save": "remove"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Folder.objects.first().publish)

    def test__folder_list__superuser(self):
        Folder.objects.create(name="verbose_folder_name_for_testing", owner=baker.make(Auditor), institution=self.institution)
        response = self.client.get(self.document_list_url)

        with self.subTest("user can't view"):
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

    def test_docs_archived(self):
        archived_url = reverse_lazy('docs:manage:doc-list-archived', kwargs={'institution_slug': self.institution.slug})
        doc: Document = baker.make(Document, name='Doc', institution=self.institution, _fill_optional=['current_version'])
        doc2: Document = baker.make(Document, name='Doc2', institution=self.institution, _fill_optional=['current_version'])

        with self.subTest("no archived documents"):
            response = self.client.get(archived_url, follow=True)
            self.assertNotIn(doc, response.context_data['document_list'])
            self.assertNotIn(doc2, response.context_data['document_list'])

        with self.subTest("archived documents"):
            Document.objects.filter(institution=self.institution).update(archived=True)
            response = self.client.get(archived_url, follow=True)
            self.assertIn(doc, response.context_data['document_list'])
            self.assertIn(doc2, response.context_data['document_list'])

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
        sub_folder: Folder = Folder.objects.create(name="verbose_sub_folder_name", owner=self.auditor, parent=self.folder, institution=self.institution)
        parent_doc: Document = baker.make(Document, name='Doc2', institution=self.institution, current_version__approved=True, folder=self.folder)
        sub_folder_doc: Document = baker.make(Document, name='Doc', institution=self.institution, current_version__approved=True, folder=sub_folder)
        folder_url = reverse_lazy('docs:manage:doc-list', kwargs={'institution_slug': self.institution.slug, 'folder': self.folder.pk})
        response = self.client.get(folder_url, follow=True)
        self.assertContains(response, sub_folder.name, count=4)
        # Make sure selected folder is preselected for upload form
        self.assertContains(response, f'{self.bulk_upload_url}?folder={self.folder.pk}')
        self.assertIn(parent_doc, response.context_data['document_list'])
        self.assertNotIn(sub_folder_doc, response.context_data['document_list'])

    def test_archived_documents_not_visible(self):
        archived_doc: Document = baker.make(Document, archived=True, name='archived_doc', institution=self.institution, current_version__approved=True, folder=self.folder)
        folder_url = reverse_lazy('docs:manage:doc-list', kwargs={'institution_slug': self.institution.slug, 'folder': self.folder.pk})
        response = self.client.get(folder_url, follow=True)
        self.assertNotIn(archived_doc, response.context_data['document_list'])

    def test_folder_permissions_not_visible(self):
        response: TemplateResponse = self.client.get(self.document_list_url, follow=True)
        self.assertNotContains(response, "Permission rules")
        self.assertNotContains(response, "Create Rule")
        rules_list_url = reverse_lazy('docs:manage:folder-permission-rules', kwargs={'institution_slug': self.institution.slug})
        response: TemplateResponse = self.client.get(rules_list_url, follow=True)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

    @english_test
    def test_folder_permissions_visible(self):
        self.auditor.user.user_permissions.add(
            get_permission_by_name('megdocs.view_folderpermissionrule'),
            get_permission_by_name('megdocs.add_folderpermissionrule')
        )
        response: TemplateResponse = self.client.get(self.document_list_url, follow=True)
        self.assertContains(response, "Permission rules")
        self.assertContains(response, "Create Rule")
        rules_list_url = reverse_lazy('docs:manage:folder-permission-rules', kwargs={'institution_slug': self.institution.slug})
        response: TemplateResponse = self.client.get(rules_list_url, follow=True)
        self.assertNotContains(response, "Is your current document management system a graveyard for unused")

    def test_folder_permission_rule_edit_delete_access(self):
        rule: FolderPermissionRule = baker.make(FolderPermissionRule, institution=self.institution)
        edit_url = reverse_lazy('docs:manage:folder-permission-rule-update', kwargs={'institution_slug': self.institution.slug, 'pk': rule.pk})

        with self.subTest("edit unauthorized"):
            response: TemplateResponse = self.client.get(edit_url, follow=True)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

        with self.subTest("edit authorized"):
            self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.change_folderpermissionrule'))
            response: TemplateResponse = self.client.get(edit_url, follow=True)
            self.assertNotContains(response, "Is your current document management system a graveyard for unused")

        with self.subTest("delete unauthorized"):
            response: TemplateResponse = self.client.post(edit_url, follow=True, data={"save": "remove"})
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

        with self.subTest("delete authorized"):
            self.auditor.user.user_permissions.add(
                get_permission_by_name('megdocs.delete_folderpermissionrule'),
                get_permission_by_name('megdocs.view_folderpermissionrule'),
            )
            response: TemplateResponse = self.client.post(edit_url, follow=True, data={"save": "remove"})
            self.assertNotContains(response, "Is your current document management system a graveyard for unused")

    @english_test
    def test_document_breadcrumbs(self):
        folder: Folder = Folder.objects.create(name="folder__verbose_name", owner=self.auditor, parent=None, institution=self.institution)
        sub_folder: Folder = Folder.objects.create(name="sub_folder__verbose_name", owner=self.auditor, parent=folder, institution=self.institution)
        sub_sub_folder: Folder = Folder.objects.create(name="sub_sub_folder__verbose_name", owner=self.auditor, parent=sub_folder, institution=self.institution)
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor, name='test_document__verbose_name', folder=sub_sub_folder)
        version: Version = baker.make(Version, document=document, approved=False, _create_files=True, revision=1, creator=self.auditor)
        url_kwargs = {
            'institution_slug': self.institution.slug,
            'pk': document.pk,
        }
        document_edit_url = reverse('docs:manage:doc-edit', kwargs=url_kwargs)
        document_view_url = reverse('docs:view:doc-detail', kwargs=url_kwargs)
        with self.subTest("document edit"):
            response: TemplateResponse = self.client.get(document_edit_url)
            self.assertContains(response, folder.name + "</a>")
            self.assertContains(response, sub_folder.name + "</a>")
            self.assertContains(response, sub_sub_folder.name + "</a>")

        with self.subTest("create version"):
            response: TemplateResponse = self.client.get(reverse('docs:manage:version-create', kwargs={
                'institution_slug': self.institution.slug,
                'pk': document.pk,
            }))
            self.assertContains(response, folder.name + "</a>")
            self.assertContains(response, sub_folder.name + "</a>")
            self.assertContains(response, sub_sub_folder.name + "</a>")

        with self.subTest("review version"):
            response: TemplateResponse = self.client.get(reverse('docs:manage:version-review', kwargs={
                'institution_slug': self.institution.slug,
                'pk': version.pk,
            }))
            self.assertNotContains(response, folder.name + "</a>")
            self.assertNotContains(response, sub_folder.name + "</a>")
            self.assertNotContains(response, sub_sub_folder.name + "</a>")
            self.assertContains(response, document.name + "</a>")
            self.assertContains(response, f"Version {version.version}</li>")

        with self.subTest("bookmarked"):
            baker.make(Bookmark, user=self.auditor.user, document=document)
            response: TemplateResponse = self.client.get(document_edit_url)
            self.assertContains(response, folder.name + "</a>")
            self.assertContains(response, sub_folder.name + "</a>")
            self.assertContains(response, sub_sub_folder.name + "</a>")
            self.assertContains(response, document.name + "</a>")
            self.assertContains(response, f"Version {version.version}</li>")

        with self.subTest("archived"):
            document.archived = True
            document.save()
            response: TemplateResponse = self.client.get(document_edit_url)
            self.assertNotContains(response, folder.name + "</a>")
            self.assertNotContains(response, sub_folder.name + "</a>")
            self.assertNotContains(response, sub_sub_folder.name + "</a>")
            self.assertContains(response, document.name + "</a>")
            self.assertContains(response, f"Version {version.version}</li>")
            self.assertContains(response, "Archived")

        with self.subTest("user without change permission"):
            version.approved = True
            version.save()
            document.archived = False
            document.current_version = version
            document.save()
            self.auditor.user.user_permissions.set(get_permissions(['megdocs.view_document', 'megdocs.view_folder']))
            response: TemplateResponse = self.client.get(document_view_url)
            self.assertEqual(response.status_code, HTTP_200_OK)
            self.assertContains(response, document.name + "</a>")
            self.assertNotContains(response, document_edit_url)

    def test_document_link_change_view(self):
        document: Document = baker.make(Document, name='doc', institution=self.institution)
        create_url = reverse('docs:manage:doc-link', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})
        with self.subTest("create - perms"):
            response: TemplateResponse = self.client.get(create_url)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
            self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.add_documentlink'))
            response: TemplateResponse = self.client.get(create_url)
            self.assertEqual(response.status_code, HTTP_200_OK)
        with self.subTest("context"):
            self.assertContains(response, document)
            self.assertIsNone(response.context_data['form'].instance.pk)
        with self.subTest("update - perms"):
            document_link: DocumentLink = baker.make(DocumentLink, document=document)
            edit_url = reverse('docs:manage:doc-link', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk, 'link': document_link.pk})
            response: TemplateResponse = self.client.get(edit_url)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
            self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.change_documentlink'))
            response: TemplateResponse = self.client.get(edit_url)
            self.assertEqual(response.status_code, HTTP_200_OK)
        with self.subTest("context"):
            self.assertContains(response, document)
            self.assertEqual(response.context_data['form'].instance, document_link)
        with self.subTest("delete - perms"):
            response: TemplateResponse = self.client.post(edit_url, data={'delete': True})
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
            self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.delete_documentlink'))
            response: TemplateResponse = self.client.post(edit_url, data={'delete': True})
            self.assertEqual(response.status_code, HTTP_200_OK)
            self.assertEqual(response.headers['Hx-Trigger'], '{"documentLinkSuccess": ""}')
            self.assertFalse(DocumentLink.objects.get().publish)
        with self.subTest("unauthorized document"):
            inaccessible_document: Document = baker.make(Document)
            response: TemplateResponse = self.client.get(reverse('docs:manage:doc-link', kwargs={'institution_slug': self.institution.slug, 'pk': inaccessible_document.pk}))
            self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)

    @english_test
    def test_document_edit_view__embed_view(self):
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor)
        url = reverse('docs:manage:doc-edit', kwargs={
            'institution_slug': self.institution.slug,
            'pk': document.pk,
        })
        with self.subTest("pdf"):
            document.current_version = baker.make(Version, file='megdocs/documents/test.pdf', document=document)
            document.save()
            self.assertContains(self.client.get(url), f'<iframe src="{pdf_viewer_url(document.current_version.file)}" width="100%" height="700px" class="document-embed"></iframe>')
        with self.subTest("image"):
            document.current_version = baker.make(Version, file='megforms/static/images/file.png', document=document, revision=2)
            document.save()
            response: TemplateResponse = self.client.get(url)
            self.assertEqual(response.status_code, HTTP_200_OK)
            self.assertContains(response, f"<img src='{create_field_file_url(document.current_version.file)}' />")
        with self.subTest("download link"):
            document.current_version = baker.make(Version, file='megforms/tests/data/test_template.xlsx', document=document, revision=3)
            document.save()
            response: TemplateResponse = self.client.get(url)
            self.assertEqual(response.status_code, HTTP_200_OK)
            if IS_ENGLISH_LOCALE:
                self.assertContains(response, 'Cannot load preview for xlsx documents')
            download_icon = icon("download-alt")
            self.assertContains(response, f'<a href="{document.current_version.file_url}" target="_blank" class="btn btn-primary">{download_icon}')

    def test_version__mark_as_reviewed(self):
        self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.approve_institution_versions'))
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor)
        version = baker.make(Version, file='megdocs/documents/test.pdf', document=document, creation_date=(datetime.datetime.now() - datetime.timedelta(days=400)).date())
        document.current_version = version
        document.save()
        review_url = reverse('docs:manage:version-review', kwargs={'institution_slug': self.institution.slug, 'pk': version.pk})
        self.auditor.user.user_permissions.remove(get_permission_by_name("megdocs.change_version"))
        with self.subTest("template context"):
            response: TemplateResponse = self.client.get(review_url, follow=True)
            self.assertFalse(response.context_data['allow_mark_reviewed'])
            self.assertNotContains(response, "mark-reviewed")
            self.assertNotContains(response, "mark-reviewed-form")
        with self.subTest("permission required"):
            response: TemplateResponse = self.client.post(review_url, follow=True, data={'save': 'mark-reviewed'})
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        with self.subTest("permission granted"):
            self.auditor.user.user_permissions.add(get_permission_by_name("megdocs.change_version"))
            response: TemplateResponse = self.client.get(review_url, follow=True)
            self.assertTrue(response.context_data['allow_mark_reviewed'])
            self.assertContains(response, "mark-reviewed")
            self.assertContains(response, "mark-reviewed-form")
        with self.subTest("marked as reviewed"):
            response: TemplateResponse = self.client.post(review_url, follow=True, data={'save': 'mark-reviewed'})
            self.assertEqual(response.status_code, HTTP_200_OK)
            self.assertTrue(Version.objects.get(pk=version.pk).creation_date, datetime.datetime.today())
            if IS_ENGLISH_LOCALE:
                self.assertContains(response, f"{version} reviewed.")

    def test_version_list_queryset_ringfencing(self):
        admin: Version = baker.make(Version, document__institution=self.institution, creation_date=(datetime.datetime.now() - datetime.timedelta(days=400)).date())
        admin.document.current_version = admin
        admin.save()
        response: TemplateResponse = self.client.get(self.review_versions_url, follow=True)
        self.assertNotIn(admin, response.context_data['object_list'])
        self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.approve_institution_versions'))
        response: TemplateResponse = self.client.get(self.review_versions_url, follow=True)
        self.assertIn(admin, response.context_data['object_list'])

    def test_version_file__visible_to_viewer(self):
        self.auditor.user.user_permissions.remove(get_permission_by_name('megdocs.approve_institution_versions'))
        document: Document = baker.make(Document, institution=self.institution)
        document_version: Version = baker.make(Version, document=document, _create_files=True)
        with self.subTest("version isn't a current version"):
            response: HttpResponse = self.client.get(document_version.file_url, follow=True)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        with self.subTest("version made current version"):
            document.current_version = document_version
            document.save()
            response: HttpResponse = self.client.get(document_version.file_url, follow=True)
            self.assertEqual(response.status_code, HTTP_200_OK)

    @english_test
    def test_version_review__diff(self, *args):
        self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.approve_institution_versions'))
        document: Document = baker.make(Document, institution=self.institution, owner=self.auditor)
        curr_version = baker.make(Version, file='megdocs/documents/test.pdf', document=document, approved=True, content="", revision=1)
        document.current_version = curr_version
        document.save()
        version = baker.make(Version, file='megdocs/documents/test.pdf', document=document, content="", revision=2)
        response = self.client.get(reverse('docs:manage:version-review', kwargs={'institution_slug': self.institution.slug, 'pk': version.pk}))
        self.assertContains(response, 'The difference view can not be rendered as the text content of the document is not available.')

    def test_folder_permission_rule__no_folder__institution_ringfencing_check(self):
        baker.make(FolderPermissionRule, permissions=[get_permission_by_name('megdocs.delete_document')])
        document: Document = baker.make(Document, institution=self.institution, name='Test Document', folder__institution=self.institution)
        version: Version = baker.make(Version, document=document, approved=True, _create_files=True, revision=1)
        document.current_version = version
        document.save()
        url = reverse('docs:manage:doc-detail', kwargs={'pk': document.pk, 'institution_slug': self.institution.slug})
        with self.subTest("rule in another institution"):
            response = self.client.get(url)
            self.assertEqual(response.status_code, HTTP_200_OK)
        with self.subTest("rule in current institution"):
            FolderPermissionRule.objects.update(institution=self.institution)
            response = self.client.get(url)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)


class DocumentAcknowledgmentStatusTest(TestCase):
    permissions = (
        'megdocs.view_document',
        'megdocs.view_folder',
        *MANAGE_PERMS,
    )

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.institution: Institution = baker.make(Institution, name='Test Institution', megdocs_enabled=True)
        cls.auditor: Auditor = baker.make(Auditor, user__email='auditor@test.com', institution=cls.institution, user__username='lead', user__user_permissions=get_permissions(cls.permissions, validate=True))
        cls.other_auditor = baker.make(Auditor, user__email='admin@test.com', institution=cls.institution, user__username='admin', user__user_permissions=get_permissions(cls.permissions, validate=True))
        cls.document_list_url = reverse_lazy('docs:manage:doc-list', kwargs={'institution_slug': cls.institution.slug})
        cls.document: Document = baker.make(Document, name='Mopping instructions', institution=cls.institution, _fill_optional=['current_version'])

    def setUp(self) -> None:
        super().setUp()
        self.client.force_login(self.auditor.user)

    def test_list_view__no_checkbox(self):
        response: HttpResponse = self.client.get(self.document_list_url, follow=True)
        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertNotContains(response, 'ack-checkbox-container')
        self.assertFalse(response.context['document_list'].first().has_checkbox)
        self.assertFalse(response.context['document_list'].first().is_acknowledged)

    def test_list_view__ack_checkbox(self):
        checkbox: DocumentCheckbox = baker.make(DocumentCheckbox, label='This needs acknowledgment', document=self.document)
        with self.subTest('Not acknowledged'):
            response: HttpResponse = self.client.get(self.document_list_url, follow=True)
            self.assertEqual(response.status_code, HTTP_200_OK)
            if IS_ENGLISH_LOCALE:
                self.assertContains(response, 'Requires Acknowledgement')
            self.assertTrue(response.context['document_list'].first().has_checkbox)
            self.assertFalse(response.context['document_list'].first().is_acknowledged)

        with self.subTest('Acknowledged'):
            baker.make(DocumentCheckboxState, checkbox=checkbox, user=self.auditor, version=self.document.current_version)
            response: HttpResponse = self.client.get(self.document_list_url, follow=True)
            self.assertEqual(response.status_code, HTTP_200_OK)
            if IS_ENGLISH_LOCALE:
                self.assertContains(response, 'Acknowledged')
            self.assertTrue(response.context['document_list'].first().has_checkbox)
            self.assertTrue(response.context['document_list'].first().is_acknowledged)
            self.assertContains(response, 'Icon-acknowledge.svg')

        with self.subTest('Another user needs to acknowledge'):
            self.client.force_login(self.other_auditor.user)
            response: HttpResponse = self.client.get(self.document_list_url, follow=True)
            self.assertEqual(response.status_code, HTTP_200_OK)
            if IS_ENGLISH_LOCALE:
                self.assertContains(response, 'Requires Acknowledgement')
            self.assertTrue(response.context['document_list'].first().has_checkbox)
            self.assertFalse(response.context['document_list'].first().is_acknowledged)
