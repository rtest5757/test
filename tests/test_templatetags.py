from django.db.models import QuerySet
from django.test import TestCase
from django.urls import reverse_lazy
from rest_framework.status import HTTP_200_OK
from megdocs.constants import MANAGE_PERMS
from megdocs.models import DocumentCheckbox, DocumentCheckboxState, Document
from megdocs.templatetags.megdocs import render_document_checked_users
from megdocs.test_utils import DocumentTestMixin
from model_bakery import baker
from megforms.models import Institution, Auditor
from megforms.utils import get_permissions


class TemplateTagTest(DocumentTestMixin, TestCase):
    def test_render_document_checked_users(self):
        baker.make(DocumentCheckboxState, checkbox__label='some other checkbox, ignore me')
        checkbox_obj: DocumentCheckbox = baker.make(DocumentCheckbox, document=self.document)

        with self.subTest('unchecked'):
            result = render_document_checked_users(self.document.current_version)
            checkbox, = result['checkboxes']
            self.assertIsInstance(checkbox, DocumentCheckbox)
            self.assertFalse(checkbox.states.all())

        DocumentCheckboxState.objects.create(checkbox=checkbox_obj, version=self.document.current_version, user=self.auditor)
        with self.subTest('checked'):
            with self.assertNumQueries(2):
                result = render_document_checked_users(self.document.current_version)
                checkbox, = result['checkboxes']
                self.assertIsInstance(checkbox, DocumentCheckbox)
                self.assertEqual(len(checkbox.states.all()), 1)
                state, = checkbox.states.all()
                self.assertEqual(state.user, self.auditor)
            self.assertEqual(state.version, self.document_version)

        with self.subTest('no version'), self.assertNumQueries(0):
            result = render_document_checked_users(None)
            self.assertIsInstance(result['checkboxes'], QuerySet)
            self.assertFalse(result['checkboxes'])


class IsArchivedFilterTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.institution: Institution = baker.make(Institution, name='Test Institution', megdocs_enabled=True)
        cls.auditor: Auditor = baker.make(
            Auditor, user__email='auditor@test.com', institution=cls.institution, user__username='lead',
            user__user_permissions=get_permissions([*MANAGE_PERMS, 'megdocs.view_document', 'megdocs.view_folder'], validate=True,)
        )

    def setUp(self) -> None:
        super().setUp()
        self.client.force_login(self.auditor.user)

    def test_docs_archived(self):
        archived_url = reverse_lazy('docs:manage:doc-list-archived', kwargs={'institution_slug': self.institution.slug})
        baker.make(Document, name='Doc', institution=self.institution, _fill_optional=['current_version'], archived=True)

        response = self.client.get(archived_url, follow=True)
        self.assertEqual(response.status_code, HTTP_200_OK)
        with self.subTest("archived documents"):
            self.assertTrue(response.context_data['document_list'][0].is_archived)

        with self.subTest("missing 'has_archived_status' annotation"):
            doc1, = response.context_data['document_list']
            self.assertTrue(Document.objects.get(pk=doc1.pk).is_archived)
