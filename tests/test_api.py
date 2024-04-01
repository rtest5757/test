import re

from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse_lazy
from model_bakery import baker
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_200_OK, HTTP_201_CREATED
from rest_framework.test import APITestCase

from megdocs.constants import REVIEWER_PERMISSION, REVIEW_FREQUENCY_TWO_YEARS
from megdocs.models import Document, Folder, Version, DocumentCategory, DocumentUploadMetadata
from megforms.models import Auditor, Institution, AuditForm
from megdocs.test_utils import DocumentTestMixin, DocumentMetadataRow, create_excel_upload_bytes
from megforms.test_utils import IS_ENGLISH_LOCALE, AuditorInstitutionTestMixin
from megforms.utils import get_permissions, get_permission_by_name


class APITests(DocumentTestMixin, APITestCase):
    auditor_login = True
    auditor_perms = 'megdocs.view_document',
    docs_url = reverse_lazy('api-v2:document-list')

    def test_docs_list(self):
        Document.objects.all().delete()
        with self.subTest("empty list"):
            response: Response = self.client.get(self.docs_url)
            self.assertEqual(response.data['count'], 0)
            self.assertIsNone(response.data['next'])
            self.assertIsNone(response.data['previous'])
            self.assertEqual(response.data['results'], [])
        with self.subTest("documents"):
            baker.make(Document, name="test document", institution=self.institution, folder=None)
            baker.make(Document, name="other", institution__name="other")
            response: Response = self.client.get(self.docs_url)
            self.assertEqual(response.data['count'], 1)
            self.assertIsNone(response.data['next'])
            self.assertIsNone(response.data['previous'])
            document = response.data['results'][0]
            self.assertEqual(document['name'], "test document")


class TestDocumentMetadata(AuditorInstitutionTestMixin, APITestCase):
    auditor_login = True
    auditor_perms = (
        "megdocs.view_documentuploadmetadata", "megdocs.change_documentuploadmetadata", "megdocs.add_documentuploadmetadata",
        "megdocs.add_document", "megdocs.change_document", "megdocs.add_folder", "megdocs.add_version", "megdocs.change_version",
        "megdocs.approve_version",
    )
    document_metadata_url = reverse_lazy('api-v2:documentmetadata-list')

    def test_create_metadata(self):
        doc1 = DocumentMetadataRow(
            name="doc1",
            creator=self.auditor.pk,
            filename="doc1.pdf",
            revision=1,
        ).as_dict()
        doc2 = DocumentMetadataRow(
            name="doc2",
            creator=self.auditor.pk,
            filename="doc2.pdf",
            tags="test,tags",
            forms="1,2,3",
            documents="4,5,6",
            contributors="7,8,9",
            archived="false",
            approved="yes",
            make_current="no",
            revision=1,
        ).as_dict()
        excel_upload = SimpleUploadedFile("upload.xlsx", create_excel_upload_bytes([doc1, doc2]), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response = self.client.post(self.document_metadata_url, data={'data': excel_upload, 'institution': self.institution.pk}, format='multipart')
        self.assertEqual(response.status_code, HTTP_201_CREATED, msg=response.json())
        metadata: DocumentUploadMetadata = DocumentUploadMetadata.objects.get()
        self.assertEqual(metadata.institution_id, response.json()['institution'])
        with self.subTest("doc1"):
            doc1 = [d for d in metadata.data if d['filename'] == 'doc1.pdf'][0]
            self.assertEqual(doc1["name"], "doc1")
            self.assertEqual(doc1["creator"], self.auditor.pk)
            self.assertEqual(doc1["filename"], "doc1.pdf")
            self.assertEqual(doc1["revision"], 1)
            self.assertEqual(doc1['tags'], [])
            self.assertEqual(doc1['forms'], [])
            self.assertEqual(doc1['documents'], [])
            self.assertEqual(doc1['contributors'], [])
            self.assertEqual(doc1['archived'], False)
            self.assertEqual(doc1['approved'], False)
            self.assertEqual(doc1['make_current'], False)
        with self.subTest("doc2"):
            doc2 = [d for d in metadata.data if d['filename'] == 'doc2.pdf'][0]
            self.assertEqual(doc2['tags'], ["test", "tags"])
            self.assertEqual(doc2['forms'], ["1", "2", "3"])
            self.assertEqual(doc2['documents'], ["4", "5", "6"])
            self.assertEqual(doc2['contributors'], ["7", "8", "9"])
            self.assertEqual(doc2['archived'], False)
            self.assertEqual(doc2['approved'], True)
            self.assertEqual(doc2['make_current'], False)

    def test_create_metadata__validate_required_fields(self):
        test_data = (
            ("name", dict(creator=self.auditor.pk, filename="doc1.pdf", revision=1)),
            ("filename", dict(creator=self.auditor.pk, name="test", revision=1)),
            ("creator", dict(name="test", filename="doc1.pdf", revision=1)),
        )
        for field_name, kwargs in test_data:
            with self.subTest(field_name):
                excel_upload = SimpleUploadedFile("upload.xlsx", create_excel_upload_bytes([DocumentMetadataRow(**kwargs).as_dict()]), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                response = self.client.post(self.document_metadata_url, data={'data': excel_upload, 'institution': self.institution.pk}, format='multipart')
                self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
                if IS_ENGLISH_LOCALE:
                    self.assertEqual(['Each row must have the following fields: name,filename,creator,revision'], response.json()['data'])

    def test_create_metadata__validate_version_fields(self):
        test_data = (
            ("revision", dict(creator=self.auditor.pk, name="test", filename="doc1.pdf", revision=1)),
            ("version_name", dict(creator=self.auditor.pk, name="test", filename="doc1.pdf", revision=2, version_name="test")),
        )
        for field_name, kwargs in test_data:
            with self.subTest(field_name):
                excel_upload = SimpleUploadedFile("upload.xlsx", create_excel_upload_bytes([DocumentMetadataRow(**kwargs).as_dict()]), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                response = self.client.post(self.document_metadata_url, data={'data': excel_upload, 'institution': self.institution.pk}, format='multipart')
                self.assertEqual(response.status_code, HTTP_201_CREATED, msg=response.json())
        with self.subTest("required validation"):
            excel_upload = create_excel_upload_bytes([DocumentMetadataRow(creator=self.auditor.pk, name="test", filename="doc1.pdf").as_dict()])
            excel_upload = SimpleUploadedFile("upload.xlsx", excel_upload, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            response = self.client.post(self.document_metadata_url, data={'data': excel_upload, 'institution': self.institution.pk}, format='multipart')
            self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
            if IS_ENGLISH_LOCALE:
                self.assertEqual(['Each row must have the following fields: name,filename,creator,revision'], response.json()['data'], msg=response.json())

    def test_create_metadata__validate_institution(self):
        institution = baker.make(Institution)
        doc1 = DocumentMetadataRow(
            name="doc1",
            creator=self.auditor.pk,
            filename="doc1.pdf",
            revision=1,
        ).as_dict()
        excel_upload = SimpleUploadedFile("upload.xlsx", create_excel_upload_bytes([doc1]), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response = self.client.post(self.document_metadata_url, data={'data': excel_upload, 'institution': institution.pk}, format='multipart')
        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST, msg=response.json())
        if IS_ENGLISH_LOCALE:
            self.assertEqual([f'Please select another choice. {institution.pk} is not one of the available choices'], response.json()['institution'])

    def test_metadata_upload(self):
        reviewer: Auditor = baker.make(Auditor, institution=self.institution, user__user_permissions=[get_permission_by_name('megdocs.approve_version')])
        contributor: Auditor = baker.make(Auditor, institution=self.institution, user__user_permissions=get_permissions(['megdocs.view_version', 'megdocs.add_version', 'megdocs.change_version', REVIEWER_PERMISSION]))
        category: DocumentCategory = baker.make(DocumentCategory, institution=self.institution)
        form: AuditForm = baker.make(AuditForm, institution=self.institution)
        self.auditor.forms.add(form)
        docs = [
            DocumentMetadataRow(
                name="doc",
                folder_path="policies/procedures",
                owner=self.auditor.pk,
                creator=self.auditor.pk,
                filename="doc.pdf",
                tags="policy,procedure",
                review_interval="730 00:00:00.000000",
                required_approvals=2,
                revision=2,
                forms=str(form.pk),
                category=str(category.pk),
                reviewer=str(reviewer.pk),
                contributors=str(contributor.pk),
            ).as_dict(),
            DocumentMetadataRow(
                name="doc",
                filename="doc_3.pdf",
                creator=self.auditor.pk,
                word_filename="doc_3.docx",
                revision=3,
                reviewer=str(reviewer.pk),
                contributors=str(contributor.pk),
                make_current="true",
                approved="true",
            ).as_dict(),
            DocumentMetadataRow(
                name="doc",
                filename="doc_1.pdf",
                creator=self.auditor.pk,
                revision=1,
                reviewer=str(reviewer.pk),
                make_current="false",
                approved="true",
            ).as_dict(),
        ]
        self.assertFalse(Document.objects.exists())
        excel_upload = SimpleUploadedFile("upload.xlsx", create_excel_upload_bytes(docs), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response = self.client.post(self.document_metadata_url, data={'data': excel_upload, 'institution': self.institution.pk}, format='multipart')
        self.assertEqual(response.status_code, HTTP_201_CREATED, msg=response.json())
        url = reverse_lazy('api-v2:documentmetadata-upload', kwargs={'pk': response.json()['pk']})
        with self.subTest("create document"):
            response = self.client.post(url, data={'file': SimpleUploadedFile("doc.pdf", b"test", content_type="application/pdf")}, format='multipart')
            self.assertEqual(response.status_code, HTTP_201_CREATED, msg=response.json())
            document: Document = Document.objects.get(name="doc")
            self.assertEqual(document.owner, self.auditor)
            self.assertEqual(document.folder, Folder.objects.filter(institution=self.institution, name="procedures", parent__institution=self.institution, parent__name="policies").get())
            self.assertEqual(set(document.tags.names()), {"policy", "procedure"})
            self.assertEqual(document.review_interval, REVIEW_FREQUENCY_TWO_YEARS)
            self.assertFalse(document.archived)
            self.assertEqual(document.category, category)
            self.assertEqual(set(document.forms.all()), {form})
            self.assertFalse(document.documents.exists())
            self.assertIsNone(document.current_version_id)
            version: Version = document.versions.get()
            self.assertRegex(version.file.name, re.compile(r'megdocs\/documents\/doc\w*\.pdf'))
            self.assertEqual(version.creator, self.auditor)
            self.assertEqual(version.reviewer, reviewer)
            self.assertEqual(set(version.contributors.all()), {contributor})
            self.assertFalse(version.approved)
            self.assertEqual(version.revision, 2)
            self.assertFalse(version.version_name)
        with self.subTest("new approved current version of document"):
            response = self.client.post(url, data={'file': SimpleUploadedFile("doc_3.pdf", b"test", content_type="application/pdf")}, format='multipart')
            self.assertEqual(response.status_code, HTTP_201_CREATED, msg=response.json())
            document: Document = Document.objects.get(name="doc")
            version: Version = document.current_version
            self.assertRegex(version.file.name, re.compile(r'megdocs\/documents\/doc_\w*\.pdf'))
            self.assertTrue(version.approved)
            self.assertEqual(version.revision, 3)
            with self.assertRaises(ValueError):
                version.source.file
        with self.subTest("upload word version"):
            response = self.client.post(url, format='multipart', data={'file': SimpleUploadedFile("doc_3.docx", b"test", content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")})
            self.assertEqual(response.status_code, HTTP_200_OK, msg=response.json())
            document: Document = Document.objects.get(name="doc")
            version: Version = document.current_version
            self.assertRegex(version.source.name, re.compile(r'megdocs\/documents\/doc_3\w*\.docx'))
        with self.subTest("old version of document"):
            response = self.client.post(url, format='multipart', data={'file': SimpleUploadedFile("doc_1.pdf", b"test", content_type="application/pdf")})
            self.assertEqual(response.status_code, HTTP_201_CREATED, msg=response.json())
            version: Version = document.versions.get(revision=1)
            self.assertRegex(version.file.name, re.compile(r'megdocs\/documents\/doc_1\w*\.pdf'))
            self.assertFalse(version.contributors.exists())
            self.assertTrue(version.approved)

    def test_metadata_upload__rollback_on_error(self):
        self.assertFalse(Document.objects.exists())
        docs = [DocumentMetadataRow(
            name="doc",
            owner=self.auditor.pk,
            creator=self.auditor.pk,
            filename="doc.pdf",
            archived="false",
            review_interval="730 00:00:00.000000",
            approved="no",
            # unapproved version can't be current
            make_current="yes",
            revision=1,
        ).as_dict()]
        excel_upload = SimpleUploadedFile("upload.xlsx", create_excel_upload_bytes(docs), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response = self.client.post(self.document_metadata_url, data={'data': excel_upload, 'institution': self.institution.pk}, format='multipart')
        self.assertEqual(response.status_code, HTTP_201_CREATED, msg=response.json())
        url = reverse_lazy('api-v2:documentmetadata-upload', kwargs={'pk': response.json()['pk']})
        response = self.client.post(url, data={'file': SimpleUploadedFile("doc.pdf", b"test", content_type="application/pdf")}, format='multipart')
        self.assertEqual(response.status_code, HTTP_400_BAD_REQUEST)
        if IS_ENGLISH_LOCALE:
            self.assertEqual(response.json()['version'], "the excel metadata specifies that this version should be the current version, but it's not approved.")
        self.assertFalse(Document.objects.exists())
