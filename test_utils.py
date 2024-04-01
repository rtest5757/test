import io

import pandas as pd

from megdocs.constants import DOCUMENT_METADATA_IMPORT_COLUMNS, REVIEWER_PERMISSION
from megdocs.models import Document, Version
from megforms.models import Auditor
from megforms.test_utils import AuditorInstitutionTestMixin
from model_bakery import baker


def create_excel_upload_bytes(rows: list[dict]) -> bytes:
    """
    Given a list of dicts an excel file is created and converted into bytes
    which can be used for testing excel file uploads.
    """
    docs = [
        # empty header rows
        DocumentMetadataRow().as_dict(),
        DocumentMetadataRow().as_dict(),
        DocumentMetadataRow().as_dict(),
        *rows
    ]
    df = pd.DataFrame(docs)
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
        df.to_excel(writer, columns=DOCUMENT_METADATA_IMPORT_COLUMNS, header=DOCUMENT_METADATA_IMPORT_COLUMNS, index=False)
    buffer.seek(0)
    return buffer.read()


class DocumentTestMixin(AuditorInstitutionTestMixin):
    document_name = 'Test Document'
    statuses = ('new', 'ready', 'archived')

    document: Document
    document_version: Version

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.document = baker.make(Document, name=cls.document_name, institution=cls.institution, owner=cls.auditor)
        cls.document_version = baker.make(Version, document=cls.document)
        cls.document.current_version = cls.document_version
        cls.document.save(update_fields=['current_version'])
        cls.contributor: Auditor = Auditor.objects.create_auditor(
            "contributor",
            "password",
            institution=cls.institution,
            permissions=['megdocs.view_version', 'megdocs.add_version', 'megdocs.change_version', REVIEWER_PERMISSION],
            user_kwargs={
                'first_name': 'Contrib',
                'last_name': 'utor',
                'email': "contrib@test.com",
            },
            level=cls.auditor_level,
        )


class DocumentMetadataRow:
    """
    Helper class for creating rows in excel file used to upload document metadata.
    """
    def __init__(self, *args, **kwargs):
        for col in DOCUMENT_METADATA_IMPORT_COLUMNS:
            setattr(self, col, kwargs.get(col))

    def as_dict(self):
        return {col: getattr(self, col) for col in DOCUMENT_METADATA_IMPORT_COLUMNS}
