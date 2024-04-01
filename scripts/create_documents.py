import os
from collections import Counter
from functools import lru_cache
from operator import itemgetter
from pathlib import Path
from typing import Collection, Iterable

from django.db import transaction

from django.conf import settings
from megdocs.models import Document, Version, Folder, DocumentCheckbox
from megforms.models import Institution, Auditor

PDF_DIR = os.path.join(settings.BASE_DIR, 'megdocs/scripts/pdf')

MIN_KEYWORD_LEN = 5
# override these keywords weight:
WORD_SCORES = {
    'www.medicaleguides.com': 0,
    'info@medicaleguides.com': 0,
    'audits': 3,
    'street': 0,
    'thomas': 0,
    'depot': 0,
    'click': 0,
    'print': 0,
    'audit': 3,
    'compliance': 3,
    'printing': 2,
    'excel': 2,
    'health-care': 3,
}


@lru_cache()
def get_tags(content: str, num_tags: int = 30) -> Collection[str]:
    """ Create tags from most common words in the document """
    counter = Counter()
    all_words = (word.strip(',. \n-_{}()[]0123456789\\:/!“”"\'’').lower() for word in content.split())
    for word in all_words:
        if MIN_KEYWORD_LEN <= len(word) < 100:
            counter[word] += WORD_SCORES.get(word, 1)
    words = sorted(counter.items(), key=itemgetter(1), reverse=True)
    return tuple(word for word, count in words[:num_tags])


def create_documents(institution: Institution, file_paths: Iterable[str]):
    auditor: Auditor = institution.auditor_set.get(user__username='senior')
    for pdf in file_paths:
        file_name: str = Path(pdf).name
        document: Document = Document.objects.create(
            name=Path(pdf).stem[:70],
            institution=institution,
            owner=auditor,
        )
        version: Version = Version(
            document=document,
            creator=auditor,
            reviewer=auditor,
            approved=True
        )
        with open(pdf, 'rb') as fp:
            version.file.save(file_name, fp)
        version.populate_content()
        tags: Collection[str] = get_tags(version.content)
        document.tags.set(tags)
        document.current_version = version
        document.save()


def create_folders(institution: Institution):
    auditor: Auditor = institution.auditor_set.get(user__username='senior')
    folder: Folder = Folder.objects.create(
        name="test folder 1",
        description="test folder description",
        owner=auditor,
        institution=institution,
    )
    sub_folder: Folder = Folder.objects.create(
        name="test sub folder 1",
        description="test sub folder description",
        owner=auditor,
        institution=institution,
        parent=folder
    )
    document = Document.objects.first()
    if document:
        document.folder = sub_folder
        document.save()


def create_checkboxes():
    documents: Iterable[Document] = Document.objects.all()
    DocumentCheckbox.objects.bulk_create(DocumentCheckbox(
        document=document,
        label="I have read, understood and agree to policy and standard operating procedure of this document",
        help_text="Please click to confirm that you have read and understood the SOP",
        required=True,
    ) for document in documents)


@transaction.atomic()
def run():
    institution, created = Institution.objects.get_or_create(name='Test Institution')
    pdfs = (os.path.join(PDF_DIR, f) for f in os.listdir(PDF_DIR))
    create_documents(institution, pdfs)
    create_folders(institution)
    create_checkboxes()
