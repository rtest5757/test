from django.test import TestCase
from model_bakery import baker

from megdocs.models import Document, Version
from megdocs.scripts import create_documents
from megforms.models import Institution, Auditor
from megforms.model_generators import LOREM_IPSUM


class LoadDataTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        institution = baker.make(Institution, name='Test Institution')
        baker.make(Auditor, institution=institution, user__username='senior')
        baker.make(Auditor, institution=institution, user__username='junior')

    def test_run(self):
        self.assertFalse(Document.objects.count())
        self.assertFalse(Version.objects.count())

        create_documents.run()
        self.assertTrue(Document.objects.count())
        self.assertTrue(Version.objects.count())

    def test_get_tags(self):
        with self.subTest('space'):
            self.assertEqual(
                set(create_documents.get_tags("tests words")),
                {'tests', 'words'},
            )
        with self.subTest('new line'):
            self.assertEqual(
                set(create_documents.get_tags("""tests
                    words""")),
                {'tests', 'words'},
            )
        with self.subTest('lorem ipsum'):
            words = create_documents.get_tags(LOREM_IPSUM, 5)
            self.assertEqual(set(words), {'nulla', 'donec', 'consectetur', 'scelerisque', 'pellentesque'})
