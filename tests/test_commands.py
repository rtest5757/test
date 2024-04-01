from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from model_bakery import baker

from megforms.models import Institution, Auditor


class CommandTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.institution: Institution = baker.make(Institution, name='Test Institution')
        baker.make(Auditor, institution=cls.institution, user__username='senior')
        baker.make(Auditor, institution=cls.institution, user__username='junior')

    def test_generate_documents(self):
        out = StringIO()
        call_command('generate_docs', self.institution.pk, 5, stdout=out, stderr=out)
        self.assertEqual(self.institution.documents.count(), 5)
