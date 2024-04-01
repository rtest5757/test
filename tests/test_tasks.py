from django.core import mail
from django.core.mail import EmailMultiAlternatives
from django.test import TestCase
from django.utils import timezone
from django.utils.translation import gettext
from model_bakery import baker

from approvals.models import VersionApprovalConfig
from megdocs import tasks
from megdocs.constants import REVIEW_FREQUENCY_ANNUAL
from megdocs.models import Document, Version, DocumentCheckbox
from megforms.models import Institution, Auditor
from megforms.test_utils import IS_ENGLISH_LOCALE
from megforms.utils import get_permission_by_name


class TasksTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.institution: Institution = baker.make(Institution, name='Test Institution')
        cls.auditor: Auditor = baker.make(Auditor, institution=cls.institution, user__username='owner', user__email='test@megit.com')

    def test_send_review_notifications(self):
        # A document that's due to review
        due_document: Document = baker.make(Document, name='Test Document', institution=self.institution, owner=self.auditor)
        due_version: Version = baker.make(Version, document=due_document, creation_date=timezone.now() - REVIEW_FREQUENCY_ANNUAL, reviewer=self.auditor)
        VersionApprovalConfig(due_version).approve(self.auditor, True)
        due_document = Document.objects.get(pk=due_document.pk)

        # A fresh document
        document: Document = baker.make(Document, name='Second Document', institution=self.institution, owner=self.auditor)
        version: Version = baker.make(Version, document=document, reviewer=self.auditor)
        VersionApprovalConfig(version).approve(self.auditor, True)

        tasks.send_review_notifications()

        with self.subTest('model check'):
            self.assertEqual(due_document.review_date, timezone.now().date())
            self.assertIn(due_document, Document.objects.due_review())

        self.assertEqual(len(mail.outbox), 1)
        email: EmailMultiAlternatives
        email, = mail.outbox
        with self.subTest('email meta'):
            self.assertEqual(email.to, ['test@megit.com'])
            self.assertEqual(email.from_email, 'MEG <info@megit.com>')
            self.assertEqual(email.subject, gettext('Document due for review'))
        with self.subTest('html email'):
            html = email.alternatives[0][0]
            if IS_ENGLISH_LOCALE:
                self.assertIn('Dear owner,', html)
                self.assertIn('This is to remind you that Test Document is due for review as of today. A new version of the document can be uploaded by following the link below:', html)
                self.assertIn('Create new version', html)
            self.assertIn('https://example.com/docs/', html)
        with self.subTest('txt email'):
            txt = email.body
            if IS_ENGLISH_LOCALE:
                self.assertIn('Dear owner,', txt)
                self.assertIn('This is to remind you that Test Document is due for review as of today. A new version of the document can be uploaded by following the link below:', txt)
            self.assertIn('https://example.com/docs/', txt)

    def test_doc_shared_email_task(self):
        view_perm = get_permission_by_name('megdocs.view_document')
        auditor_one: Auditor = baker.make(Auditor, institution=self.institution, user__email='first@example.co', user__username='first', user__user_permissions=[view_perm])
        doc: Document = baker.make(Document, name='Test Document', institution=self.institution, owner=self.auditor)
        version: Version = baker.make(Version, document=doc, reviewer=self.auditor)
        VersionApprovalConfig(version).approve(self.auditor, True)

        with self.subTest('document has no checkbox to ack'):
            tasks.share_document(auditor_one.pk, 'Sender', doc.id)
            self.assertEqual(len(mail.outbox), 1)
            email: EmailMultiAlternatives
            first = mail.outbox[0]

            self.assertEqual(first.to, ['first@example.co'])
            self.assertEqual(first.from_email, 'MEG <info@megit.com>')
            if IS_ENGLISH_LOCALE:
                self.assertEqual(first.subject, 'A document has been shared with you')

            html = first.alternatives[0][0]
            if IS_ENGLISH_LOCALE:
                self.assertIn('Dear first,', html)
                self.assertIn('has shared a new document with you titled', html)
                self.assertNotIn('you will be required to acknowledge that you have read', html)

            txt = first.body
            if IS_ENGLISH_LOCALE:
                self.assertIn('Dear first,', txt)
                self.assertIn('has shared a new document with you titled', txt)
                self.assertNotIn('you will be required to acknowledge that you have read', txt)

        with self.subTest('document has checkbox to acknowledge'):
            baker.make(DocumentCheckbox, label='This needs acknowledgment', document=doc)
            tasks.share_document(auditor_one.pk, 'Sender', doc.id)
            self.assertEqual(len(mail.outbox), 2)
            email: EmailMultiAlternatives
            sharing = mail.outbox[1]

            self.assertEqual(sharing.to, ['first@example.co'])
            self.assertEqual(sharing.from_email, 'MEG <info@megit.com>')
            if IS_ENGLISH_LOCALE:
                self.assertEqual(sharing.subject, 'A document has been shared with you')

            html = sharing.alternatives[0][0]
            if IS_ENGLISH_LOCALE:
                self.assertIn('Dear first,', html)
                self.assertIn('has shared a new document with you titled', html)
                self.assertIn('you will be required to acknowledge that you have read', html)

            txt = sharing.body
            if IS_ENGLISH_LOCALE:
                self.assertIn('Dear first,', txt)
                self.assertIn('has shared a new document with you titled', txt)
                self.assertIn('you will be required to acknowledge that you have read', txt)
