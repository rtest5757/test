from typing import Optional

from django.conf import settings
from django.urls import reverse
from django.utils.translation import gettext

from emails.utils import send_mail_template
from meg_forms import app
from megdocs.models import Version, Document
from megforms.models import Auditor
from megforms.utils import make_absolute_url


@app.task(**settings.CELERY_TASK_DEFAULTS)
def parse_document_content(version_id: int):
    version: Version = Version.objects.get(pk=version_id)
    version.populate_content()


@app.task(**settings.CELERY_TASK_DEFAULTS)
def send_review_notifications():
    documents = Document.objects.published().due_review().select_related('owner__user', 'institution', 'current_version__reviewer__user').exclude(owner__user__email='')
    document: Document
    for document in documents.iterator():
        owner: Auditor = document.owner
        reviewer: Optional[Auditor] = document.current_version.reviewer if document.current_version else None
        new_version_url = reverse('docs:manage:version-create', kwargs={
            'pk': document.pk,
            'institution_slug': document.institution.slug,
        })
        send_mail_template(
            gettext('Document due for review'),
            'document_review_reminder',
            settings.DEFAULT_FROM_EMAIL,
            addr_to=[auditor.user.email for auditor in (owner, reviewer) if auditor and auditor.user.email],
            locale=owner.get_language(),
            context={
                'document': document,
                'institution': document.institution,
                'owner': owner,
                'new_version_url': make_absolute_url(new_version_url),
                'document_url': make_absolute_url(reverse('docs:manage:doc-detail', kwargs={
                    'pk': document.pk,
                    'institution_slug': document.institution.slug,
                })),
            }
        )

    upcoming_documents = Document.objects.published().upcoming_due_review().select_related(
        'owner__user', 'institution', 'current_version__reviewer__user'
    ).exclude(owner__user__email='', current_version__reviewer__user__email='')

    document: Document
    for document in upcoming_documents.iterator():
        owner: Auditor = document.owner
        reviewer: Optional[Auditor] = document.current_version.reviewer if document.current_version else None
        new_version_url = reverse('docs:manage:version-create', kwargs={
            'pk': document.pk,
            'institution_slug': document.institution.slug,
        })

        for auditor in (owner, reviewer):
            if not auditor or not auditor.user.email:
                continue

            send_mail_template(
                gettext('Document review upcoming in 30 days'),
                'document_review_upcoming_reminder',
                settings.DEFAULT_FROM_EMAIL,
                addr_to=[auditor.user.email],
                locale=owner.get_language(),
                context={
                    'document': document,
                    'review_date': document.review_date,
                    'institution': document.institution,
                    'auditor': auditor,
                    'new_version_url': make_absolute_url(new_version_url),
                    'document_url': make_absolute_url(reverse('docs:manage:doc-detail', kwargs={
                        'pk': document.pk,
                        'institution_slug': document.institution.slug,
                    })),
                }
            )


@app.task(**settings.CELERY_TASK_DEFAULTS)
def share_document(recipient_id: int, sharer_name: str, document_id: int) -> None:
    """
    Emails a user to notify them that another user has shared a document with them.

    :param recipient_id: The recipient auditor's id.
    :param sharer_name: Name of the user who shared the document.
    :param document_id: The document's id.
    """
    auditor: Auditor = Auditor.objects.published().select_related('user').active_users().with_email_address().get(id=recipient_id)
    document = Document.objects.published().prefetch_related('checkboxes').for_user(auditor.user).get(id=document_id)
    send_mail_template(
        gettext('A document has been shared with you'),
        'document_shared_email',
        settings.DEFAULT_FROM_EMAIL,
        addr_to=auditor.user.email,
        locale=auditor.get_language(),
        context={
            'shared_by': sharer_name,
            'user': auditor,
            'document': document,
            'requires_ack': document.checkboxes.exists(),
            'document_url': make_absolute_url(document.get_absolute_url()),
        }
    )


if not settings.ASYNC_TASKS:
    parse_document_content.delay = parse_document_content
