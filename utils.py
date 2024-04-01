from django.db.models import Q

from megdocs.constants import REVIEWER_PERMISSION
from megdocs.models import Document
from megforms.models import AuditorQueryset


def get_document_reviewer_choices(document: Document, auditors: AuditorQueryset) -> AuditorQueryset:
    """
    Filters auditor queryset down to a set of users who can be made a reviewer for given document.
    Auditors are filtered by following:
    * has the document reviewer permission
    * or is the document owner.

    IMPORTANT: This function does not check if user has access to the document

    :param document: the document
    :param auditors: pre-ringfenced set of auditors who have access to this document
    :returns: filtered list of auditors
    """
    with_perm: AuditorQueryset = auditors.with_permission(REVIEWER_PERMISSION)
    return auditors.filter(Q(pk=document.owner_id) | Q(pk__in=with_perm.values('pk'))).annotate_display_name()
