import typing
from typing import Iterable

from django.db.models import Prefetch, QuerySet
from django.template.defaultfilters import register
from django.template.defaulttags import CsrfTokenNode
from django.utils.html import format_html
from django.utils.translation import gettext as _
from megdocs.models import (
    Document, Bookmark, Version, DocumentCheckbox, DocumentCheckboxState
)
from megforms.constants import ICON_TYPE_STAR, ICON_TYPE_STAR_EMPTY
from megforms.templatetags.megforms_extras import icon


@register.simple_tag(takes_context=True)
def bookmark_button(context: dict, document: Document, btn_classes='btn btn-default', label=''):
    """ Renders simple bookmark form with button. Requires that view class implements BookmarkViewMixin """
    if 'bookmarked_document_ids' not in context:
        return ''
    document_ids = context['bookmarked_document_ids']
    if document.pk in document_ids:
        action = 'remove_bookmark'
        icon_type = ICON_TYPE_STAR
        title = _("Remove bookmark from this document")
    else:
        action = 'add_bookmark'
        icon_type = ICON_TYPE_STAR_EMPTY
        title = _("Bookmark this document")

    csrf = CsrfTokenNode()
    return format_html("""<form action="" method="post">
        {csrf_token}
        <button class="{btn_classes} btn-bookmark" name="{action}" value="{document_id}" title="{title}" data-toggle="tooltip" data-placement="bottom" >{icon} {label}</button>
</form>""", csrf_token=csrf.render(context), document_id=document.pk, btn_classes=btn_classes, label=label, title=title, action=action, icon=icon(icon_type=icon_type))


@register.simple_tag(takes_context=True)
def bookmarked(context: dict, document: Document) -> bool:
    return Bookmark.objects.filter(user=context['user'], document=document, publish=True).exists()


@register.inclusion_tag('documents/document_checked_users.html')
def render_document_checked_users(document_version: typing.Optional[Version]) -> dict[str, typing.Any]:
    """ Renders table of users who ticked checkboxes for the given document version """
    if document_version:
        prefetched_states: QuerySet = DocumentCheckboxState.objects.filter(version=document_version).select_related('user__user')
        checkboxes: Iterable[DocumentCheckbox] = DocumentCheckbox.objects.filter(document_id=document_version.document_id).prefetch_related(
            Prefetch('states', prefetched_states),
        ).published().order_by('order', 'pk')
    else:
        checkboxes = DocumentCheckbox.objects.none()

    return {
        'checkboxes': checkboxes,
    }
