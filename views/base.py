from typing import Sequence, Callable, Set, List, Optional, Union

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db import transaction
from django.db.models import Q, Exists, OuterRef
from django.http import HttpRequest
from django.shortcuts import redirect, get_object_or_404
from django.urls import reverse
from django.utils.functional import cached_property
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _, gettext
from django.views.generic import ListView
from emails.constants import (
    EMAIL_TYPE_DOCUMENT_REVIEWER_ASSIGNMENT, EMAIL_TYPE_DOCUMENT_OWNER_ASSIGNMENT,
    EMAIL_TYPE_VERSION_RE_UPLOAD, EMAIL_TYPE_VERSION_APPROVED, EMAIL_TYPE_VERSION_DECLINED
)
from emails.models import EmailContext
from emails.utils import send_mail_template
from megdocs.constants import PAGE_SIZE, MANAGE_PERMS
from megdocs.forms import FolderPermissionRuleSearchForm, DocumentFilterForm
from megdocs.models import (
    Document, DocumentQuerySet, DocumentRelationQuerySet, Bookmark, Folder, VersionQuerySet, Version,
    FolderPermissionRuleQueryset, DocumentLink, VersionApproval, DocumentCheckbox, DocumentCheckboxState,
    FolderQuerySet
)
from megdocs.permissions import FolderPermViewFolderMixin
from megforms.constants import ICON_TYPE_CLOUD_UPLOAD, ICON_TYPE_PLUS, ICON_TYPE_FULLSCREEN, ICON_TYPE_BOOK, \
    ICON_TYPE_STATS, ICON_TYPE_FILE, ICON_TYPE_NEW_WINDOW
from megforms.models import Institution, Auditor, AuditForm, AuditorQueryset
from megforms.templatetags.megforms_extras import icon
from megforms.toolbar import BaseToolbarItem, LinkToolbarItem, DropdownToolbarItem
from megforms.utils import make_absolute_url
from megforms.views.auth import LoginSecurityMixin
from megforms.views.base import AuditorInstitutionMixin, ToolbarMixin, NavbarBranding
from megforms.views.dashboard import NavbarTabMixin
from rest_framework.reverse import reverse_lazy
from taggit.models import Tag

from utils.filter_form_mixin import BaseFilterFormMixin


class MegDocsBaseMixin(NavbarBranding, LoginSecurityMixin, NavbarTabMixin):
    """Mixin class used in every megdocs view"""
    navbar_color = settings.NAV_COLOR_DOCS
    request: HttpRequest

    @cached_property
    def manage(self) -> bool:
        """
        Determines if the user is using MEG Docs in "manage" mode.
        If activated, the user will be able to see extra metadata in the document list view
        and will see UI elements for "managing" documents (review versions, create folders, upload documents etc).
        """
        return self.request.user.has_perms(MANAGE_PERMS)

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            manage=self.manage,
            **kwargs
        )


class DocumentFilterFormMixin(BaseFilterFormMixin):
    filter_form_class = DocumentFilterForm

    def filter_objects(self, qs: DocumentQuerySet) -> DocumentQuerySet:
        """ Applies filtering selected by the user to the queryset """
        return self.filter_form.filter(qs)

    @property
    def bookmarked_documents(self) -> DocumentQuerySet:
        qs: DocumentQuerySet = super().bookmarked_documents
        return self.filter_objects(qs)


class DocumentListMixin(AuditorInstitutionMixin, PermissionRequiredMixin):
    """Mixin for list document view"""
    queryset = Document.objects.published()
    request: HttpRequest

    def get_queryset(self) -> DocumentQuerySet:
        queryset = super().get_queryset().filter(institution__in=self.auditor.institutions)
        if not self.all_documents:
            return queryset
        return queryset.filter(Q(folder__in=self.auditor.allowed_folders(permissions=["view_document"], institution=self.institution)) | Q(folder=None))

    def allowed_doc_count(self):
        qs = super().get_queryset().filter(institution=self.institution)
        qs = qs.published().filter(Q(folder__in=self.auditor.allowed_folders(permissions=["view_document"], institution=self.institution)) | Q(folder=None), Q(archived=False))
        return qs.count()

    def get(self, request, *args, **kwargs):
        if self.request.user.is_authenticated:
            if not self.institution.megdocs_enabled:
                return redirect('docs:doc-landing', self.institution.slug)
        return super().get(request, *args, **kwargs)


class DocumentLinkButton(BaseToolbarItem):
    """
    Displays a link to an object which is related to the current document.
    """
    __slots__ = 'url',

    def __init__(self, linked_object: Union[DocumentLink, AuditForm, Document], **kwargs):
        if isinstance(linked_object, AuditForm):
            label = linked_object.name
            url = None
            if linked_object in kwargs.pop('allowed_forms'):
                url = reverse('dashboard_reports_form', kwargs={'current_form_id': linked_object.pk, 'institution_slug': linked_object.institution.slug})
            icon = ICON_TYPE_STATS
        elif isinstance(linked_object, Document):
            label = linked_object.name
            url = None
            url_name: str = "manage" if kwargs.pop("manage") else "view"
            if linked_object in kwargs.pop('allowed_documents'):
                url = reverse(f'docs:{url_name}:doc-detail', kwargs={
                    'pk': linked_object.pk,
                    'institution_slug': linked_object.institution.slug,
                })
            icon = ICON_TYPE_FILE
        else:
            label, url, icon = linked_object.name, linked_object.url, ICON_TYPE_NEW_WINDOW
        super(DocumentLinkButton, self).__init__(label=label, url=url, icon=icon, **kwargs)

    @property
    def url_target(self):
        return '_blank' if self.url.startswith('https://') else ''

    def render(self):
        if self.url:
            return format_html(
                """
                <div class="link-row">
                    <a href="{url}" target="{target}">{icon}{label}</a>
                </div>
                """,
                label=self.label,
                url=self.url,
                target=self.url_target,
                icon=icon(self.icon, extra_class="mr10"),
            )
        return format_html(
            '<div class="link-row">{icon}{label}</div>',
            label=self.label,
            icon=icon(self.icon, extra_class="mr10"),
        )


class DocumentViewMixin(MegDocsBaseMixin, AuditorInstitutionMixin, FolderPermViewFolderMixin):
    """Mixin for detail document view"""
    queryset = Document.objects.published()
    request: HttpRequest
    document: Document

    def get_queryset(self) -> DocumentQuerySet:
        return super().get_queryset().filter(institution=self.institution)

    def get(self, request, *args, **kwargs):
        if self.request.user.is_authenticated:
            if not self.institution.megdocs_enabled:
                return redirect('docs:doc-landing', self.institution.slug)
        return super().get(request, *args, **kwargs)

    @cached_property
    def related_objects(self) -> list[tuple[str, list[DocumentLinkButton], str]]:
        linked_objects = []
        if self.request.user.has_perm("megdocs.view_documentlink"):
            document_links = [DocumentLinkButton(link) for link in self.document.links.all().published()]
            if document_links:
                linked_objects.append((_('Links'), document_links, _('Web links that are relevant to this document.')))
        if self.document.forms.exists():
            allowed_forms = self.auditor.allowed_forms
            form_links = [DocumentLinkButton(form, allowed_forms=allowed_forms) for form in self.document.forms.all()]
            if form_links:
                linked_objects.append((_('Forms'), form_links, _('Forms on MEG that are relevant to this document.')))
        documents = Document.objects.published().for_institution(self.institution)
        if self.document.documents.exists():
            document_links = [DocumentLinkButton(document, allowed_documents=documents.for_user(self.request.user), manage=getattr(self, 'manage', False)) for document in self.document.documents.all().published()]
            if document_links:
                linked_objects.append((_('Documents - Linked to'), document_links, _('These documents may be referenced in or follow up reading for the current document. These documents may also be printable material for the current document.')))
        implicit_document_links = documents.filter(documents__in=[self.document]).published()
        if implicit_document_links.exists():
            document_links = [DocumentLinkButton(document, allowed_documents=documents.for_user(self.request.user), manage=getattr(self, 'manage', False)) for document in implicit_document_links]
            if document_links:
                linked_objects.append((_('Documents - Linked from'), document_links, _('These documents may contain references to or be pre-requisite reading to the current document. The current document may also be printable material for these documents.')))
        return linked_objects

    def get_context_data(self, **kwargs):
        kwargs.update(related_objects=self.related_objects)
        return super().get_context_data(**kwargs)


class FolderPermissionRuleMixin(AuditorInstitutionMixin, PermissionRequiredMixin):
    def get(self, request, *args, **kwargs):
        if self.request.user.is_authenticated:
            if not self.institution.megdocs_enabled:
                return redirect('docs:doc-landing', self.institution.slug)
        return super().get(request, *args, **kwargs)


class FolderPermissionRuleSearchMixin:

    @cached_property
    def folder_permission_rule_search_form(self) -> FolderPermissionRuleSearchForm:
        return FolderPermissionRuleSearchForm(data=self.request.GET or None, institution=self.institution)

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            folder_permission_rule_search_form=self.folder_permission_rule_search_form,
            **kwargs,
        )

    def get_queryset(self) -> FolderPermissionRuleQueryset:
        qs = super().get_queryset()
        if self.folder_permission_rule_search_form.is_valid():
            qs = self.folder_permission_rule_search_form.search(qs)
        return qs


class BaseDocumentListView(MegDocsBaseMixin, ListView):
    queryset = Document.objects.published().select_related('institution')
    paginate_by = PAGE_SIZE

    @cached_property
    def tags(self) -> Sequence[Tag]:
        slugs = self.request.GET.getlist('tag', default=())
        if not slugs:
            return Tag.objects.none()
        return Tag.objects.filter(slug__in=slugs)

    def get_queryset(self) -> DocumentQuerySet:
        qs = super().get_queryset().prefetch_related('tags').annotate(
            has_checkbox=Exists(DocumentCheckbox.objects.published().filter(document_id=OuterRef('pk'))),
            is_acknowledged=Exists(DocumentCheckboxState.objects.published().filter(version_id=OuterRef('current_version'), user=self.request.user.auditor)),
        )
        if self.tags:
            qs = qs.filter(tags__in=self.tags).distinct()
        return qs

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            tags=self.tags,
            **kwargs
        )


class BookmarkViewMixin:
    """
    Mixin that provides bookmarking capabilities to a view:
    - getting a list of bookmarked documents
    - bookmarking a document
    This mixin must be used in a CBV whose model is Document
    """
    request: HttpRequest
    queryset: DocumentQuerySet
    get_queryset: Callable[[], DocumentQuerySet]
    bookmark_message = _("Bookmarked {document}")
    bookmark_remove_message = _("Removed bookmark for {document}")
    bookmarks_only = False

    @cached_property
    def bookmarks(self) -> DocumentRelationQuerySet:
        return self.request.user.bookmarks.published().filter(document__archived=False)

    @cached_property
    def bookmarked_document_ids(self) -> Set[int]:
        return set(self.bookmarks.values_list('document_id', flat=True))

    @property
    def bookmarked_documents(self) -> DocumentQuerySet:
        return self.bookmarks.documents()

    @transaction.atomic
    def add_bookmark(self, document: Document):
        if document not in self.bookmarked_documents:
            Bookmark.objects.create(user=self.request.user, document=document)
            messages.success(self.request, self.bookmark_message.format(document=document))

    @transaction.atomic
    def remove_bookmark(self, document: Document):
        self.bookmarks.filter(document=document).delete()
        messages.success(self.request, self.bookmark_remove_message.format(document=document))

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            bookmarked_documents=self.bookmarked_documents,
            bookmarked_document_ids=self.bookmarked_document_ids,
            bookmarks=self.bookmarks,
            bookmarks_only=self.bookmarks_only,
            **kwargs
        )

    def post(self, request: HttpRequest, *args, **kwargs):
        add_bookmark = request.POST.get('add_bookmark', None)
        remove_bookmark = request.POST.get('remove_bookmark', None)
        redirect_url = f"{request.path}?{request.GET.urlencode()}"
        try:
            if add_bookmark:
                document = self.get_queryset().get(pk=add_bookmark)
                self.add_bookmark(document)
                return redirect(redirect_url)
            elif remove_bookmark:
                document = self.bookmarked_documents.get(pk=remove_bookmark)
                self.remove_bookmark(document)
                return redirect(redirect_url)
        except Document.DoesNotExist:
            # Ignore user trying to un/bookmark document they cannot access
            return redirect(redirect_url)

        return super().post(request, *args, **kwargs)


class FolderTreeManageMixin:
    institution: Institution
    auditor: Auditor

    @cached_property
    def folder(self) -> Optional[Folder]:
        """ Currently viewed folder (if any) """
        folder_id: Optional[str] = self.kwargs.get('folder')
        if folder_id:
            return get_object_or_404(self.folders, id=folder_id)

    @property
    def folders(self) -> 'FolderQuerySet':
        """ Folders available in current view """
        return Folder.objects.published() & self.auditor.allowed_folders(institution=self.institution)

    @property
    def folder_documents(self) -> Optional['DocumentQuerySet']:
        """ Folder documents available in current view to calculate count """
        return self.get_raw_queryset(False) if hasattr(self, 'get_raw_queryset') else None

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            folder=self.folder,
            folders=self.folders.annotate_documents_count(
                self.folder_documents,
            ),
            filtered_doc_count=self.folder_documents.count() if self.folder_documents is not None else None,
            change_requests_enabled=self.institution.megdocs_change_requests_enabled,
            **kwargs
        )


class MegDocsToolbarMixin(ToolbarMixin):

    def get_upload_url(self):
        return reverse_lazy('docs:manage:doc-bulk-upload', kwargs={
            'institution_slug': self.institution.slug,
        })

    def get_upload_item(self):
        if self.auditor.user.has_perms(['megdocs.add_document', 'megdocs.add_version']):
            return LinkToolbarItem(
                gettext('Upload'),
                self.get_upload_url(),
                ICON_TYPE_CLOUD_UPLOAD,
                help_text=_('Click to upload documents'),
            )

    def get_toolbar_items(self) -> Sequence[BaseToolbarItem]:
        items: List[BaseToolbarItem] = list(super().get_toolbar_items())
        if self.institution.megdocs_change_requests_enabled and self.auditor.can_suggest_new_document:
            items.append(LinkToolbarItem(
                _('Suggest document'),
                reverse_lazy('docs:manage:doc-suggest', kwargs={
                    'institution_slug': self.institution.slug,
                }),
                ICON_TYPE_PLUS,
                help_text=_("Suggest a new document"),
            ))
        if self.auditor.user.has_perms(['megdocs.add_folderpermissionrule']):
            items.append(LinkToolbarItem(
                _('Create Rule'),
                reverse_lazy('docs:manage:folder-permission-rule-create', kwargs={
                    'institution_slug': self.institution.slug,
                }),
                ICON_TYPE_PLUS,
                help_text=_("Create a folder permission access rule"),
            ))
        if self.auditor.user.has_perms(['megdocs.add_document', ]):
            items.append(LinkToolbarItem(
                _('Library View'),
                reverse_lazy('docs:view:doc-list-fullscreen', kwargs={
                    'institution_slug': self.institution.slug,
                }),
                ICON_TYPE_FULLSCREEN,
                help_text=_("Open document list page without nav bar"),
            ))
        return items + [self.get_upload_item(), DropdownToolbarItem(
            _('eGuides'),
            ICON_TYPE_BOOK,
            (
                LinkToolbarItem(
                    _('eGuides'),
                    reverse_lazy('eguides:cms-eguide-list', kwargs={
                        'institution_slug': self.institution.slug
                    }),
                    ICON_TYPE_BOOK,
                ),
                LinkToolbarItem(
                    _('eGuides (legacy)'),
                    'https://eguides.megsupporttools.com/',
                    ICON_TYPE_BOOK,
                ),
            )
        )]


class VersionReviewerNotificationMixin:
    def notify_reviewer(self, request: HttpRequest, version: Version, versions: Optional[VersionQuerySet] = None, document: Optional[Document] = None):
        recipients = version.reviewer,
        if versions:
            # Multi file upload. Email contributors.
            recipients = *recipients, *versions.contributors,
        for recipient in recipients:
            if recipient and recipient.email:
                recipient: Auditor
                context = self.get_email_context(request, version, versions=versions, document=document, contributor=recipient)
                if email_context := EmailContext.objects.published().for_auditor(recipient).filter(institution=recipient.institution, email_type=EMAIL_TYPE_DOCUMENT_REVIEWER_ASSIGNMENT).first():
                    context['email_context'] = email_context.text
                subject = _('You have been assigned to approve uploaded documents')
                if document:
                    subject = ('You have been assigned to approve {}').format(document.name)
                elif versions and recipient != version.reviewer:
                    subject = _('You have been assigned to review uploaded documents')
                send_mail_template(
                    subject=subject,
                    template='version_review_notification_email' if recipient == version.reviewer else 'versions_contributor_notification_email',
                    addr_from=settings.DEFAULT_FROM_EMAIL,
                    addr_to=recipient.user.email,
                    context=context,
                    locale=recipient.get_language(),
                )

    def notify_re_uploaded(self, request: HttpRequest, version: Version):
        context = self.get_email_context(request, version, document=version.document, uploader=request.user.auditor)
        approval: VersionApproval
        for approval in version.versionapproval_set.exclude(reviewer=request.user.auditor).approved():
            if not approval.reviewer.user.email:
                continue
            if email_context := EmailContext.objects.published().for_auditor(approval.reviewer).filter(institution=approval.reviewer.institution, email_type=EMAIL_TYPE_VERSION_RE_UPLOAD).first():
                context['email_context'] = email_context.text
            context['contributor'] = approval.reviewer
            send_mail_template(
                subject=_('Version Re-uploaded: {}').format(version),
                template='version_re_uploaded_email',
                addr_from=settings.DEFAULT_FROM_EMAIL,
                addr_to=approval.reviewer.user.email,
                context=context,
                locale=approval.reviewer.get_language(),
            )

    def get_email_context(self, request: HttpRequest, version: Version, versions: Optional[VersionQuerySet] = None, document: Optional[Document] = None, **kwargs):
        return {
            'reviewer': version.reviewer.user if version.reviewer else None,
            'uploader': version.creator.user,
            'document_name': document.name if document else None,
            'version_urls': self.version_urls(request, version, versions),
            'version': version,
            **kwargs
        }

    def version_urls(self, request: HttpRequest, version: Version, versions: Optional[VersionQuerySet] = None):
        urls = []
        if versions:
            for version in versions:
                url = reverse('docs:manage:version-review', kwargs={'institution_slug': version.document.institution.slug, 'pk': version.pk})
                urls.append(make_absolute_url(url, request))
        else:
            url = reverse('docs:manage:version-review', kwargs={'institution_slug': version.document.institution.slug, 'pk': version.pk})
            urls.append(make_absolute_url(url, request))
        return urls

    def notify_version_approved(self, request: HttpRequest, version: Version, approved_by: AuditorQueryset):
        recipient = version.reviewer
        if recipient and recipient.email:
            recipient: Auditor
            context = self.get_email_context(request, version, approved_by=approved_by)
            if email_context := EmailContext.objects.published().for_auditor(recipient).filter(institution=recipient.institution, email_type=EMAIL_TYPE_VERSION_APPROVED).first():
                context['email_context'] = email_context.text
            send_mail_template(
                subject=_('Version has been approved: {}').format(version),
                template='version_approved_notification_email',
                addr_from=settings.DEFAULT_FROM_EMAIL,
                addr_to=recipient.user.email,
                context=context,
                locale=recipient.get_language(),
            )

    def notify_version_decline(self, request: HttpRequest, version: Version, sent_by: Auditor, reason: str):
        for recipient in [*self.approval_config.auditors, version.creator]:
            if recipient and recipient.email:
                recipient: Auditor
                context = self.get_email_context(request, version, declined_by=sent_by, reason=reason)
                if email_context := EmailContext.objects.published().for_auditor(recipient).filter(
                    institution=recipient.institution, email_type=EMAIL_TYPE_VERSION_DECLINED
                ).first():
                    context['email_context'] = email_context.text
                send_mail_template(
                    subject=_('Version has been declined: {}').format(version),
                    template='version_decline_notification_email',
                    addr_from=settings.DEFAULT_FROM_EMAIL,
                    addr_to=recipient.user.email,
                    context=context,
                    locale=recipient.get_language(),
                )


class DocumentUpdateNotificationMixin:
    request: HttpRequest

    def get_context(self, document: Document, owner: Auditor, editor: Auditor, email_type):
        email_context: Optional[EmailContext] = EmailContext.objects.published().for_auditor(owner)\
            .filter(institution=owner.institution, email_type=email_type).first()
        return {
            'owner': owner.user,
            'editor': editor.user,
            'document': document,
            'document_name': document.name,
            'document_url': make_absolute_url(reverse('docs:manage:doc-detail', kwargs={
                'pk': document.pk,
                'institution_slug': document.institution.slug,
            })),
            'email_context': email_context.text if email_context else None,
        }

    def notify_owner(self, document: Document):
        owner: Auditor = document.owner
        editor: Auditor = self.request.user.auditor
        if owner != editor and owner.email:
            send_mail_template(
                subject=_('You have been assigned as an owner of {}').format(document.name),
                template='document_owner_notification_email',
                addr_from=settings.DEFAULT_FROM_EMAIL,
                addr_to=owner.email,
                context=self.get_context(document, owner, editor, EMAIL_TYPE_DOCUMENT_OWNER_ASSIGNMENT),
                locale=owner.get_language(),
            )
