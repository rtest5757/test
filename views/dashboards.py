import datetime
import functools
import json
import reversion
from pathlib import Path
from typing import Sequence, Optional

from django.contrib import messages
from django.contrib.admin.models import ADDITION
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Prefetch, Q
from django.forms import modelform_factory, modelformset_factory, BaseModelFormSet
from django.http import HttpRequest, HttpResponseRedirect, HttpResponse, Http404
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _, gettext_lazy, gettext
from django.views.generic import CreateView, DetailView, ListView, UpdateView, FormView
from django_htmx.middleware import HtmxDetails
from rest_framework.reverse import reverse_lazy

from action_audit.utils import ActionAuditFormMixin, BaseActionAuditMixin, BaseActionAuditViewMixin
from approvals.models import VersionApprovalConfig, VersionNotApproved
from files.utils import create_model_field_url
from megdocs.constants import (
    DOCUMENT_CHANGE_REQUEST_STATUS_PENDING, DOCUMENT_CHANGE_REQUEST_STATUS_DECLINED,
    DOCUMENT_CHANGE_REQUEST_STATUS_APPROVED, CHANGE_REQUEST_ACTION_TYPE_ARCHIVE
)
from megdocs.forms import (
    DocumentBulkUploadForm, CreateFolderForm, DocumentVersionForm, DocumentEditForm,
    FolderPermissionRuleForm, DocumentLinkForm, DocumentVersionDeclineForm, DocumentVersionReUploadForm,
    ChangeRequestNewVersionForm
)
from megdocs.models import (
    Document, Version, DocumentQuerySet, VersionQuerySet, Folder, FolderPermissionRule,
    FolderPermissionRuleQueryset, FolderQuerySet, DocumentLink, DocumentRelationQuerySet,
    DocumentCheckbox, DocumentChangeRequest, DocumentChangeRequestQuerySet
)
from megdocs.permissions import FolderPermPOSTParentMixin, FolderPermUpdateFolderMixin, FolderPermUpdateDocMixin, \
    FolderPermDocMixin, FolderPermDocVersionMixin, FolderPermViewFolderMixin
from megdocs.tasks import parse_document_content
from megdocs.views.base import DocumentViewMixin, BaseDocumentListView, DocumentListMixin, BookmarkViewMixin, \
    DocumentUpdateNotificationMixin, FolderTreeManageMixin, MegDocsToolbarMixin, VersionReviewerNotificationMixin, \
    MegDocsBaseMixin, FolderPermissionRuleSearchMixin, FolderPermissionRuleMixin, \
    DocumentFilterFormMixin
from megforms.constants import ICON_TYPE_PLUS, ICON_TYPE_DOWNLOAD_ALT
from megforms.models import Auditor
from megforms.toolbar import BaseToolbarItem, LinkToolbarItem
from megforms.utils import get_permission_by_name, auditors_with_perm
from megforms.views.base import AuditorInstitutionMixin, ReversionMixin, ToolbarMixin, MaintenanceModeMixin
from utils.htmx import HTMXUtilsViewMixin, HTMXViewMixin
from utils.unpublish import Unpublisher


class DocumentListView(DocumentFilterFormMixin, BookmarkViewMixin, DocumentListMixin, MegDocsToolbarMixin, FolderTreeManageMixin, FolderPermViewFolderMixin, BaseDocumentListView):
    """
    A list of documents displayed in the dashboard,
    can be reused to show documents requiring review
    """
    template_name = 'dashboard/document_list.html'
    permission_required = 'megdocs.view_document', 'megdocs.view_folder',
    current_tab = 'docs'
    archived = False
    all_documents = False
    full_screen = False

    def get_raw_queryset(self, filter_folder: bool = True):
        qs = super().get_queryset()
        if self.archived:
            qs = qs.archived_documents()
        else:
            qs = qs.live_documents()
        if not self.archived and self.folder and filter_folder:
            qs = qs.filter(folder=self.folder)
        qs = qs.prefetch_related(
            Prefetch('versions', Version.objects.published().order_by('-revision'), to_attr='latest_versions'),
        ).select_related('owner__user', 'current_version')
        if self.full_screen or not self.manage:
            qs = qs.approved()
        return qs

    def get_queryset(self) -> DocumentQuerySet:
        return self.get_raw_queryset()

    def get_upload_url(self) -> str:
        """
        Get the url for the upload button adding the selected folder id to pre-fill
        the folder in the upload document form
        """
        url = super().get_upload_url()
        if folder := self.kwargs.get('folder'):
            url += f"?folder={folder}"
        return url

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            full_screen=self.full_screen,
            doc_count=self.allowed_doc_count(),
            **kwargs,
        )

    def has_permission(self):
        if self.archived and not self.manage:
            return False
        return super().has_permission()


class ReviewVersionListView(MegDocsBaseMixin, AuditorInstitutionMixin, MegDocsToolbarMixin, FolderTreeManageMixin, PermissionRequiredMixin, DocumentFilterFormMixin, ListView):
    queryset = Version.objects.published().select_related('creator__user', 'document', 'reviewer__user')
    ordering = 'created'
    permission_required = 'megdocs.view_version',
    template_name = 'dashboard/version_list.html'
    current_tab = 'docs'
    my_waiting_approval = False

    def get_queryset(self) -> VersionQuerySet:
        published_versions = Document.objects.published().filter(institution=self.institution).due_review(exact=False).values_list('current_version_id', flat=True)
        qs: VersionQuerySet = super().get_queryset().filter(
            # Show versions that are either unapproved or published and require re-review
            Q(approved=False) | Q(pk__in=published_versions),
            document__institution=self.institution,
        )
        qs = qs.for_user(self.request.user)
        if self.my_waiting_approval:
            return qs.waiting_for_user_approval(self.request.user)
        return qs

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            my_waiting_approval=self.my_waiting_approval,
            show_review_tabs=True,
            **kwargs,
        )


class AwaitingPublishVersionListView(MegDocsBaseMixin, AuditorInstitutionMixin, MegDocsToolbarMixin, FolderTreeManageMixin, PermissionRequiredMixin, DocumentFilterFormMixin, ListView):
    queryset = Version.objects.published().select_related('creator__user', 'document', 'reviewer__user')
    ordering = 'created'
    permission_required = 'megdocs.view_version',
    template_name = 'dashboard/version_awaiting_publish_list.html'
    current_tab = 'docs'

    def get_queryset(self) -> VersionQuerySet:
        # Show versions that are approved but not published
        qs: VersionQuerySet = super().get_queryset().pending_publishing().filter(
            document__institution=self.institution,
        )
        return qs.for_user(self.request.user)


class DocumentEditView(DocumentUpdateNotificationMixin, SuccessMessageMixin, DocumentViewMixin, FolderPermUpdateDocMixin, ActionAuditFormMixin, ReversionMixin, ToolbarMixin, VersionReviewerNotificationMixin, UpdateView):
    permission_required = 'megdocs.change_document', 'megdocs.change_folder',
    current_tab = 'docs'
    template_name = 'dashboard/document_edit.html'
    success_message = _('Successfully saved %(name)s')
    reversion_change_comment = 'Updated in MEG Docs'
    audit_change_message = 'Document edited in MEG Docs'
    form_class = DocumentEditForm

    def get_permission_required(self):
        perms = super().get_permission_required()
        if self.deleting:
            perms += 'megdocs.delete_document',
        return perms

    @cached_property
    def versions(self) -> VersionQuerySet:
        """ Versions of current document, from latest to oldest """
        result = self.document.versions.published().order_by('-revision')
        if not self.request.user.has_perm('megdocs.view_version'):
            # If user has no permission to browse versions, show only current version
            result = result.filter(pk=self.document.current_version_id)
        return result

    @cached_property
    def document(self) -> Document:
        return self.get_object()

    @cached_property
    def is_current_version(self) -> bool:
        """ Whether the currently displayed version is the published one """
        return self.version and self.version.pk == self.document.current_version_id

    @property
    def version(self) -> Optional[Version]:
        if 'revision' in self.kwargs:
            return get_object_or_404(self.versions, revision=self.kwargs['revision'])
        return self.document.current_version or self.versions.first()

    def get_success_url(self):
        kwargs = {
            'institution_slug': self.institution.slug,
            'pk': self.document.pk,
        }

        if version := self.version:
            kwargs['revision'] = version.revision
        return reverse('docs:manage:doc-edit', kwargs=kwargs)

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            versions=self.versions,
            version=self.version,
            is_current_version=self.is_current_version,
            checkbox_formset=self.checkbox_formset,
            current_change_request=self.document.current_change_request,
            **kwargs
        )

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update(
            user=self.request.user,
            institution=self.institution,
            versions=self.versions,
        )
        return kwargs

    def get_toolbar_items(self) -> Sequence[BaseToolbarItem]:
        items = super().get_toolbar_items()
        if self.auditor.user.has_perm('megdocs.add_version'):
            if not self.document.has_current_change_request:
                items.append(LinkToolbarItem(
                    _('New Version'),
                    reverse_lazy('docs:manage:version-create', kwargs={
                        'institution_slug': self.institution.slug,
                        'pk': self.document.pk,
                    }),
                    ICON_TYPE_PLUS,
                ))
            version: Version
            if (version := self.version) and version.source:
                items.append(LinkToolbarItem(
                    _('Word version'),
                    create_model_field_url(version, 'source', Path(version.source.name).name),
                    ICON_TYPE_DOWNLOAD_ALT,
                ))
        return items

    @property
    def deleting(self) -> bool:
        return self.request.POST.get('save') == 'remove'

    @transaction.atomic()
    def delete(self, request: HttpRequest):
        Unpublisher(self.document, self.request.user).unpublish_logged(comment='Deleted using MEG Docs')
        messages.success(self.request, _("Successfully deleted {document}").format(document=self.document))
        return redirect(reverse('docs:manage:doc-list', kwargs={
            'institution_slug': self.institution.slug,
        }))

    def post(self, request, *args, **kwargs):
        if self.deleting:
            return self.delete(request)
        return super().post(request, *args, **kwargs)

    @cached_property
    def checkbox_formset(self) -> BaseModelFormSet:
        formset: type[BaseModelFormSet] = modelformset_factory(DocumentCheckbox, fields=('label', 'help_text', 'required'), extra=1, max_num=1)
        return formset(data=self.request.POST or None, prefix='checkbox', queryset=self.document.checkboxes.published(), form_kwargs={
            'instance': DocumentCheckbox(document=self.document),
        })

    @transaction.atomic()
    def form_valid(self, form):
        if not self.checkbox_formset.is_valid():
            return self.form_invalid(form)
        response: HttpResponseRedirect = super().form_valid(form)
        self.checkbox_formset.save()
        reviewer_updated: Optional[int] = form.save_reviewer()
        owner_updated: bool = 'owner' in form.changed_data
        if reviewer_updated or owner_updated:
            updated_document: Document = Document.objects.get(pk=self.document.pk)
            if reviewer_updated and updated_document.current_version:
                self.notify_reviewer(self.request, updated_document.current_version, document=updated_document)
            if owner_updated:
                self.notify_owner(updated_document)
        return response


class DocumentBulkUploadView(MegDocsBaseMixin, MaintenanceModeMixin, AuditorInstitutionMixin, SuccessMessageMixin, PermissionRequiredMixin, ReversionMixin, BaseActionAuditMixin, VersionReviewerNotificationMixin, FormView):
    permission_required = 'megdocs.add_document', 'megdocs.add_version',
    form_class = DocumentBulkUploadForm
    template_name = 'dashboard/document_bulk_upload.html'
    current_tab = 'docs'
    documents: Sequence[Document]

    def get_success_url(self):
        if len(self.documents) == 1 and self.request.user.has_perms(('megdocs.change_document', 'megdocs.change_folder',)):
            return reverse('docs:manage:doc-edit', kwargs={
                'institution_slug': self.institution.slug,
                'pk': self.documents[0].pk,
            })
        return reverse('docs:manage:doc-list', kwargs={
            'institution_slug': self.institution.slug,
        })

    def get_success_message(self, cleaned_data):
        return _('Successfully uploaded documents: {documents}.').format(documents=', '.join((d.name for d in self.documents)))

    def form_valid(self, form: DocumentBulkUploadForm):
        documents: Sequence[Document] = form.create()
        versions = Version.objects.filter(document__in=documents)
        comment = "Uploaded and approved in MEG Docs" if form.cleaned_data["publish"] is True else "Uploaded for review in MEG Docs"
        self._log(self.request, ADDITION, documents, comment=comment)
        self._log(self.request, ADDITION, versions, comment=comment)
        self.notify_reviewer(self.request, versions.first(), versions=versions)
        self.documents = documents
        return super().form_valid(form)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update(
            auditor=self.auditor,
            institution=self.institution,
        )
        return kwargs

    def get_initial(self):
        """
        Add the folder id to the initials of the form to select it when opening the upload document form
        """
        initials = super().get_initial()
        if folder := self.request.GET.get('folder', None):
            initials.update({
                'folder': folder,
            })
        return initials


class VersionRedirectMixin:
    def get_success_url(self):
        if self.request.user.has_perm('megdocs.approve_version'):
            # if user has the right permission, redirect to review screen so they can approve the version right away
            return reverse('docs:manage:version-review', kwargs={
                'institution_slug': self.institution.slug,
                'pk': self.object.pk,
            })
        else:
            return reverse('docs:manage:doc-edit', kwargs={
                'institution_slug': self.institution.slug,
                'pk': self.document.pk,
                'revision': self.revision,
            })

    @cached_property
    def revision(self) -> int:
        return self.document.get_new_revision_number()


class VersionCreateView(VersionRedirectMixin, MaintenanceModeMixin, SuccessMessageMixin, ReversionMixin, FolderPermDocMixin, ActionAuditFormMixin, DocumentViewMixin, VersionReviewerNotificationMixin, CreateView):
    """
    Form allowing the user to create and assign a new version of a document
    Task #24108
    """
    model = Version
    current_tab = 'docs'
    permission_required = 'megdocs.add_version',
    template_name = 'dashboard/version_create.html'
    success_message = gettext_lazy('Successfully uploaded new version of the document')
    form_class = DocumentVersionForm
    # Log entry comment, do not translate:
    audit_create_message = "Submitted new version for review in MEG Docs"
    change_request_checked_out_message = _('Cannot add new version as there is an approved change suggestion for this document')

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        version_kwargs = {}
        if self.document.current_version_id:
            version_kwargs.update(reviewer=self.document.current_version.reviewer)
        kwargs.update(
            institution=self.institution,
            owner=self.document.owner,
            instance=Version(
                document=self.document,
                revision=self.revision,
                creator=self.auditor,
                approved=False,
                **version_kwargs,
            ),
        )
        return kwargs

    @cached_property
    def document(self) -> Document:
        return get_object_or_404(self.get_queryset(), pk=self.kwargs['pk'])

    def form_valid(self, form: DocumentVersionForm):
        if self.document.has_current_change_request:
            messages.error(self.request, self.change_request_checked_out_message)
            return self.form_invalid(form)

        result = super().form_valid(form)
        transaction.on_commit(functools.partial(parse_document_content.delay, form.instance.pk))
        self.notify_reviewer(self.request, form.instance, document=self.document)
        return result

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            document=self.document,
            revision=self.revision,
            **kwargs
        )


class VersionUpdateMixin:
    queryset = Version.objects.published().select_related('document', 'document__current_version').select_related('reviewer__signature')
    current_tab = 'docs'

    @cached_property
    def document(self) -> Document:
        return self.version.document

    @cached_property
    def version(self) -> Version:
        return self.get_object()

    def get_queryset(self) -> VersionQuerySet:
        qs: VersionQuerySet = super().get_queryset().filter(
            document__institution=self.institution,
        )
        return qs.for_user(self.request.user).distinct()

    @cached_property
    def is_lead(self) -> bool:
        return self.document.leads.all().filter(pk=self.auditor.pk).exists()

    @cached_property
    def can_edit(self) -> bool:
        if self.auditor == self.document.owner or self.is_lead:
            return True
        return self.request.user.has_perm('megdocs.change_version') and self.auditor in (self.document.owner, self.version.creator)

    def get_context_data(self, **kwargs):
        return super().get_context_data(
            document=self.document,
            can_edit=self.can_edit,
            **kwargs,
        )


class VersionReviewView(HTMXViewMixin, VersionUpdateMixin, MegDocsBaseMixin, AuditorInstitutionMixin, FolderPermDocVersionMixin, BaseActionAuditViewMixin, ReversionMixin, VersionReviewerNotificationMixin, DetailView):
    """
    View allowing user to review proposed version of a document
    against current version and approve or decline it
    Task #24109
    """
    permission_required = 'megdocs.view_version',
    template_name = 'dashboard/version_review.html'

    def get_context_data(self, **kwargs):
        approved_auditors, not_yet_approved = self.approval_config.approved_by, self.approval_config.not_approved_by
        if approved_by := approved_auditors.as_string():
            approved, required = approved_auditors.count(), not_yet_approved.count()
            approve_label = gettext("Approved by {users} ({approved} of {required} required)").format(
                users=approved_by,
                approved=approved,
                required=required,
            )
        else:
            approve_label = gettext("Mark this version as approved")
        return super().get_context_data(
            can_re_upload=self.can_re_upload,
            can_approve_or_decline=self.can_approve_or_decline,
            can_publish=self.can_publish,
            change_form=self.change_form,
            show_add_comment=self.version.can_comment(self.auditor),
            approve_label=approve_label,
            user_approved=self.auditor in approved_auditors,
            approval_config=self.approval_config,
            allow_mark_reviewed=self.allow_mark_reviewed,
            **kwargs,
        )

    @property
    def approval_config(self) -> VersionApprovalConfig:
        return VersionApprovalConfig(self.version)

    @property
    def can_approve_or_decline(self) -> bool:
        """ Whether current user is assigned to review this version """
        return self.approval_config.can_approve_or_decline(self.auditor) and self.request.user.has_perm('megdocs.approve_version')

    @property
    def can_re_upload(self) -> bool:
        """ Whether current user can re-upload version """
        return self.approval_config.is_declined and self.version.creator == self.request.user.auditor

    @property
    def can_publish(self) -> bool:
        """
        Whether current user can publish this document version.
        It requires that user has the permission but also the version needs to have all the required approvals
        """
        return not self.approval_config.is_declined and self.auditor.pk == self.version.reviewer_id and self.approval_config.is_approved and self.request.user.has_perm('megdocs.change_document')

    @transaction.atomic()
    def revoke_approval(self):
        """ Removes current user's approval an updates version status (resets approved value)"""
        self.approval_config.revoke(self.auditor)
        self.log_change(self.version, field_names=['approved'], comment="Revoked approval")
        messages.info(self.request, gettext("Your approval has been removed"))

    @transaction.atomic()
    def approve(self):
        if not self.can_approve_or_decline:
            raise PermissionDenied
        self.approval_config.approve(self.auditor)
        self.log_change(self.version, field_names=['approved'], comment="Approved in MEG Docs")

    @transaction.atomic()
    def publish(self) -> bool:
        if self.can_publish:
            try:
                self.approval_config.publish()
                self.log_change(self.version.document, field_names=['current_version'], comment=f"Document updated to version {self.version.version}")
                messages.success(self.request, gettext('{version} is approved and published').format(version=self.version))
                return True
            except VersionNotApproved:
                messages.error(self.request, gettext('{version} cannot be published because it does not have all the required approvals').format(version=self.version))
        else:
            messages.error(self.request, gettext('{version} can only be approved by {reviewer}').format(version=self.version, reviewer=self.approval_config.auditors.as_string()))
        return False

    @property
    def deleting(self) -> bool:
        return self.request.POST.get('save') == 'remove'

    @property
    def reviewing(self) -> bool:
        return self.request.POST.get('save') == 'mark-reviewed'

    @cached_property
    def change_form(self):
        VersionForm = modelform_factory(Version, fields=['reviewer', 'summary'])
        form = VersionForm(self.request.POST or None, instance=self.version)

        review_permission = get_permission_by_name('megdocs.approve_version')
        form.fields['reviewer'].queryset &= Auditor.objects.active_users() \
            .for_institution(self.institution) \
            .filter(auditors_with_perm(review_permission, include_global=False) | Q(pk=self.version.document.owner.pk))
        return form

    @transaction.atomic()
    def delete(self, request: HttpRequest):
        Unpublisher(self.version, self.request.user).unpublish_logged(comment='Deleted using MEG Docs')
        Document.objects.filter(current_version=self.version).update(current_version=None)
        messages.success(self.request, _("Successfully deleted {version}").format(version=self.version))
        return redirect(reverse('docs:manage:assigned-list', kwargs={'institution_slug': self.institution.slug}))

    def get_permission_required(self):
        perms = super().get_permission_required()
        if self.reviewing:
            perms += 'megdocs.change_version',
        return perms

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        self.log_view(self.version, comment='Review screen')
        return response

    def handle_decline_htmx(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        decline_form: DocumentVersionDeclineForm = DocumentVersionDeclineForm(data=self.request.POST or None)
        status_message: Optional[dict[str, str]] = None
        if self.document.current_version and self.document.current_version > self.version:
            status_message = {
                'message': _("A newer version is already published"), 'status': 'error',
            }
        elif not self.can_approve_or_decline:
            status_message = {
                'message': _("Permission denied"), 'status': 'error',
            }
        elif request.method == 'POST':
            if decline_form.is_valid():
                status_message = {
                    'message': _("Declined version and sent notification to other approvers."), 'status': 'success',
                }

                reason = decline_form.cleaned_data['reason']
                self.approval_config.decline(self.auditor, reason)
                self.notify_version_decline(request, self.version, self.auditor, reason)

        return self.render_htmx_response('includes/version_decline.html', include_base_context=False, extra_context={
            'form': decline_form, 'status_message': status_message
        })

    @transaction.atomic()
    def handle_re_upload_htmx(self, request, *args, **kwargs):
        status_message: Optional[dict[str, str]] = None
        re_upload_form: DocumentVersionReUploadForm = DocumentVersionReUploadForm(
            instance=self.version,
            data=self.request.POST or None,
            files=self.request.FILES or None,
            initial={
                'file': None,
            }
        )

        if not self.approval_config.is_declined or not self.can_re_upload:
            status_message = {
                'message': _('You can only re-upload if this version was declined.'), 'status': 'error',
            }

        elif request.method == 'POST':
            if re_upload_form.is_valid():
                re_upload_form.save()
                self.notify_re_uploaded(self.request, self.version)
                self.approval_config.re_upload_reset(self.request)
                status_message = {
                    'message': _('Uploaded new file.'), 'status': 'success',
                }

        return self.render_htmx_response('includes/version_re_upload.html', include_base_context=False, extra_context={
            'declined_by': self.approval_config.declined_by,
            'form': re_upload_form,
            'status_message': status_message
        })

    def handle_htmx(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        """ HTMX for popup """
        action = request.GET.get('_action', '') or request.POST.get('_action', '')

        if action == 'decline':
            return self.handle_decline_htmx(request, *args, **kwargs)

        elif action == 're-upload':
            return self.handle_re_upload_htmx(request, *args, **kwargs)

        raise Http404()

    def post(self, request: HttpRequest, *args, **kwargs):
        redirect_url: str = request.path
        if request.POST.get('approve', '') == 'false':
            self.revoke_approval()
        elif request.POST.get('approve', '') == 'true':
            if self.document.current_version and self.document.current_version > self.version:
                messages.error(request, gettext('A newer version is already published'))
            else:
                self.approve()
                approved_auditors, not_yet_approved = self.approval_config.approved_by, self.approval_config.not_approved_by
                if not not_yet_approved.exists():
                    self.notify_version_approved(request, self.version, approved_auditors)
                messages.success(request, gettext('Your approval has been added'))
        elif request.POST.get('save') == 'mark-reviewed':
            if self.allow_mark_reviewed:
                self.version.creation_date = datetime.datetime.today()
                self.version.save()
                messages.success(request, gettext('{} reviewed.').format(self.version))
            else:
                messages.error(request, gettext('{} is not due for review').format(self.version))
        elif request.POST.get('publish', '') == 'true':
            if self.publish():
                return redirect(reverse('docs:manage:doc-detail', kwargs={
                    'pk': self.document.pk,
                    'institution_slug': self.document.institution.slug,
                }))
        else:
            if not self.can_edit:
                raise PermissionDenied
            if not self.change_form.is_valid():
                return self.get(request, *args, **kwargs)
            with transaction.atomic():
                self.change_form.save()
                version: Version = Version.objects.get(pk=self.version.pk)
                self.notify_reviewer(self.request, version, document=version.document)
                self.log_change(self.version, self.change_form.changed_data, comment="Edited via review screen")
            messages.success(self.request, gettext('Successfully updated {version}').format(version=self.version))

        return redirect(redirect_url)

    @property
    def allow_mark_reviewed(self) -> bool:
        return self.auditor.user.has_perm('megdocs.change_version') and self.document.is_due_review and self.version.pk == self.document.current_version_id


class PendingRequestsListView(HTMXViewMixin, MegDocsBaseMixin, AuditorInstitutionMixin, MegDocsToolbarMixin, FolderTreeManageMixin, PermissionRequiredMixin, DocumentFilterFormMixin, ListView):
    queryset = DocumentChangeRequest.objects.published().select_related('document', 'auditor')
    ordering = 'created'
    template_name = 'dashboard/change_request_list.html'
    current_tab = 'docs'

    def has_permission(self) -> bool:
        return self.request.user.is_authenticated and self.request.user.auditor.can_view_pending_requests

    def get_queryset(self) -> DocumentChangeRequestQuerySet:
        # Show versions that are approved but not published
        qs: DocumentChangeRequestQuerySet = super().get_queryset().for_institution(self.institution)
        return qs.for_user(self.request.user)

    @transaction.atomic()
    def handle_htmx(self, request: HttpRequest, htmx: HtmxDetails, *args, **kwargs) -> HttpResponse:
        change_request_id = request.GET.get('change_request_id') or request.POST.get('change_request_id')

        if not change_request_id:
            raise Http404()

        change_request: DocumentChangeRequest = get_object_or_404(self.get_queryset(), pk=change_request_id)
        status_message: Optional[dict[str, str]] = None
        form = ChangeRequestNewVersionForm(
            change_request=change_request,
            auditor=self.auditor,
            data=self.request.POST or None,
            files=self.request.FILES or None
        )

        if request.method == 'POST':
            if change_request.status == DOCUMENT_CHANGE_REQUEST_STATUS_PENDING:
                if not change_request.can_approve_or_decline(self.auditor):
                    raise PermissionDenied

                with reversion.create_revision():
                    reversion.set_user(request.user)
                    if bool(request.POST.get('_decline')):
                        change_request.status = DOCUMENT_CHANGE_REQUEST_STATUS_DECLINED
                        change_request.save()
                        reversion.set_comment("Declined change request")
                        status_message = {'message': _("Change request declined"), 'status': 'success'}
                    elif bool(request.POST.get('_approve')):
                        change_request.status = DOCUMENT_CHANGE_REQUEST_STATUS_APPROVED
                        change_request.save()
                        reversion.set_comment("Approved change request")
                        message = _("Change request approved")
                        if change_request.type == CHANGE_REQUEST_ACTION_TYPE_ARCHIVE:
                            change_request.archive(self.auditor)
                        status_message = {'message': message, 'status': 'success'}

            elif change_request.status == DOCUMENT_CHANGE_REQUEST_STATUS_APPROVED:
                if not change_request.can_submit(self.auditor):
                    raise PermissionDenied("You don't have permission to submit document change requests")

                if form.is_valid():
                    form.save()
                    status_message = {'message': _('New version submitted'), 'status': 'success'}
            else:
                raise Http404()

        return self.render_htmx_response('includes/change_request_document_view.html', include_base_context=False, extra_context={
            'can_approve_or_decline': change_request.can_approve_or_decline(self.auditor),
            'form': form,
            'submit_label': _('Archive Document'),
            'change_request': change_request,
            'status_message': status_message,
        })


class FolderCreateView(MegDocsBaseMixin, SuccessMessageMixin, AuditorInstitutionMixin, ReversionMixin, FolderPermPOSTParentMixin, ActionAuditFormMixin, CreateView):
    """
    form view allowing user to create a new folder
    """
    current_tab = 'docs'
    model = Folder
    permission_required = 'megdocs.add_folder',
    template_name = 'dashboard/folder_create.html'
    form_class = CreateFolderForm
    success_message = gettext_lazy('Successfully created %(name)s.')

    def get_success_url(self) -> str:
        return reverse('docs:manage:doc-list', kwargs={
            'institution_slug': self.institution.slug,
            'folder': self.object.pk,
        })

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update(
            user=self.request.user,
            institution=self.institution,
            instance=Folder(
                owner=self.auditor,
                institution=self.institution,
            ),
        )
        return kwargs


class FolderEditView(MegDocsBaseMixin, SuccessMessageMixin, AuditorInstitutionMixin, ReversionMixin, FolderPermUpdateFolderMixin, ActionAuditFormMixin, UpdateView):
    """
    form view allowing user to edit an existing folder
    """
    permission_required = 'megdocs.change_folder'
    current_tab = 'docs'
    template_name = 'dashboard/folder_create.html'
    success_message = _('Successfully saved %(name)s')
    reversion_change_comment = 'Updated in MEG Docs'
    audit_change_message = 'Folder edited in MEG Docs'
    model = Folder
    form_class = CreateFolderForm

    @cached_property
    def folder(self) -> Folder:
        return self.get_object()

    def get_success_url(self) -> str:
        return reverse('docs:manage:doc-list', kwargs={
            'institution_slug': self.institution.slug,
            'folder': self.object.pk,
        })

    def get_delete_success_url(self) -> str:
        return reverse('docs:manage:doc-list', kwargs={'institution_slug': self.institution.slug})

    def get_context_data(self, **kwargs):
        data = super().get_context_data(**kwargs)
        data['allow_delete'] = self.allow_delete()
        return data

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update(user=self.request.user, institution=self.institution)
        return kwargs

    def get_permission_required(self):
        perms = super().get_permission_required()
        if self.deleting:
            perms += 'megdocs.delete_folder',
        return perms

    def get_queryset(self) -> FolderQuerySet:
        return super().get_queryset().published().filter(institution=self.institution)

    @property
    def deleting(self) -> bool:
        return self.request.POST.get('save') == 'remove'

    @transaction.atomic()
    def delete(self, request: HttpRequest):
        Unpublisher(self.folder, self.request.user).unpublish_logged(comment='Deleted using MEG Docs')
        messages.success(self.request, _("Successfully deleted {folder}").format(folder=self.folder.name))
        return HttpResponseRedirect(self.get_delete_success_url())

    def allow_delete(self) -> bool:
        if self.folder.owner == self.request.user.auditor or self.request.user.is_superuser:
            return True
        return FolderPermissionRule.objects.published()\
            .filter(permissions__codename__in=["delete_folder"], institution=self.institution, folders__in=[self.folder])\
            .filter(Q(users__in=[self.request.user]) | Q(teams__auditors__in=[self.auditor])).exists()

    def post(self, request, *args, **kwargs):
        if self.deleting:
            return self.delete(request)
        return super().post(request, *args, *kwargs)


class FolderPermissionRuleCreateView(MegDocsBaseMixin, SuccessMessageMixin, FolderPermissionRuleMixin, ReversionMixin, PermissionRequiredMixin, ActionAuditFormMixin, CreateView):
    """
    form view allowing user to create or edit folder permission rules
    """
    current_tab = 'docs'
    permission_required = 'megdocs.add_folderpermissionrule',
    template_name = 'dashboard/folder_permission_rule.html'
    success_message = _('Successfully saved %(name)s')
    audit_change_message = 'Folder permission rule created in MEG Docs'
    form_class = FolderPermissionRuleForm
    model = FolderPermissionRule

    def get_success_url(self) -> str:
        return reverse('docs:manage:folder-permission-rules', kwargs={'institution_slug': self.institution.slug})

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update(
            institution=self.institution,
            user=self.request.user,
            instance=FolderPermissionRule(
                owner=self.auditor,
                institution=self.institution,
            )
        )
        return kwargs


class FolderPermissionRuleUpdateView(MegDocsBaseMixin, SuccessMessageMixin, FolderPermissionRuleMixin, ReversionMixin, PermissionRequiredMixin, ActionAuditFormMixin, UpdateView):
    """
    form view allowing user to edit folder permission rules
    """
    current_tab = 'docs'
    permission_required = 'megdocs.change_folderpermissionrule',
    template_name = 'dashboard/folder_permission_rule.html'
    success_message = _('Successfully saved %(name)s')
    audit_change_message = 'Folder permission rule updated in MEG Docs'
    form_class = FolderPermissionRuleForm
    model = FolderPermissionRule

    def get_success_url(self) -> str:
        return reverse('docs:manage:folder-permission-rules', kwargs={'institution_slug': self.institution.slug})

    @cached_property
    def rule(self) -> FolderPermissionRule:
        return self.get_object()

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update(institution=self.institution, user=self.request.user)
        return kwargs

    def get_permission_required(self):
        perms = super().get_permission_required()
        if self.deleting:
            perms += 'megdocs.delete_folderpermissionrule',
        return perms

    def get_queryset(self) -> FolderPermissionRuleQueryset:
        return super().get_queryset().published().filter(institution=self.institution)

    @property
    def deleting(self) -> bool:
        return self.request.POST.get('save') == 'remove'

    @transaction.atomic()
    def delete(self, request: HttpRequest):
        Unpublisher(self.rule, self.request.user).unpublish_logged(comment='Deleted using MEG Docs')
        messages.success(self.request, _("Successfully deleted {rule}").format(rule=self.rule.name))
        return HttpResponseRedirect(self.get_success_url())

    def post(self, request, *args, **kwargs):
        if self.deleting:
            return self.delete(request)
        return super().post(request, *args, *kwargs)


class FolderPermissionRulesListView(FolderPermissionRuleMixin, PermissionRequiredMixin, MegDocsBaseMixin, MegDocsToolbarMixin, FolderTreeManageMixin, FolderPermissionRuleSearchMixin, ListView):
    """
    A list of folder permission rules visible to the logged in user
    """
    template_name = 'dashboard/folder_permission_rules.html'
    permission_required = 'megdocs.view_folderpermissionrule',
    current_tab = 'docs'
    queryset = FolderPermissionRule.objects.published()

    def get_queryset(self) -> FolderPermissionRuleQueryset:
        return super().get_queryset().published().filter(institution=self.institution)


class DocumentLinkChangeView(AuditorInstitutionMixin, ActionAuditFormMixin, FolderPermUpdateDocMixin, ReversionMixin, HTMXUtilsViewMixin, CreateView):
    queryset = DocumentLink.objects.published()
    template_name = 'dashboard/dialog_document_link.html'
    form_template_name = 'dashboard/form_document_link.html'
    list_template_name = 'dashboard/list_document_link.html'
    form_class = DocumentLinkForm
    pk_url_kwarg = 'link'

    @classmethod
    def htmx_success(cls):
        # return Response with documentLinkSuccess event trigger to close modal and refresh list
        response = HttpResponse()
        response['HX-Trigger'] = json.dumps({'documentLinkSuccess': ""})
        return response

    def form_valid(self, form: DocumentLinkForm) -> HttpResponse:
        # Form validated, trigger refresh of current page
        super().form_valid(form)
        return self.htmx_success()

    def get_template_names(self) -> list[str]:
        if self.htmx.target == 'form-link-body':
            return [self.form_template_name]
        if self.htmx.target == 'document-links-list':
            return [self.list_template_name]
        return super().get_template_names()

    def get_queryset(self):
        return super().get_queryset().for_user(self.request.user).filter(document_id=self.kwargs['pk'])

    @cached_property
    def document(self) -> Document:
        return get_object_or_404(Document.objects.published().for_user(self.request.user), pk=self.kwargs['pk'])

    def get_form_kwargs(self) -> dict[str, dict]:
        kwargs = super().get_form_kwargs()
        kwargs.update(instance=self.get_object())
        return kwargs

    def get_permission_required(self) -> tuple[str]:
        if self.creating:
            return 'megdocs.add_documentlink',
        elif self.deleting:
            return 'megdocs.delete_documentlink',
        else:
            return 'megdocs.change_documentlink',

    @cached_property
    def creating(self) -> bool:
        return self.kwargs.get(self.pk_url_kwarg) is None

    @property
    def deleting(self) -> bool:
        return bool(self.request.POST.get('delete', False))

    def get_success_url(self) -> str:
        return reverse('docs:manage:doc-edit', kwargs={
            'institution_slug': self.institution.slug,
            'pk': self.kwargs['pk'],
        })

    def get_object(self, queryset: Optional[DocumentRelationQuerySet] = None) -> DocumentLink:
        if not self.creating:
            return super().get_object(queryset)
        else:
            return DocumentLink(
                document=self.document,
            )

    @transaction.atomic()
    def delete(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        obj: DocumentLink = self.get_object()
        Unpublisher(obj, self.request.user).unpublish_logged(comment='Deleted in dashboards')
        return self.htmx_success()

    def post(self, request, *args, **kwargs) -> HttpResponse:
        if self.deleting:
            return self.delete(request, *args, **kwargs)
        return super().post(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(
            document=self.document,
            links=self.document.links.all().published()
        )
        return context
