import json
from functools import cached_property
from typing import Iterable, Optional
import reversion
from django.contrib.messages.views import SuccessMessageMixin
from django.core.exceptions import PermissionDenied
from django.urls import reverse

from action_audit.utils import BaseActionAuditViewMixin, ActionAuditFormMixin
from analytics.views.mixin import AnalyticsViewLogMixin
from django.db import transaction
from django.db.models import Prefetch
from django.utils.translation import gettext_lazy as _
from django.http import HttpRequest, HttpResponse, Http404
from django.shortcuts import get_object_or_404
from django.views.generic import DetailView, CreateView
from django_htmx.middleware import HtmxDetails
from megdocs.constants import DOCUMENT_CHANGE_REQUEST_STATUS_APPROVED, CHANGE_REQUEST_ACTION_TYPE_NEW, CHANGE_REQUEST_ACTION_TYPE_EDIT, CHANGE_REQUEST_ACTION_TYPE_ARCHIVE
from megdocs.models import DocumentChangeRequest, DocumentQuerySet, Version, Document, DocumentCheckbox, DocumentCheckboxState, VersionApproval
from megdocs.forms import DocumentShareForm, DocumentEditRequestForm, ChangeRequestNewVersionForm, DocumentNewRequestForm
from megdocs.permissions import FolderPermDocMixin, FolderPermPOSTParentMixin
from megdocs.views.base import DocumentViewMixin, BookmarkViewMixin, MegDocsToolbarMixin, MegDocsBaseMixin
from megforms.utils import log_debug
from megforms.views.base import AuditorInstitutionMixin, ReversionMixin
from utils.htmx import HTMXViewMixin
from approvals.models import VersionApprovalConfig


class DocumentDetailView(HTMXViewMixin, AnalyticsViewLogMixin, BookmarkViewMixin, BaseActionAuditViewMixin, MegDocsToolbarMixin, DocumentViewMixin, FolderPermDocMixin, DetailView):
    """ Single document view """
    template_name = 'documents/document_detail.html'
    permission_required = 'megdocs.view_document',
    current_tab = 'docs'

    def get_queryset(self) -> DocumentQuerySet:
        queryset: DocumentQuerySet = super().get_queryset()
        return queryset.live_documents().approved().select_related('current_version')

    @property
    def document(self) -> Document:
        return self.object

    @property
    def current_version(self) -> Version:
        return self.document.current_version

    @cached_property
    def checkboxes(self) -> Iterable[DocumentCheckbox]:
        return self.document.checkboxes.published().order_by('order', 'pk').prefetch_related(
            Prefetch('states', DocumentCheckboxState.objects.filter(user=self.auditor, version=self.current_version)),
        )

    @cached_property
    def approvals(self) -> Iterable['VersionApproval']:
        return VersionApprovalConfig(self.document.current_version).get_all_approvals()

    def get_upload_url(self) -> str:
        """
        Get the url for the upload button adding the selected folder id to pre-fill
        the folder in the upload document form
        """
        url = super().get_upload_url()
        if folder := self.object.folder:
            url += f"?folder={folder.pk}"
        return url

    @transaction.atomic()
    def handle_share_document(self, request: HttpRequest, htmx: HtmxDetails, *args, **kwargs) -> HttpResponse:
        form: DocumentShareForm = DocumentShareForm(
            instance=self.object,
            user=self.request.user,
            data=self.request.POST or None,
        )
        status_message: Optional[dict[str, str]] = None
        if request.method == 'POST':
            if form.is_valid():
                try:
                    status_message = {'message': _("Successfully shared document with {number} users").format(
                        number=len(form.share_document())), 'status': 'success'}
                except Exception as e:
                    status_message = {'message': _("Error sharing document: {e}").format(e=str(e)), 'status': 'error'}
        return self.render_htmx_response('includes/share_document.html', include_base_context=False, extra_context={
            'form': form, 'status_message': status_message
        })

    @transaction.atomic()
    def handle_change_request_document_create(self, request: HttpRequest, htmx: HtmxDetails, *args, **kwargs) -> HttpResponse:
        if not self.institution.megdocs_change_requests_enabled or not self.document.suggestions_enabled:
            raise Http404()

        form: DocumentEditRequestForm = DocumentEditRequestForm(
            instance=DocumentChangeRequest(
                institution=self.institution,
                document=self.document,
                auditor=self.auditor,
                type=CHANGE_REQUEST_ACTION_TYPE_EDIT,
            ),
            data=self.request.POST or None,
        )
        status_message: Optional[dict[str, str]] = None
        if request.method == 'POST' and form.is_valid():
            form.save()
            status_message = {
                'message': _('Successfully submitted %s request.') % form.instance.get_type_display(),
                'status': 'success',
            }

        return self.render_htmx_response('includes/change_request_document_create.html', include_base_context=False, extra_context={
            'form': form, 'status_message': status_message
        })

    def handle_change_request_document(self, request: HttpRequest, htmx: HtmxDetails, *args, **kwargs) -> HttpResponse:
        change_request_id = request.GET.get('change_request_id') or request.POST.get('change_request_id')

        if not self.auditor.can_suggest_document_change:
            raise PermissionDenied("You don't have permission to add document change requests")

        # Show create if no change request id is provided
        if not change_request_id:
            return self.handle_change_request_document_create(request, htmx, *args, **kwargs)
        change_request_qs = DocumentChangeRequest.objects.for_institution(self.institution).for_user(self.request.user).for_edit()
        change_request: DocumentChangeRequest = get_object_or_404(change_request_qs, pk=change_request_id)

        if change_request.type == CHANGE_REQUEST_ACTION_TYPE_ARCHIVE:
            return self.render_htmx_response(
                'includes/change_request_document_view.html', include_base_context=False,
                extra_context={
                    'can_approve_or_decline': False,
                    'change_request': change_request,
                })

        status_message: Optional[dict[str, str]] = None
        form = ChangeRequestNewVersionForm(
            change_request=change_request,
            auditor=self.auditor,
            data=self.request.POST or None,
            files=self.request.FILES or None
        )

        if request.method == 'POST':
            if change_request.status != DOCUMENT_CHANGE_REQUEST_STATUS_APPROVED:
                raise Http404()

            if form.is_valid():
                form.save()
                status_message = {'message': _('New version submitted'), 'status': 'success'}

        return self.render_htmx_response(
            'includes/change_request_document_view.html', include_base_context=False,
            extra_context={
                'can_approve_or_decline': False,
                'form': form,
                'submit_label': _('Add Version'),
                'change_request': change_request,
                'status_message': status_message,
            })

    def handle_htmx(self, request: HttpRequest, htmx: HtmxDetails, *args, **kwargs) -> HttpResponse:
        self.object: Document = self.get_object()
        action = request.GET.get('_action', '') or request.POST.get('_action', '')

        if action == 'share':
            return self.handle_share_document(request, htmx, *args, **kwargs)
        elif action == 'change-request':
            return self.handle_change_request_document(request, htmx, *args, **kwargs)

        if request.method == 'POST':
            checkbox: DocumentCheckbox = get_object_or_404(self.checkboxes, pk=request.POST['checkbox_id'])
            with reversion.create_revision():
                reversion.set_user(request.user)
                reversion.set_comment("Checkbox clicked on document page")
                state, created = DocumentCheckboxState.objects.get_or_create(
                    checkbox=checkbox,
                    version=self.current_version,
                    user=self.auditor,
                )
            if created:
                self.log_creation(state, comment=f"checkbox '{checkbox}' ticked")
            else:
                log_debug(f"Checkbox '{checkbox}' already ticked")
            return self.render_htmx_response('documents/document_checkbox.html', include_base_context=False, extra_context={
                'checkbox': get_object_or_404(self.checkboxes, pk=request.POST['checkbox_id']),
            })
        return super().handle_htmx(request, htmx, *args, **kwargs)

    def get_context_data(self, **kwargs):
        required_checkboxes: list[int] = [c.pk for c in self.checkboxes if c.required and not c.states.all()]
        return super().get_context_data(
            version=self.current_version,
            checkboxes=self.checkboxes,
            required_checkboxes=json.dumps(required_checkboxes),
            approvals=self.approvals,
            change_requests_enabled=self.institution.megdocs_change_requests_enabled,
            current_change_request=self.document.current_change_request,
            user_change_request=self.document.get_user_change_request(self.auditor),
            **kwargs
        )

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        self.log_view(self.document, f"Viewed version {self.current_version.version} of {self.document}")
        return response


class DocumentSuggestView(MegDocsBaseMixin, SuccessMessageMixin, AuditorInstitutionMixin, ReversionMixin, FolderPermPOSTParentMixin, ActionAuditFormMixin, CreateView):
    """ form view allowing user to suggest a new document """
    current_tab = 'docs'
    model = DocumentChangeRequest
    permission_required = 'megdocs.can_suggest_new_document',
    template_name = 'documents/document_suggest.html'
    form_class = DocumentNewRequestForm
    success_message = _('Successfully created suggestion.')

    def dispatch(self, request, *args, **kwargs):
        if not self.institution.megdocs_change_requests_enabled:
            raise Http404()
        return super().dispatch(request, *args, **kwargs)

    def get_success_url(self) -> str:
        return reverse('docs:manage:doc-list', kwargs={
            'institution_slug': self.institution.slug,
        })

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update(
            instance=DocumentChangeRequest(
                institution=self.institution,
                auditor=self.auditor,
                type=CHANGE_REQUEST_ACTION_TYPE_NEW,
            ),
        )
        return kwargs
