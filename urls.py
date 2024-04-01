from django.urls import re_path as url
from django.urls import include

from .views import documents, dashboards
from .views.views import LandingPageView

app_name = 'megdocs'

doc_views = [
    url(r'^$', dashboards.DocumentListView.as_view(full_screen=False, all_documents=True), name='doc-list'),
    url(r'^bookmarks$', dashboards.DocumentListView.as_view(bookmarks_only=True), name='doc-list-bookmarks'),
    url(r'^fullscreen/bookmarks$', dashboards.DocumentListView.as_view(bookmarks_only=True, full_screen=True), name='doc-list-bookmarks-fullscreen'),
    url(r'^folder/(?P<folder>\d+)$', dashboards.DocumentListView.as_view(full_screen=False), name='doc-list'),
    url(r'^fullscreen$', dashboards.DocumentListView.as_view(full_screen=True), name='doc-list-fullscreen'),
    url(r'^fullscreen/folder/(?P<folder>\d+)$', dashboards.DocumentListView.as_view(full_screen=True), name='doc-list-fullscreen'),
    url(r'^(?P<pk>\d+)$', documents.DocumentDetailView.as_view(manage=False), name='doc-detail'),
]

dashboards = [
    url(r'^list$', dashboards.DocumentListView.as_view(all_documents=True), name='doc-list'),
    url(r'^list/bookmarks$', dashboards.DocumentListView.as_view(bookmarks_only=True), name='doc-list-bookmarks'),
    url(r'^list/archived$', dashboards.DocumentListView.as_view(archived=True), name='doc-list-archived'),
    url(r'^list/folder/(?P<folder>\d+)$', dashboards.DocumentListView.as_view(), name='doc-list'),
    url(r'^(?P<pk>\d+)$', documents.DocumentDetailView.as_view(manage=True), name='doc-detail'),
    url(r'^awaiting-publish$', dashboards.AwaitingPublishVersionListView.as_view(), name='awaiting-publish-list'),
    url(r'^pending-requests$', dashboards.PendingRequestsListView.as_view(), name='pending-requests-list'),
    url(r'^review$', dashboards.ReviewVersionListView.as_view(), name='assigned-list'),
    url(r'^review/user$', dashboards.ReviewVersionListView.as_view(my_waiting_approval=True), name='user-assigned-list'),
    url(r'^document/suggest$', documents.DocumentSuggestView.as_view(), name='doc-suggest'),
    url(r'^document/create/bulk$', dashboards.DocumentBulkUploadView.as_view(), name='doc-bulk-upload'),
    url(r'^document/(?P<pk>\d+)$', dashboards.DocumentEditView.as_view(), name='doc-edit'),
    url(r'^document/(?P<pk>\d+)/v(?P<revision>\d+)$', dashboards.DocumentEditView.as_view(), name='doc-edit'),
    url(r'^document/(?P<pk>\d+)/version/create$', dashboards.VersionCreateView.as_view(), name='version-create'),
    url(r'^document/version/(?P<pk>\d+)/review$', dashboards.VersionReviewView.as_view(), name='version-review'),
    url(r'^document/(?P<pk>\d+)/link/create$', dashboards.DocumentLinkChangeView.as_view(), name='doc-link'),
    url(r'^document/(?P<pk>\d+)/link/(?P<link>\d+)$', dashboards.DocumentLinkChangeView.as_view(), name='doc-link'),
    url(r'^folder/create$', dashboards.FolderCreateView.as_view(), name='folder-create'),
    url(r'^list/folder/(?P<pk>\d+)/update$', dashboards.FolderEditView.as_view(), name='folder-update'),
    url(r'^folder-permission-rules$', dashboards.FolderPermissionRulesListView.as_view(), name='folder-permission-rules'),
    url(r'^folder-permission-rule/create$', dashboards.FolderPermissionRuleCreateView.as_view(), name='folder-permission-rule-create'),
    url(r'^folder-permission-rule/(?P<pk>\d+)/update$', dashboards.FolderPermissionRuleUpdateView.as_view(), name='folder-permission-rule-update'),
]

urlpatterns = [
    url(r'^landing$', LandingPageView.as_view(), name='doc-landing'),
    url(r'^view/', include((doc_views, 'view'))),
    url(r'^manage/', include((dashboards, 'manage'))),
]
