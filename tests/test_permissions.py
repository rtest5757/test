import os

from django.conf import settings
from django.contrib.auth.models import Permission, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.template.response import TemplateResponse
from django.test import TestCase
from django.urls import reverse_lazy, reverse
from django.utils.translation import gettext

from model_bakery import baker
from rest_framework.status import HTTP_403_FORBIDDEN, HTTP_200_OK, HTTP_404_NOT_FOUND

from approvals.models import VersionApprovalConfig
from megdocs.constants import MANAGER, VIEWER, REVIEWER
from megdocs.models import FolderPermissionRule, Folder, Document, Version
from megdocs.permissions import FolderPermMixinBase
from megforms.test_utils import english_test
from megforms.utils import get_permissions, get_permission_by_name
from megforms.models import Institution, Auditor, Team


class PermissionsTest(TestCase):
    test_pdf_document = os.path.join(settings.BASE_DIR, 'megdocs/scripts/pdf/hand hygiene.pdf')
    permissions = (
        'megdocs.add_document',
        'megdocs.change_document',
        'megdocs.delete_document',
        'megdocs.view_document',
        'megdocs.view_version',
        'megdocs.add_version',
        'megdocs.change_version',
        'megdocs.delete_version',
        'megdocs.approve_version',
        'megdocs.view_folder',
        'megdocs.add_folder',
        'megdocs.change_folder',
        'megdocs.delete_folder',
        'comments.view_comment',
        'comments.add_comment',
    )
    test_pdf_content: bytes

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.institution: Institution = baker.make(Institution, name='Test Institution', megdocs_enabled=True)
        cls.auditor: Auditor = baker.make(Auditor, institution=cls.institution, user__username='owner', user__email='test@megit.com', user__user_permissions=get_permissions(cls.permissions, validate=True))
        cls.auditor2: Auditor = baker.make(Auditor, institution=cls.institution, user__username='owner2', user__email='test2@megit.com')
        cls.folder: Folder = Folder.objects.create(name="Folder", owner=cls.auditor, parent=None, institution=cls.institution)
        cls.team = baker.make(Team, institution=cls.institution)
        cls.create_rule_url = reverse_lazy('docs:manage:folder-permission-rule-create', kwargs={'institution_slug': cls.institution.slug})
        cls.rule_list_url = reverse_lazy('docs:manage:folder-permission-rules', kwargs={'institution_slug': cls.institution.slug})
        cls.folder_create_url = reverse_lazy('docs:manage:folder-create', kwargs={'institution_slug': cls.institution.slug})
        cls.folder_update_url = reverse_lazy('docs:manage:folder-update', kwargs={'institution_slug': cls.institution.slug, 'pk': cls.folder.pk})

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with open(cls.test_pdf_document, 'rb') as test_document:
            cls.test_pdf_content = test_document.read()

    def setUp(self) -> None:
        super().setUp()
        self.client.force_login(self.auditor.user)
        self.user: User = baker.make(User)

    def test_view_document__allowed(self):
        self.user.user_permissions.add(get_permission_by_name('megdocs.view_document'))
        self.assertTrue(FolderPermMixinBase().check_global_permissions(["view_document"], self.user))

    def test_view_document__not_allowed(self):
        self.user.user_permissions.remove(get_permission_by_name('megdocs.view_document'))
        self.assertFalse(FolderPermMixinBase().check_global_permissions(["view_document", "change_document"], self.user))
        self.assertFalse(FolderPermMixinBase().check_global_permissions(["view_document"], self.user))

    def test_view_version__allowed(self):
        self.user.user_permissions.add(get_permission_by_name('megdocs.view_version'))
        self.assertTrue(self.user.has_perms(['megdocs.view_version']))
        self.assertTrue(FolderPermMixinBase().check_global_permissions(["view_version"], self.user))

    def test_view_version__not_allowed(self):
        self.assertFalse(FolderPermMixinBase().check_global_permissions(["view_version", "change_version"], self.user))
        self.assertFalse(FolderPermMixinBase().check_global_permissions(["view_version"], self.user))

    def test_view_folder__allowed(self):
        self.user.user_permissions.add(get_permission_by_name('megdocs.view_folder'))
        self.assertTrue(self.user.has_perms(['megdocs.view_folder']))
        self.assertTrue(FolderPermMixinBase().check_global_permissions(["view_folder"], self.user))

    def test_view_folder__not_allowed(self):
        self.assertFalse(FolderPermMixinBase().check_global_permissions(["view_folder", "change_folder"], self.user))
        self.assertFalse(FolderPermMixinBase().check_global_permissions(["view_folder"], self.user))

    def test_empty__not_allowed(self):
        self.assertFalse(FolderPermMixinBase().check_global_permissions([], self.user))

    @english_test
    def test_create_permission_rule(self):
        self.auditor.user.user_permissions.add(
            get_permission_by_name('megdocs.add_folderpermissionrule'),
            get_permission_by_name('megdocs.change_folderpermissionrule'),
            get_permission_by_name('megdocs.delete_folderpermissionrule'),
            get_permission_by_name('megdocs.view_folderpermissionrule'),
        )
        with self.subTest("create view"):
            response = self.client.get(self.create_rule_url, follow=True)
            self.assertContains(response, 'Create Folder Permission Rule')
            self.assertNotContains(response, 'Delete')

        with self.subTest('create rule'):
            self.assertFalse(FolderPermissionRule.objects.filter(name="test rule").exists())
            response = self.client.post(self.create_rule_url, data={
                "name": "test rule",
                "folders": self.folder.pk,
                "role": 0,
                "teams": self.team.pk,
                "users": [self.auditor.user.pk, self.auditor2.user.pk]
            }, follow=True)
            self.assertContains(response, 'Successfully saved test rule')
            self.assertRedirects(response, self.rule_list_url)
            self.assertTrue(FolderPermissionRule.objects.filter(
                name="test rule", folders__in=[self.folder], teams__in=[self.team],
                users__in=[self.auditor.user, self.auditor2.user]
            ).exists())
            rule = FolderPermissionRule.objects.get(name="test rule")
            self.assertEqual(rule.role_index, 0)
            self.assertEqual(rule.role, MANAGER)

    def test_create_permission_rule__viewer(self):
        self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.add_folderpermissionrule'))
        self.assertFalse(FolderPermissionRule.objects.filter(name="viewer").exists())
        self.client.post(self.create_rule_url, data={
            "name": "viewer",
            "folders": self.folder.pk,
            "role": 2,
            "teams": self.team.pk,
            "users": [self.auditor.user.pk]
        }, follow=True)
        rule = FolderPermissionRule.objects.get(name="viewer")
        self.assertEqual(rule.role_index, 2)
        self.assertEqual(rule.role, VIEWER)

    def test_create_permission_rule__reviewer(self):
        self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.add_folderpermissionrule'))
        self.assertFalse(FolderPermissionRule.objects.filter(name="reviewer").exists())
        self.client.post(self.create_rule_url, data={
            "name": "reviewer",
            "folders": self.folder.pk,
            "role": 1,
            "teams": self.team.pk,
            "users": [self.auditor.user.pk]
        }, follow=True)
        rule = FolderPermissionRule.objects.get(name="reviewer")
        self.assertEqual(rule.role_index, 1)
        self.assertEqual(rule.role, REVIEWER)

    def test_create_permission_rule_post__folder_permission_unauthorized(self):
        self.assertFalse(FolderPermissionRule.objects.filter(name="test rule 2").exists())
        folder: Folder = Folder.objects.create(name="Folder", owner=self.auditor2, institution=self.institution)
        baker.make(FolderPermissionRule, folders=[folder])
        self.client.post(self.create_rule_url, data={
            "name": "test rule 2",
            "folders": folder.pk,
            "role": 2,
            "teams": self.team.pk,
            "users": [self.auditor.user.pk, self.auditor2.user.pk]
        }, follow=True)
        self.assertFalse(FolderPermissionRule.objects.filter(name="test rule 2").exists())

    def test_permission_rule_list(self):
        self.auditor.user.user_permissions.add(
            get_permission_by_name('megdocs.add_folderpermissionrule'),
            get_permission_by_name('megdocs.change_folderpermissionrule'),
            get_permission_by_name('megdocs.delete_folderpermissionrule'),
            get_permission_by_name('megdocs.view_folderpermissionrule'),
        )
        baker.make(FolderPermissionRule, institution=self.institution, name="rule1", folders=[self.folder], users=[self.auditor.user], owner=self.auditor, permissions=[
            Permission.objects.get(codename="change_document", content_type__app_label="megdocs"),
        ])
        baker.make(FolderPermissionRule, institution=self.institution, name="rule2", folders=[self.folder], teams=[self.team], owner=self.auditor, permissions=[
            Permission.objects.get(codename="view_folder", content_type__app_label="megdocs"),
        ])
        baker.make(FolderPermissionRule, name="unowned_rule", owner=self.auditor2)
        response = self.client.get(self.rule_list_url, follow=True)
        self.assertContains(response, gettext('Create Rule'))
        self.assertContains(response, gettext('Search all rules'))
        self.assertContains(response, 'rule1')
        self.assertContains(response, 'rule2')
        self.assertNotContains(response, 'unowned_rule')
        with self.subTest("search"):
            response = self.client.get(self.rule_list_url + "?q=rule1")
            self.assertContains(response, 'rule1')
            self.assertNotContains(response, 'rule2')
            response = self.client.get(self.rule_list_url + "?q=change_document")
            self.assertContains(response, 'rule1')
            self.assertNotContains(response, 'rule2')
            response = self.client.get(self.rule_list_url + "?q=view_folder")
            self.assertContains(response, 'rule2')
            self.assertNotContains(response, 'rule1')
            response = self.client.get(self.rule_list_url + "?q=" + self.auditor.user.username)
            self.assertContains(response, 'rule1')
            self.assertNotContains(response, 'rule2')
            response = self.client.get(self.rule_list_url + "?q=" + self.team.name)
            self.assertContains(response, 'rule2')
            self.assertNotContains(response, 'rule1')

    def test_folder_delete__team_permission(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        # protect folder
        rule: FolderPermissionRule = baker.make(FolderPermissionRule, institution=self.institution, folders=[self.folder], permissions=[
            Permission.objects.get(codename="delete_folder", content_type__app_label="megdocs"),
            Permission.objects.get(codename="change_folder", content_type__app_label="megdocs"),
        ])
        with self.subTest("unauthorized"):
            self.assertTrue(Folder.objects.first().publish)
            response = self.client.post(self.folder_update_url, data={"save": "remove"}, follow=True)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
            self.assertTrue(Folder.objects.first().publish)

        with self.subTest("authorized"):
            team = baker.make(Team, institution=self.institution)
            team.auditors.add(self.auditor)
            rule.teams.add(team)
            self.assertTrue(Folder.objects.first().publish)
            response = self.client.post(self.folder_update_url, data={"save": "remove"}, follow=True)
            self.assertFalse(Folder.objects.first().publish)
            self.assertEqual(response.status_code, HTTP_200_OK)

    def test_folder_list_manage__team_permission(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        # protect folder
        rule: FolderPermissionRule = baker.make(FolderPermissionRule, institution=self.institution, folders=[self.folder], permissions=[
            Permission.objects.get(codename="change_document", content_type__app_label="megdocs"),
            Permission.objects.get(codename="view_folder", content_type__app_label="megdocs"),
        ])
        with self.subTest("unauthorized"):
            response = self.client.get(self.folder_update_url, follow=True)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

        with self.subTest("authorized"):
            team = baker.make(Team, institution=self.institution)
            team.auditors.add(self.auditor)
            rule.teams.add(team)
            url = reverse_lazy('docs:manage:doc-list', kwargs={'institution_slug': self.institution.slug, 'folder': self.folder.pk})
            response = self.client.get(url, follow=True)
            self.assertEqual(response.status_code, HTTP_200_OK)

    def test_document_edit__team_permission(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        document: Document = baker.make(Document, name='Doc', institution=self.institution, folder=self.folder, owner=user, publish=True)
        rule: FolderPermissionRule = baker.make(FolderPermissionRule, institution=self.institution, folders=[self.folder], permissions=[
            Permission.objects.get(codename="change_document", content_type__app_label="megdocs"),
            Permission.objects.get(codename="add_document", content_type__app_label="megdocs"),
        ])
        url = reverse_lazy('docs:manage:doc-edit', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})

        with self.subTest("unauthorized"):
            self.assertFalse(Document.objects.filter(name="edited").exists())
            response = self.client.post(url, data={
                'name': 'edited',
                'description': '',
                'tags': 'test,document',
                'folder': self.folder.id,
                'required_approvals': '1',
            }, follow=True)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
            self.assertFalse(Document.objects.filter(name="edited").exists())

        with self.subTest("authorized"):
            self.assertFalse(Document.objects.filter(name="edited").exists())
            team = baker.make(Team, institution=self.institution)
            team.auditors.add(self.auditor)
            rule.teams.add(team)
            response = self.client.post(url, data={
                'name': 'edited',
                'description': '',
                'tags': 'test,document',
                'required_approvals': '1',
                'folder': self.folder.id,
                'checkbox-TOTAL_FORMS': 0,
                'checkbox-INITIAL_FORMS': 0,
            }, follow=True)
            self.assertEqual(response.status_code, HTTP_200_OK)
            self.assertTrue(Document.objects.filter(name="edited").exists())

    def test_document_version_create__team_permission(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        reviewer: Auditor = baker.make(Auditor, institution=self.institution, user__user_permissions=get_permissions(['megdocs.approve_version'], True))
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        document: Document = baker.make(Document, name='Doc', institution=self.institution, folder=self.folder, owner=user, publish=True)
        url = reverse('docs:manage:version-create', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})
        # protect folder
        rule: FolderPermissionRule = baker.make(FolderPermissionRule, folders=[self.folder], institution=self.institution, permissions=[
            Permission.objects.get(codename="add_version", content_type__app_label="megdocs"),
            Permission.objects.get(codename="approve_version", content_type__app_label="megdocs"),
            Permission.objects.get(codename="view_version", content_type__app_label="megdocs"),
        ])
        with self.subTest("unauthorized"):
            response = self.client.post(url, data={
                'file': SimpleUploadedFile('file.pdf', self.test_pdf_content, content_type='application/pdf'),
                'reviewer': reviewer.pk,
            }, follow=True)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
            self.assertFalse(document.versions.exists())

        with self.subTest("authorized"):
            team = baker.make(Team, institution=self.institution)
            team.auditors.add(self.auditor)
            rule.teams.add(team)
            response = self.client.post(url, data={
                'file': SimpleUploadedFile('file.pdf', self.test_pdf_content, content_type='application/pdf'),
                'reviewer': reviewer.pk,
            }, follow=True)
            self.assertEqual(response.status_code, HTTP_200_OK)
            self.assertTrue(document.versions.exists())

    def test_document_delete__team_permission(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        document: Document = baker.make(Document, name='Doc', institution=self.institution, folder=self.folder, owner=user, publish=True)
        team = baker.make(Team, institution=self.institution)
        team.auditors.add(self.auditor)
        url = reverse_lazy('docs:manage:doc-edit', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})

        rule: FolderPermissionRule = baker.make(FolderPermissionRule, institution=self.institution, folders=[self.folder], permissions=[
            Permission.objects.get(codename="change_document", content_type__app_label="megdocs"),
            Permission.objects.get(codename="delete_document", content_type__app_label="megdocs"),
            Permission.objects.get(codename="change_folder", content_type__app_label="megdocs"),
        ])
        with self.subTest("unauthorized"):
            self.assertTrue(Document.objects.filter(name="Doc", publish=True).exists())
            response = self.client.post(url, data={'save': 'remove'}, follow=True)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
            self.assertTrue(Document.objects.filter(name="Doc", publish=True).exists())

        with self.subTest("authorized"):
            self.assertTrue(Document.objects.filter(name="Doc", publish=True).exists())
            rule.teams.add(team)
            response = self.client.post(url, data={'save': 'remove'}, follow=True)
            self.assertEqual(response.status_code, HTTP_200_OK)
            self.assertFalse(Document.objects.filter(name="Doc", publish=True).exists())

    def test_folder_update__team_permission(self):
        self.assertFalse(Folder.objects.filter(name="updated folder").exists())
        user: Auditor = baker.make(Auditor, institution=self.institution)
        folder = Folder.objects.create(name="Folder", owner=user, institution=self.institution)
        url = reverse_lazy('docs:manage:folder-update', kwargs={'institution_slug': self.institution.slug, 'pk': folder.pk})
        rule: FolderPermissionRule = baker.make(FolderPermissionRule, institution=self.institution, folders=[folder], permissions=[
            Permission.objects.get(codename="change_folder", content_type__app_label="megdocs"),
            Permission.objects.get(codename="view_folder", content_type__app_label="megdocs"),
            Permission.objects.get(codename="view_document", content_type__app_label="megdocs"),
        ])
        with self.subTest("unauthorized"):
            response = self.client.post(url, data={
                "name": "updated folder",
                "description": "test description",
            }, follow=True)
            self.assertFalse(Folder.objects.filter(name="updated folder").exists())
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

        with self.subTest("authorized"):
            team = baker.make(Team, institution=self.institution)
            team.auditors.add(self.auditor)
            rule.teams.add(team)
            response = self.client.post(url, data={
                "name": "updated folder",
                "description": "test description",
            }, follow=True)
            self.assertTrue(Folder.objects.filter(name="updated folder").exists())
            self.assertEqual(response.status_code, HTTP_200_OK)

    def test_folder_delete__permission_unauthorized(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        self.auditor.user.user_permissions.remove(get_permission_by_name("megdocs.delete_folder"))
        self.assertTrue(Folder.objects.first().publish)

        response = self.client.post(self.folder_update_url, data={"save": "remove"}, follow=True)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        self.assertTrue(Folder.objects.first().publish)

    def test_folder_delete__permission_authorized(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        self.assertTrue(Folder.objects.first().publish)

        baker.make(FolderPermissionRule, folders=[self.folder], users=[self.auditor.user], permissions=[
            Permission.objects.get(codename="delete_folder", content_type__app_label="megdocs"),
            Permission.objects.get(codename="change_folder", content_type__app_label="megdocs"),
        ])

        response = self.client.post(self.folder_update_url, data={"save": "remove"}, follow=True)
        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertFalse(Folder.objects.first().publish)

    def test_folder_delete__permission_authorized__folders_none(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        self.assertTrue(Folder.objects.first().publish)

        baker.make(FolderPermissionRule, institution=self.institution, folders=[], users=[self.auditor.user], permissions=[
            Permission.objects.get(codename="delete_folder", content_type__app_label="megdocs"),
            Permission.objects.get(codename="change_folder", content_type__app_label="megdocs"),
        ])

        response = self.client.post(self.folder_update_url, data={"save": "remove"}, follow=True)
        self.assertEqual(response.status_code, HTTP_200_OK)
        self.assertFalse(Folder.objects.first().publish)

    def test_folder_update__parent_unauthorized(self):
        self.assertFalse(Folder.objects.filter(name="updated folder").exists())

        user: Auditor = baker.make(Auditor, institution=self.institution)
        folder = Folder.objects.create(name="Folder", owner=user, institution=self.institution)
        baker.make(FolderPermissionRule, folders=[folder], institution=self.institution)

        response = self.client.post(self.folder_update_url, data={
            "name": "updated folder",
            "description": "test description",
            "parent": folder.pk,
        }, follow=True)

        self.assertFalse(Folder.objects.filter(name="updated folder").exists())
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

    def test_folder_update__unauthorized(self):
        self.assertFalse(Folder.objects.filter(name="updated folder").exists())
        user: Auditor = baker.make(Auditor, institution=self.institution)
        folder = Folder.objects.create(name="Folder", owner=user, institution=self.institution)
        baker.make(FolderPermissionRule, folders=[folder], institution=self.institution)
        url = reverse_lazy('docs:manage:folder-update', kwargs={'institution_slug': self.institution.slug, 'pk': folder.pk})

        response = self.client.post(url, data={
            "name": "updated folder",
            "description": "test description",
        }, follow=True)

        self.assertFalse(Folder.objects.filter(name="updated folder").exists())
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

    def test_folder_list_manage_permission_unauthorized(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        self.auditor.user.user_permissions.remove(get_permission_by_name("megdocs.change_folder"))
        Folder.objects.filter(owner=self.auditor).update(owner=user)

        response = self.client.get(self.folder_update_url, follow=True)
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

    def test_folder_list_manage_permission_authorized(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        folder = Folder.objects.create(name="Folder", owner=user, institution=self.institution)

        baker.make(FolderPermissionRule, folders=[folder], institution=self.institution, users=[self.auditor.user], permissions=[
            Permission.objects.get(codename="change_document", content_type__app_label="megdocs"),
            Permission.objects.get(codename="view_folder", content_type__app_label="megdocs"),
        ])

        url = reverse_lazy('docs:manage:doc-list', kwargs={'institution_slug': self.institution.slug, 'folder': folder.pk})
        response = self.client.get(url, follow=True)
        self.assertNotContains(response, "You don't have access to this module yet")

    def test_folder_list_view__permission_authorized(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)

        url = reverse_lazy('docs:view:doc-list', kwargs={'institution_slug': self.institution.slug, 'folder': self.folder.pk})
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, HTTP_200_OK)

    def test_document_view__authorized(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        document: Document = baker.make(Document, name='Doc', institution=self.institution, folder=self.folder, owner=user, _fill_optional=['current_version'])
        version: Version = baker.make(Version, document=document, approved=False, reviewer=user, _create_files=True)
        published = VersionApprovalConfig(version).approve(user, True)
        self.assertTrue(published)
        self.assertTrue(version.approved)

        url = reverse_lazy('docs:view:doc-detail', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, HTTP_200_OK)

    def test_document_edit__unauthorized(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        baker.make(FolderPermissionRule, folders=[self.folder])
        document: Document = baker.make(Document, name='Doc', institution=self.institution, folder=self.folder, owner=user, publish=True)

        self.assertFalse(Document.objects.filter(name="edited").exists())
        url = reverse_lazy('docs:manage:doc-edit', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})
        self.client.post(url, data={
            'name': 'edited',
            'description': '',
            'tags': 'test,document',
            'folder': self.folder.id,
            'required_approvals': '1',
        }, follow=True)

        self.assertFalse(Document.objects.filter(name="edited").exists())

    def test_document_edit__authorized(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        document: Document = baker.make(Document, name='Doc', institution=self.institution, folder=self.folder, owner=user, publish=True)

        baker.make(FolderPermissionRule, institution=self.institution, folders=[self.folder], users=[self.auditor.user], permissions=[
            Permission.objects.get(codename="change_document", content_type__app_label="megdocs"),
            Permission.objects.get(codename="add_document", content_type__app_label="megdocs"),
            Permission.objects.get(codename="change_folder", content_type__app_label="megdocs"),
        ])

        self.assertFalse(Document.objects.filter(name="edited").exists())
        url = reverse_lazy('docs:manage:doc-edit', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})
        self.client.post(url, data={
            'name': 'edited',
            'description': '',
            'tags': 'test,document',
            'folder': self.folder.id,
            'required_approvals': '1',
            'checkbox-TOTAL_FORMS': 0,
            'checkbox-INITIAL_FORMS': 0,
        }, follow=True)

        self.assertTrue(Document.objects.filter(name="edited").exists())

    def test_document_delete__unauthorized(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        baker.make(FolderPermissionRule, folders=[self.folder], institution=self.institution)
        document: Document = baker.make(Document, name='Doc', institution=self.institution, folder=self.folder, owner=user, publish=True)

        self.assertTrue(Document.objects.filter(name="Doc", publish=True).exists())
        url = reverse_lazy('docs:manage:doc-edit', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})
        self.client.post(url, data={'save': 'remove'}, follow=True)

        self.assertTrue(Document.objects.filter(name="Doc", publish=True).exists())

    def test_document_delete__authorized(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        document: Document = baker.make(Document, name='Doc', institution=self.institution, folder=self.folder, owner=user, publish=True)

        baker.make(FolderPermissionRule, folders=[self.folder], users=[self.auditor.user], permissions=[
            Permission.objects.get(codename="change_document", content_type__app_label="megdocs"),
            Permission.objects.get(codename="delete_document", content_type__app_label="megdocs"),
            Permission.objects.get(codename="change_folder", content_type__app_label="megdocs"),
        ])

        self.assertTrue(Document.objects.filter(name="Doc", publish=True).exists())
        url = reverse_lazy('docs:manage:doc-edit', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})
        self.client.post(url, data={'save': 'remove'}, follow=True)

        self.assertFalse(Document.objects.filter(name="Doc", publish=True).exists())

    def test_document_version_create__unauthorized(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        reviewer: Auditor = baker.make(Auditor, institution=self.institution, user__user_permissions=get_permissions(['megdocs.approve_version'], True))
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        baker.make(FolderPermissionRule, folders=[self.folder], institution=self.institution)
        document: Document = baker.make(Document, name='Doc', institution=self.institution, folder=self.folder, owner=user, publish=True)

        url = reverse('docs:manage:version-create', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})
        self.client.post(url, data={
            'file': SimpleUploadedFile('file.pdf', self.test_pdf_content, content_type='application/pdf'),
            'reviewer': reviewer.pk,
        }, follow=True)
        self.assertFalse(document.versions.exists())

    def test_document_version_create__authorized(self):
        newowner: Auditor = baker.make(Auditor, institution=self.institution, user__username='newowner')
        reviewer: Auditor = baker.make(Auditor, institution=self.institution, user__username="reviewer", user__user_permissions=get_permissions(['megdocs.approve_version'], True))
        Folder.objects.filter(owner=self.auditor).update(owner=newowner)
        document: Document = baker.make(Document, name='Doc', institution=self.institution, folder=self.folder, owner=newowner, publish=True)

        baker.make(FolderPermissionRule, folders=[self.folder], users=[self.auditor.user], permissions=[
            Permission.objects.get(codename="add_version", content_type__app_label="megdocs")
        ])

        url = reverse('docs:manage:version-create', kwargs={'institution_slug': self.institution.slug, 'pk': document.pk})
        self.client.post(url, data={
            'file': SimpleUploadedFile('file.pdf', self.test_pdf_content, content_type='application/pdf'),
            'reviewer': reviewer.pk,
        }, follow=True)
        self.assertTrue(document.versions.exists())

    def test_document_version_review__authorized(self):
        user: Auditor = baker.make(Auditor, institution=self.institution)
        document: Document = baker.make(Document, institution=self.institution, owner=user, name='Test Document', folder=self.folder)
        Folder.objects.filter(owner=self.auditor).update(owner=user)
        version: Version = baker.make(Version, document=document, reviewer=self.auditor, _create_files=True)

        url = reverse('docs:manage:version-review', kwargs={'institution_slug': self.institution.slug, 'pk': version.pk})
        response: TemplateResponse = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, HTTP_200_OK)

    def test_folder_create_parent_unauthorized(self):
        self.assertFalse(Folder.objects.filter(name="created folder").exists())
        user: Auditor = baker.make(Auditor, institution=self.institution)
        folder = Folder.objects.create(name="Folder", owner=user, institution=self.institution)
        baker.make(FolderPermissionRule, folders=[folder], institution=self.institution)
        response = self.client.post(self.folder_create_url, data={
            "name": "created folder",
            "description": "test description",
            "parent": folder.pk,
        }, follow=True)

        self.assertFalse(Folder.objects.filter(name="created folder").exists())
        self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)

    def test_folder_create_parent_authorized_team(self):
        self.assertFalse(Folder.objects.filter(name="created folder").exists())
        user: Auditor = baker.make(Auditor, institution=self.institution)
        with self.subTest("team authorization"):
            folder = Folder.objects.create(name="Folder", owner=user, institution=self.institution)
            team = baker.make(Team, institution=self.institution)
            team.auditors.add(self.auditor)
            baker.make(FolderPermissionRule, institution=self.institution, folders=[folder], teams=[team], permissions=[
                Permission.objects.get(codename="add_folder", content_type__app_label="megdocs"),
            ])
            response = self.client.post(self.folder_create_url, data={
                "name": "folder1",
                "description": "test description",
                "parent": folder.pk,
            }, follow=True)
            self.assertNotContains(response, "Select a valid choice. That choice is not one of the available choices.")
            self.assertTrue(Folder.objects.filter(name="folder1").exists())
            self.assertEqual(response.status_code, HTTP_200_OK)

        with self.subTest("user authorization"):
            folder = Folder.objects.create(name="Folder", owner=user, institution=self.institution)
            baker.make(FolderPermissionRule, institution=self.institution, folders=[folder], users=[self.auditor.user], permissions=[
                Permission.objects.get(codename="add_folder", content_type__app_label="megdocs"),
            ])
            response = self.client.post(self.folder_create_url, data={
                "name": "folder2",
                "description": "test description",
                "parent": folder.pk,
            }, follow=True)
            self.assertNotContains(response, "Select a valid choice. That choice is not one of the available choices.")
            self.assertTrue(Folder.objects.filter(name="folder2").exists())
            self.assertEqual(response.status_code, HTTP_200_OK)

    def test_folder_edit__institution_protection(self):
        institution: Institution = baker.make(Institution)
        folder = Folder.objects.create(name="Folder", owner=self.auditor, institution=institution)
        url = reverse_lazy('docs:manage:folder-update', kwargs={'institution_slug': self.institution.slug, 'pk': folder.pk})
        response = self.client.post(url, data={
            "name": "updated folder",
            "description": "test description",
        }, follow=True)
        self.assertFalse(Folder.objects.filter(name="updated folder").exists())
        self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)

    def test_folder_view__institution_protection(self):
        institution: Institution = baker.make(Institution)
        folder = Folder.objects.create(name="Folder", owner=self.auditor, institution=institution)
        response = self.client.get(reverse_lazy('docs:manage:doc-list', kwargs={
            'institution_slug': self.institution.slug, 'folder': folder.pk
        }), follow=True)
        self.assertFalse(Folder.objects.filter(name="updated folder").exists())
        self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)

    def test_rule_edit__institution_protection(self):
        self.auditor.user.user_permissions.add(get_permission_by_name('megdocs.change_folderpermissionrule'))
        institution: Institution = baker.make(Institution)
        rule: FolderPermissionRule = baker.make(FolderPermissionRule, institution=institution)
        url = reverse_lazy('docs:manage:folder-permission-rule-update', kwargs={'institution_slug': self.institution.slug, 'pk': rule.pk})
        response = self.client.post(url, data={
            "name": "updated rule",
            "folders": self.folder.pk,
            "role": 0,
            "teams": self.team.pk,
            "users": [self.auditor.user.pk, self.auditor2.user.pk]
        }, follow=True)
        self.assertFalse(FolderPermissionRule.objects.filter(name="updated rule").exists())
        self.assertEqual(response.status_code, HTTP_404_NOT_FOUND)

    def test_edit_unprotected_unowned_foldered_document(self):
        self.client.logout()
        document: Document = baker.make(Document, institution=self.institution, folder=self.folder)
        document_edit_url = reverse('docs:manage:doc-edit', kwargs={
            'institution_slug': self.institution.slug,
            'pk': document.pk,
        })
        self.client.force_login(self.auditor2.user)
        with self.subTest("permission denied - no global perms"):
            response: TemplateResponse = self.client.get(document_edit_url)
            self.assertEqual(response.status_code, HTTP_403_FORBIDDEN)
        with self.subTest("permission granted"):
            self.auditor2.user.user_permissions.add(get_permission_by_name("megdocs.change_document"))
            self.auditor2.user.user_permissions.add(get_permission_by_name("megdocs.change_folder"))
            response: TemplateResponse = self.client.get(document_edit_url)
            self.assertEqual(response.status_code, HTTP_200_OK)
