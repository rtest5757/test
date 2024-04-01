from django.views.generic import TemplateView

from megdocs.views.base import MegDocsBaseMixin
from megforms.views.base import AuditorInstitutionMixin


class LandingPageView(MegDocsBaseMixin, AuditorInstitutionMixin, TemplateView):
    template_name = 'document_landing.html'
    current_tab = 'docs'
