$(document).ready(function () {
    $('#id_owner, #id_current_version, #id_reviewer, #id_folder, #id_review_interval').multiselect({
        enableCaseInsensitiveFiltering: true,
    });
    $('#id_forms').multiselect({
        nonSelectedText: gettext('Select forms...'),
        enableCaseInsensitiveFiltering: true,
        includeSelectAllOption: true,
    });
    $('#id_leads').multiselect({
        enableCaseInsensitiveFiltering: true,
        includeSelectAllOption: true,
    });
    $('#id_documents').multiselect({
        nonSelectedText: gettext('Select documents...'),
        enableCaseInsensitiveFiltering: true,
        includeSelectAllOption: true,
    });
    $('#id_contributors').multiselect({
        nonSelectedText: gettext('Select reviewers...'),
        enableCaseInsensitiveFiltering: true,
        includeSelectAllOption: true,
    });
});
