$(document).ready(function () {
    $('#id_contributors').multiselect({
        nonSelectedText: gettext('Select reviewers...'),
        enableCaseInsensitiveFiltering: true,
        includeSelectAllOption: true,
    });
    $('#id_reviewer, #id_folder').multiselect({
        enableCaseInsensitiveFiltering: true,
    });
    $('#id_audit_forms').multiselect({
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

    $('input#id_document_files').attr('required', 'required');
});
