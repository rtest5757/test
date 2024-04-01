$(document).ready(function () {
    $('#id_contributors').multiselect({
        nonSelectedText: gettext('Select reviewers...'),
        enableCaseInsensitiveFiltering: true,
        includeSelectAllOption: true,
    });
    $('#id_reviewer').multiselect({
        enableCaseInsensitiveFiltering: true,
    });
});
