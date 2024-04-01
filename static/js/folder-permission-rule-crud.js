$(document).ready(function () {
    $('#id_folders').multiselect({
        nonSelectedText: gettext('All folders'),
        enableCaseInsensitiveFiltering: true,
        includeSelectAllOption: true,
        selectAllText: gettext('Select all in list'),
        numberDisplayed: 2,
    });
    $('#id_role').multiselect({
        nonSelectedText: gettext('Select permissions...'),
        enableCaseInsensitiveFiltering: true,
        includeSelectAllOption: true,
        numberDisplayed: 2,
    });
    $('#id_teams').multiselect({
        nonSelectedText: gettext('Select teams...'),
        enableCaseInsensitiveFiltering: true,
        includeSelectAllOption: true,
        numberDisplayed: 2,
    });
    $('#id_users').multiselect({
        nonSelectedText: gettext('Select users...'),
        enableCaseInsensitiveFiltering: true,
        includeSelectAllOption: true,
        numberDisplayed: 2,
    });
});
