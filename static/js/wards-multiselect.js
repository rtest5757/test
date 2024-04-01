$(document).ready(function () {
    $('#id_wards').multiselect({
        enableClickableOptGroups: true,
        enableCaseInsensitiveFiltering: true,
        numberDisplayed: 1,
        nonSelectedText: gettext('Select') + ' ' + institution_config.terms.ward.plural,
        nSelectedText: ' ' + institution_config.terms.ward.plural,
        allSelectedText: gettext('All areas'),
        selectAllNumber: false,
        includeSelectAllOption: true,
    });
});
