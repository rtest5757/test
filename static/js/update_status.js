$(document).ready(function() {
    $(document).on('click', '.btn-update-status li.status a', function (e) {
        var target = $(e.target);
        var statusId = target.attr('value');
        var statusLabel = target.html();
        let dropdownParent = target.parents('.btn-update-status');
        let issueRow = target.parents('.issue-parent');
        var actionUrl = dropdownParent.attr('updateStatusUrl');
        var data = {};
        data[dropdownParent.attr('statusName')] = statusId;
        dropdownParent.addClass('updating');

        $.ajax({
            url: actionUrl,
            type: 'PUT',
            data: JSON.stringify(data),
            success: function (response) {
                // update dropdown label and colour
                let btn = dropdownParent.find('button');
                btn.find('span').first().html(statusLabel);
                dropdownParent.removeClass('updating');
                var background_color = dropdownParent.find('span.colors-'+statusId).get()[0].textContent;
                // update the button with the new status color
                btn.css({"background-color": background_color});
                // Update active item in dropdown
                dropdownParent.find('li').removeClass('active');
                dropdownParent.find('li.status-'+statusId).addClass('active');

                // Update due date styling based on the new label
                if (response.is_closed) {
                    issueRow.find('.text-danger').removeClass('text-danger');
                    issueRow.find('.text-warning').removeClass('text-warning');
                } else {
                    let dueDateCell = issueRow.find('#date_cell')[0];
                    let dueDate = new Date(dueDateCell.getAttribute('key')).setHours(0, 0, 0, 0);
                    let now = new Date().setHours(0, 0, 0, 0);
                    if (dueDate < now) {
                        $(dueDateCell).find('.text-warning').removeClass('text-warning');
                        $(dueDateCell).addClass('text-danger');
                    } else if (dueDate === now) {
                         $(dueDateCell).find('.text-danger').removeClass('text-danger');
                         $(dueDateCell).addClass('text-warning');
                    }
                }
                // finalize, message user
                toastr.success(gettext('Status updated to') + ' "' + statusLabel + '"');
            },
        }).fail(function (e) {
            console.error(e);
            dropdownParent.removeClass('updating');
            var message = gettext('Status update failed');
            if (e.responseJSON && e.responseJSON.detail) {
                message = e.responseJSON.detail;
            }
            toastr.error(message);
        });
    });
});
