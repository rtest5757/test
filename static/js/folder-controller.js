/* Mobile controller for folder actions */

function controlFolders(){
	$(document.body).on('click','.folder-list .folders.header .folders-controller',function(){
		if( $('.folder-list').hasClass('open') ){
			$('.folder-list .folders.header .folders-controller .glyphicon').removeClass('glyphicon-chevron-up').addClass('glyphicon-chevron-down');
			$('.folder-list').removeClass('open');
		}else{
			$('.folder-list .folders.header .folders-controller .glyphicon').removeClass('glyphicon-chevron-down').addClass('glyphicon-chevron-up');
			$('.folder-list').addClass('open');
		}
	});
}

function controlDocumentInfo(){
	$(document.body).on('click','table.document-list .column-content .document-info .document-info-controller', function(){
		if ( $(this).siblings('.document-additional-info').is(':visible') ){
			$('.glyphicon', this).removeClass('glyphicon-chevron-up').addClass('glyphicon-chevron-down');
			$(this).siblings('.document-additional-info').slideUp(200);
		}else{
			$('.glyphicon', this).removeClass('glyphicon-chevron-down').addClass('glyphicon-chevron-up');
			$(this).siblings('.document-additional-info').slideDown(200);
		}
	});
}

function controlFolderInfo(){
	$(document.body).on('click','table.document-list .column-content .document-info .folder-info-controller', function(){
		if ( $(this).siblings('.document-additional-info').is(':visible') ){
			$('.glyphicon', this).removeClass('glyphicon-chevron-up').addClass('glyphicon-chevron-down');
			$(this).siblings('.document-additional-info').slideUp(200);
		}else{
			$('.glyphicon', this).removeClass('glyphicon-chevron-down').addClass('glyphicon-chevron-up');
			$(this).siblings('.document-additional-info').slideDown(200);
		}
	});
}

$(document).ready(function () {

	controlFolders();
	controlDocumentInfo();
	controlFolderInfo();

});


// Reset open elements
$(window).resize(function(event) {

	var doc_width	= $(window).width();

	if ( doc_width > 700 ){

		//reset folder-list
		if ( $('.folder-list').hasClass('open') ){
			$('.folder-list').removeClass('open');
			$('.folder-list .folders.header .folders-controller .glyphicon').removeClass('glyphicon-chevron-up').addClass('glyphicon-chevron-down');
		}
		
		//Reset Document controller
		$('table.document-list .column-content .document-info .document-additional-info').hide();
		$('table.document-list .column-content .document-info .document-info-controller .glyphicon').removeClass('glyphicon-chevron-up').addClass('glyphicon-chevron-down');
		
		//Reset folder controller
		$('table.document-list .folder-row .column-content .document-info .document-additional-info').hide();
		$('table.document-list .folder-row .column-content .document-info .folder-info-controller .glyphicon').removeClass('glyphicon-chevron-up').addClass('glyphicon-chevron-down');

	}

});