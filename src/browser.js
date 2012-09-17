(function($) {
    "use strict";
    $(function() {
	var opening = false;
	function readFiles(files, callback) {
            var reader = new FileReader(), fileArray = [], i;

            if (files.length!=1) {
        	return false;
            }
            for (i=0; i < files.length; i += 1){
        	fileArray.push(files[i]);
            }

            function doRead(fileArray) {
        	$(reader).bind('loadend', function(ev){
        	    var file = {
        		name: fileArray[0].name,
        		size: fileArray[0].size,
        		type: fileArray[0].type,
        		data: reader.result
        	    };
        	    callback(file);
        	    fileArray.shift();
        	    if (fileArray.length) {
        		doRead(fileArray);
        	    }
                });
                reader.readAsBinaryString(fileArray[0]);
            }

            doRead(fileArray);
	}

	window.task = function (name, percentage) {
	    $('#progressbar').progressbar({value: percentage});
	    $('#progressmessage').text(name + ' - ' + percentage.toString() + '%');
	};

        $('body').bind('dragenter', function (ev) {
            $(this).css('background-color', '#f00');
            ev.preventDefault();
            ev.stopPropagation();
            return false;
        });
        $('body').bind('dragleave', function (ev) {
            $(this).css('background-color', '#fff');
            ev.preventDefault();
            ev.stopPropagation();
            return false;
        });
        $('body').bind('dragover', function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            return false;
        });

        $('body').bind('drop', function (ev) {
            ev.preventDefault();
    	    ev.stopPropagation();
            $(this).css('background-color', '#fff');

            document.getElementById('keepassfile').files = ev.originalEvent.dataTransfer.files;

            return false;
        });

        function createEntry(entry) {
            var entryMarkup = $('<tr><td><a href="' + entry.url + '">'+ entry.title + '</a></td><td>' + entry.userName + '</td><td class="password masked">' + (new Array(entry.password.length)).join('*') + '</td><td><pre>' + entry.additional + '</pre></td></tr>');
	    entryMarkup.find('.password').click(function() {
		var $this = $(this);
                if ($this.hasClass('masked')) {
                    $this.text(entry.password);
		} else {
		    $this.text((new Array(entry.password.length)).join('*'));
		}
                $this.toggleClass('masked');
	    });
	    return entryMarkup;
        }

        function createSubGroups(groups, container) {
            var g, e=null, l = $('<ul class="groups"></ul>'),
                groupMarkup, entriesContainer, entryMarkup, entry;

            container.append(l);
            for (g = 0; g < groups.length; g += 1) {
        	groupMarkup = $('<li><span class="group-name">' + groups[g].name + '</span></li>');
        	entriesContainer = $('<table class="entries"><thead><tr><th>Title</th><th>Username</th><th>Password</th><th>Notes</th></tr></thead></table>');

        	for (e in groups[g].entries) {
        	    entry = groups[g].entries[e];
        	    if (groups[g].entries.hasOwnProperty(e) && e.length) {
        		entry = groups[g].entries[e];
        		entryMarkup = createEntry(entry);
        		entriesContainer.append(entryMarkup);
        	    }
        	}

        	groupMarkup.append(entriesContainer);
        	l.append(groupMarkup);

        	createSubGroups(groups[g].subGroups, groupMarkup);
            }
        }

        function opened(manager) {
            var container = $('#results'),
                groups = manager.database.subGroups;

            createSubGroups(groups, container);
        }

        function process() {
            var key = $('#password').val(),
                diskDrive = !!$('#use_keyfile:checked').length,
                providerName = 'KeePassJS',
                manager = new Manager();

            if (opening) {
        	return;
            }
            opening = true;

            function loadWithKeyFile(keyFile) {
        	readFiles($('#keepassfile').get(0).files, function(file) {
        	   try {
        	       manager.setMasterKey(
                           key,
        	           diskDrive,
        		   keyFile,
        		   providerName
    		       );
        	       manager.open(file.data);

        	       opened(manager);
        	   } catch (e) {
        	       alert(e);
        	   } finally {
        	       opening = false;
        	   }
        	});
            }

            if (diskDrive) {
        	readFiles($('#keyfile').get(0).files, function(file) {
        	    loadFile(keyfile);
        	});
            } else {
        	loadWithKeyFile(null);
            }
        }

        $('#open').bind('click', process);
        $('#keepassform').bind('submit', function(ev) {
            ev.preventDefault();
            process();
        });
    });
}(jQuery));
