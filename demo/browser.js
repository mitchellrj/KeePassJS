/* Copyright (C) 2012 Richard Mitchell
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/*jslint unparam: true, white: true, browser: true */
/*global FileReader: true, File: true, alert: true, jQuery: true */
(function ($) {
    "use strict";
    var KeePass = window.KeePass;

    $(function () {
        var opening = false;

        function readFiles(files, callback) {
            var reader = new FileReader(),
                fileArray = [],
                i;

            if (files.length !== 1) {
                return false;
            }
            for (i = 0; i < files.length; i += 1) {
                fileArray.push(files[i]);
            }

            function doRead(fileArray) {
                $(reader).bind('loadend', function (ev) {
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

        function pwMask(len) {
            /* Could also be done by (new Array(len)).join('*');, but lint no likey. */
            var result = '', i;
            for (i = 0; i < len; i += 1) {
                result += '*';
            }
            return result;
        }

        function createEntry(entry) {
            var entryMarkup = $('<tr><td><a href="' + entry.url + '">' + entry.title + '</a></td><td>' + entry.userName + '</td><td class="password masked">' + pwMask(entry.password.length) + '</td><td><pre>' + entry.additional + '</pre></td></tr>');
            entryMarkup.find('.password').click(function () {
                var $this = $(this);
                if ($this.hasClass('masked')) {
                    $this.text(entry.password);
                } else {
                    $this.text(pwMask(entry.password.length));
                }
                $this.toggleClass('masked');
            });
            return entryMarkup;
        }

        function doNotDisplay(entry) {
            return (entry.title==='Meta-Info' &&
        	    entry.userName==='SYSTEM' &&
        	    entry.url==='$' &&
        	    entry.additional==="KPX_GROUP_TREE_STATE");
        }

        function createSubGroups(groups, container) {
            var g, e = null,
                l = $('<ul class="groups"></ul>'),
                groupMarkup, entriesContainer, entryMarkup, entry;

            container.append(l);
            for (g = 0; g < groups.length; g += 1) {
                groupMarkup = $('<li><span class="group-name">' + groups[g].name + '</span></li>');
                entriesContainer = $('<table class="entries"><thead><tr><th>Title</th><th>Username</th><th>Password</th><th>Notes</th></tr></thead></table>');

                for (e in groups[g].entries) {
                    if (groups[g].entries.hasOwnProperty(e) && !doNotDisplay(groups[g].entries[e])) {
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
                manager = new KeePass.Manager();

            if (opening) {
                return;
            }
            $('#results').empty();
            opening = true;
            $('#spinner').show();

            function loadWithKeyFile(keyFile) {
                readFiles($('#keepassfile').get(0).files, function (file) {
                    try {
                        manager.setMasterKey(
                        key,
                        diskDrive,
                        keyFile,
                        providerName);
                        manager.open(file.data);

                        opened(manager);
                    } catch (e) {
                        alert(e);
                    } finally {
                        $('#spinner').hide();
                        opening = false;
                    }
                });
            }

            if (diskDrive) {
                readFiles($('#keyfile').get(0).files, function (keyfile) {
                    loadWithKeyFile(keyfile);
                });
            } else {
                loadWithKeyFile(null);
            }
        }

        $('#open').bind('click', process);
        $('#keepassform').bind('submit', function (ev) {
            ev.preventDefault();
            process();
        });
    });
}(jQuery));
