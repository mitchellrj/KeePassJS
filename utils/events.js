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
(function() {
    "use strict";

    var KeePass = window.KeePass || {},
        E = KeePass.events = {};

    E.fireDatabaseKeySet = function (manager) {
        var event = document.createEvent('Event');
        event.initEvent('keePassDatabaseKeySet', true, true);
        event.manager = manager;
        document.dispatchEvent(event);
    };
    E.fireDatabaseKeySetError = function (manager, exc) {
        var event = document.createEvent('Event');
        event.initEvent('keePassDatabaseKeySetError', true, true);
        event.manager = manager;
        event.exception = exc;
        document.dispatchEvent(event);
    };

    E.fireDatabaseOpened = function (manager) {
    	var event = document.createEvent('Event');
    	event.initEvent('keePassDatabaseOpen', true, true);
    	event.manager = manager;
    	document.dispatchEvent(event);
    };
    E.fireDatabaseOpenError = function (manager, exc) {
    	var event = document.createEvent('Event');
    	event.initEvent('keePassDatabaseOpenError', true, true);
    	event.manager = manager;
    	event.exception = exc;
    	document.dispatchEvent(event);
    };

}());