/*jslint bitwise: true, white: true, browser: true */
/*global CryptoJS: true */
(function () {
    "use strict";

    var KeePass = window.KeePass || {},
        U = KeePass.utils = KeePass.utils || {};


    U.byteArrayToWordArray = function (arr) {
        var words = [],
            i,
            padding = 4 - (arr.length % 4),
            byte1, byte2, byte3, byte4;
        for (i = 0; i < arr.length + padding; i += 4) {
            byte1 = arr[i];
            byte2 = arr[i + 1] === undefined ? 0 : arr[i + 1];
            byte3 = arr[i + 2] === undefined ? 0 : arr[i + 2];
            byte4 = arr[i + 3] === undefined ? 0 : arr[i + 3];
            words.push((byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4);
        }
        return CryptoJS.lib.WordArray.create(words, arr.length);
    };

    U.wordArrayToByteArray = function (arr) {
        return arr.toString(CryptoJS.enc.Latin1).split('').map(function (i) {
            return i.charCodeAt(0);
        });
    };
}());