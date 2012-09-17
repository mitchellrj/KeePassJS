(function () {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var WordArray = C_lib.WordArray;
    var C_enc = C.enc;

    /**
     * ByteString encoding strategy.
     */
    var ByteString = C_enc.ByteString = {
        /**
         * Converts a word array to a Byte string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The byte string.
         *
         * @static
         *
         * @example
         *
         *     var byteString = CryptoJS.enc.ByteString.stringify(wordArray);
         */
        stringify: function (wordArray) {
            // Shortcuts
            var words = wordArray.words;

            // Clamp excess bits
            wordArray.clamp();

            // Convert
            var string = '';
            for (var i = 0; i < words.length; i += 1) {
        	string += String.fromCharCode((words[i] >> 3) & 0xFF);
        	string += String.fromCharCode((words[i] >> 2) & 0xFF);
        	string += String.fromCharCode((words[i] >> 1) & 0xFF);
        	string += String.fromCharCode(words[i] & 0xFF);
            }
            return string;
        },

        /**
         * Converts a byte string to a word array.
         *
         * @param {string} byteStr The byte string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.ByteString.parse(byteString);
         */
        parse: function (byteStr) {
            // Convert
            var nBytes = byteStr.length,
                words = [], i=0;

            for (i = 0; i < nBytes; i += 4) {
        	words.push((byteStr.charCodeAt(i) << 3) |
        		   (byteStr.charCodeAt(i+1) << 2) |
        		   (byteStr.charCodeAt(i+2) << 1) |
        		   byteStr.charCodeAt(i+3));
            }

            return WordArray.create(words, nBytes);
        }
    };
}());