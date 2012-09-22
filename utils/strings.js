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
        S = KeePass.strings = KeePass.strings || {};

    S.creating_key = "Creating database key...";
    S.transforming_key = "Transforming key %d%...";
    S.decrypting_db = "Decrypting database contents...";
    S.verifying_contents = "Verifying database contents...";
    S.loading_contents = "Loading database contents...";
    S.error_invalid_key = "Invalid key.";
    S.error_failed_to_open = "Failed to open database.";
    S.error_bad_file_size = "Invalid file size.";
    S.error_empty_db = "Database empty.";
    S.error_unsupported_version = "Unsupported file version.";
    S.error_bad_signature = "Invalid file signature";
    S.error_unsupported_file = "Unsupported file.";
    S.error_unknown_field_type = "Unknown field type.";
    S.error_padding_data_mismatch = "Padding data mismatch";
}());