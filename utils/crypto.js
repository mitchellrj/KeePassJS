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
/*jslint nomen: true, white: true, browser: true */
/*global CryptoJS: true */
(function () {
    "use strict";

    var KeePass = window.KeePass = window.KeePass || {},
    C = KeePass.crypto = KeePass.crypto || {},
    U = KeePass.utils,
        nativeCryptoImplementation = window.mozCrypto || window.crypto,
        createAESCryptoOperation = null;

    function parseCallbackParams(callbackParams) {
        if (typeof (callbackParams) !== 'object') {
            callbackParams = {
                complete: callbackParams
            };
        }
        return callbackParams;
    }

    function addEventListeners(target, callbackParams, dataArgument) {
        target.addEventListener('init', function (ev) {
            if (callbackParams.init) {
                callbackParams.init(ev);
            }
        });
        target.addEventListener('progress', function (ev) {
            if (callbackParams.progress) {
                callbackParams.progress(ev);
            }
        });
        target.addEventListener('complete', function (ev) {
            if (callbackParams.complete) {
                callbackParams.complete(ev);
            }
        });
        target.addEventListener('abort', function (ev) {
            if (callbackParams.abort) {
                callbackParams.abort(ev);
            }
        });
        target.addEventListener('error', function (ev) {
            if (callbackParams.error) {
                callbackParams.error(ev);
            }
        });

        target.addEventListener('init', function (ev) {
            ev.target.processData(dataArgument);
        });

        target.addEventListener('progress', function (ev) {
            ev.target.complete();
        });
    }

    function wrapCryptoJS(cryptoAction) {
        var createCryptoEvent = function(type) {
                var ev = document.createEvent('Event');
                ev.initEvent(type, true, false);
                return ev;
            },
            dispatch = function (self, ev) {
                window.setTimeout(function () { self.dispatchEvent(ev); }, 0);
            },
            target = document.createElement('span'), // has to be a DOM node to dispatchEvent
            error = window.InvalidStateError ? new window.InvalidStateError() : {
                code: 9,
                target: target
            };
        target.key = undefined;
        target.algorithm = 'SHA-256';
        target.result = null;
        target._state = 'empty';
        target._data = [];

        target.init = function () {
            if (this._state !== 'empty') {
                throw error;
            }
            this._state = 'initializing';
            this._state = 'processing';
            dispatch(this, createCryptoEvent('init'));
        };
        target.processData = function (data) {
            if (this._state !== 'processing') {
                throw error;
            }
            this._data = this._data.concat(data);
            dispatch(this, createCryptoEvent('progress'));
        };
        target.complete = function () {
            var errorEvent = null;
            this._state = 'completing';
            try {
                this.result = cryptoAction(this._data);
            } catch (e) {
                errorEvent = createCryptoEvent('error');
                errorEvent.originalException = e;
                dispatch(this, errorEvent);
                this.dispatchEvent(errorEvent);
            }
            this._state = 'complete';
            dispatch(this, createCryptoEvent('complete'));
        };
        target.abort = function () {
            if (this._state === 'empty' || this._state === 'complete') {
                this.result = null;
            } else {
                this._state = 'complete';
                this.result = null;
            }
            dispatch(this, createCryptoEvent('abort'));
        };

        return target;
    }
    if (nativeCryptoImplementation && nativeCryptoImplementation.hash) {
        C.SHA256 = function (data, callbackParams) {
            var cryptoOperation = nativeCryptoImplementation.createDigester('SHA-256');
            callbackParams = parseCallbackParams(callbackParams);
            addEventListeners(cryptoOperation, callbackParams, data);

            cryptoOperation.init();
        };
    } else {
        C.SHA256 = function (data, callbackParams) {
            var cryptoOperation = wrapCryptoJS(function (data) {
                return U.wordArrayToByteArray(CryptoJS.SHA256(U.byteArrayToWordArray(data)));
            });
            callbackParams = parseCallbackParams(callbackParams);
            addEventListeners(cryptoOperation, callbackParams, data);
            cryptoOperation.init();
        };
    }

    if (nativeCryptoImplementation &&
        nativeCryptoImplementation.sym &&
        nativeCryptoImplementation.sym.algorithms.blockenc) {
        createAESCryptoOperation = function (fn, key, data, iv, mode, callbackParams) {
            var algorithmIdentifier = 'AES-' + mode,
                keyGenParams = {
                    name: algorithmIdentifier,
                    params: {
                        length: key.length
                    }
                },
                keyGenerator = nativeCryptoImplementation.createKeyGenerator(
                    keyGenParams,
                    false,
                    false, [fn]);

            callbackParams = parseCallbackParams(callbackParams);

            keyGenerator.addEventListener('error', function (ev) {
                if (callbackParams.error) {
                    callbackParams.error(ev);
                }
            });

            keyGenerator.addEventListener('complete', function (ev) {
                var finalKey = ev.target.result,
                    cipherParams = {
                        name: algorithmIdentifer,
                        params: {
                            iv: iv
                        }
                    },
                    cryptoOperation = nativeCryptoImplementation.createEncrypter(
                    cipherParams,
                    finalKey);
                addEventListeners(cryptoOperation, callbackParams, data);
                cryptoOperation.init();
            });
            return function () { keyGenerator.generate(); };
        };
    } else {
        createAESCryptoOperation = function (fn, key, data, iv, mode, callbackParams) {
            return function () {
                var cryptoOperation = wrapCryptoJS(function (data) {
                        var cipherParams = {
                                ciphertext: U.byteArrayToWordArray(data),
                                key: U.byteArrayToWordArray(key),
                                mode: CryptoJS.mode[mode],
                                padding: CryptoJS.pad.Pkcs7,
                                algorithm: CryptoJS.algo.AES
                            },
                            cipherOptions = {
                                mode: CryptoJS.mode[mode],
                                padding: CryptoJS.pad.Pkcs7
                            },
                            cryptoResult;
                        if (iv!==null) {
                            cipherParams.iv = cipherOption.iv = U.byteArrayToWordArray(iv);
                        }
                        cryptoResult = CryptoJS.AES[fn](
                            fn === 'decrypt' ? CryptoJS.lib.CipherParams.create(cipherParams) : U.byteArrayToWordArray(data),
                            U.byteArrayToWordArray(key),
                            cipherOptions
                        );
                        return U.wordArrayToByteArray(
                            cryptoResult.ciphertext
                        );
                    });
                callbackParams = parseCallbackParams(callbackParams);
                addEventListeners(cryptoOperation, callbackParams, data);

                cryptoOperation.init();
            };
        };
    }


    C.encryptAESCBC = function (key, data, iv, callbackParams) {
        var cryptoOperation = createAESCryptoOperation('encrypt', key, data, iv, 'CBC', callbackParams);
        cryptoOperation();
    };
    C.decryptAESCBC = function (key, data, iv, callbackParams) {
        var cryptoOperation = createAESCryptoOperation('decrypt', key, data, iv, 'CBC', callbackParams);
        cryptoOperation();
    };
    C.encryptAESECB = function (key, data, callbackParams) {
        var cryptoOperation = createAESCryptoOperation('encrypt', key, data, null, 'ECB', callbackParams);
        cryptoOperation();
    };
    C.decryptAESECB = function (key, data, callbackParams) {
        var cryptoOperation = createAESCryptoOperation('decrypt', key, data, null, 'ECB', callbackParams);
        cryptoOperation();
    };
}());