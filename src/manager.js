/* KeePassJS - A JavaScript port of KeePassLib.
 * Copyright (C) 2012 Richard Mitchell
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */
/*jslint nomen: true, white: true, browser: true */
/*global Base64: true */
(function () {
    "use strict";

    var KeePass = window.KeePass = window.KeePass || {},
        U = KeePass.utils || {},
        S = KeePass.strings || {},
        E = KeePass.events || {},
        crypto = KeePass.crypto,
        Database = KeePass.Database,
        isBase64UrlString = (new RegExp('^base64:\/\/')).test,
        C = KeePass.constants || {},
        Manager = KeePass.Manager = function (statusCallback) {
        this.masterKey = '';
        this.keySource = '';
        this.database = null;
        this.statusCallback = statusCallback;
    };

    function loadHexKey(byteArray) {
        var i, result = [], string = U.byteArrayToString(byteArray);
        for (i = 0; i < 32; i += 2) {
            result.push(parseInt(string.slice(i, 2), 16));
        }
        return U.byteArrayToWordArray(result);
    }

    Manager.prototype.status = function(message) {
    	var $this = this;
    	if (this.statusCallback) {
    	    // fork
    	    $this.statusCallback(message);
    	    //window.setTimeout(function() {}, 0);
    	}
    };

    Manager.prototype.setMasterKey = function (key, diskDrive, keyFile, providerName) {
        var fileSize, fileData, self = this, readNormal, extKey, keySourceCand,
            finalizeKeyWithKeyFile = function(fileKey) {
                crypto.SHA256(key, function (ev) {
                    var passwordKey = ev.target.result;
                    crypto.SHA256(passwordKey.concat(fileKey), function (ev) {
                        self.masterKey = ev.target.result;
                        self.status(null);
                        E.fireDatabaseKeySet(self);
                    });
                });
            };

        key = U.stringToByteArray(key);
        if (key.length === 0) {
            this.status(null);
            E.fireDatabaseKeySetError(self, S.error_invalid_key);
            throw S.error_invalid_key;
        }

        this.status(S.creating_key);

        if (!diskDrive) {
            crypto.SHA256(key, function (ev) {
                self.masterKey = ev.target.result;
                self.status(null);
                E.fireDatabaseKeySet(self);
            });
        } else if (isBase64UrlString(keyFile.name)) {
            extKey = Base64.decode(keyFile.name.slice(9));
            if (extKey) {
                crypto.SHA256(extKey, function (ev) {
                    var fileKey = ev.target.result;
                    if (providerName !== null && providerName !== undefined) {
                        self.keySource = providerName;
                    }
                    if (key === null) { // external source only
                        self.masterKey = fileKey;
                        self.status(null);
                        E.fireDatabaseKeySet(self);
                    } else {
                        crypto.SHA256(key, function(ev) {
                            var passwordKey = ev.target.result;
                            crypto.SHA256(passwordKey.concat(fileKey), function (ev) {
                                self.masterKey = ev.target.result;
                                self.status(null);
                                E.fireDatabaseKeySet(self);
                            });
                        });
                    }
                });
            } else {
                this.status(null);
                E.fireDatabaseKeySetError(self, S.error_invalid_key);
                throw S.error_invalid_key;
            }

        } else {
            // with key file
            if (key === null) { // key file only
                keySourceCand = keyFile.name;
                if (keySourceCand.charAt(keySourceCand.length - 1) === '\\') {
                    keySourceCand += C.PWS_DEFAULT_KEY_FILENAME;
                }
                fileData = keyFile.data;

                readNormal = true;
                fileSize = keyFile.size;
                if (fileSize === 32) {
                    this.masterKey = fileData;
                    readNormal = false;
                } else if (fileSize === 64) {
                    this.masterKey = loadHexKey(fileData);
                    readNormal = false;
                }
                if (readNormal) {
                    crypto.SHA256(fileData, function (ev) {
                        self.masterKey = ev.target.result;
                        self.keySource = keySourceCand;
                        self.status(null);
                        E.fireDatabaseKeySet(self);
                    });
                } else {
                    this.status(null);
                    E.fireDatabaseKeySet(self);
                }
            } else { // secondKey != null
                keySourceCand = keyFile.name;
                if (keySourceCand.charAt(keySourceCand.length - 1) === '\\') {
                    keySourceCand += C.PWS_DEFAULT_KEY_FILENAME;
                }
                fileData = keyFile.data;
                fileSize = keyFile.size;
                readNormal = true;

                if (fileSize === 32) {
                    fileKey = fileData;
                    readNormal = false;
                } else if (fileSize === 64) {
                    fileKey = loadHexKey(fileData);
                    readNormal = false;
                }

                if (readNormal) {
                    crypto.SHA256(fileData, function (ev) {
                        var fileKey = ev.target.result;
                        finalizeKeyWithKeyFile(fileKey);
                    });
                } else {
                    finalizeKeyWithKeyFile(fileKey);
                }
            }
        }
        this.status(null);
    };

    Manager.prototype.open = function (data) {
	try {
	    this.database = new Database(this);
	    this.database.read(data);
	} catch (e) {
	    E.fireDatabaseOpenError(this, e);
	    throw e;
	}
    };

    Manager.prototype._transformMasterKey = function (keySeed, keyEncRounds, callback) {
        var lastPercentage = 0, percentage, self = this,
            remainingRounds = keyEncRounds,
            transformedMasterKey = this.masterKey;
        function nextRound(ev) {
            var allowUpdate = false;
            transformedMasterKey = ev.target.result;
            remainingRounds -= 1;
            if (remainingRounds === 0) {
                // Hash once with SHA-256
                crypto.SHA256(transformedMasterKey, function (ev) {
                    self.status(null);
                    callback(ev.target.result);
                });
            } else {
                percentage = Math.round((keyEncRounds - remainingRounds) / keyEncRounds * 100);
                if (percentage != lastPercentage) {
                    allowUpdate = true;
                    self.status(S.transforming_key.replace('%d', percentage));
                    lastPercentage = percentage;
                }
                if (allowUpdate) {
                    // timeout to let DOM update
                    window.setTimeout(function() { doRound(transformedMasterKey, remainingRounds);}, 0);
                } else {
                    doRound(transformedMasterKey, remainingRounds);
                }
            }
        }
        function doRound (transformedMasterKey) {
            crypto.encryptAESECB(
                keySeed,
                transformedMasterKey,
                nextRound);
        }

        this.status(S.transforming_key.replace('%d', 0));

        doRound(transformedMasterKey);
    };
}());