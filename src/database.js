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
/*jslint bitwise: true, nomen: true, unparam: true, todo: true, white: true, browser: true */
/*global struct: true */
(function () {
    "use strict";

    var KeePass = window.KeePass = window.KeePass || {},
        C = KeePass.constants || {},
        S = KeePass.strings || {},
        E = KeePass.events || {},
        U = KeePass.utils || {},
        Group = KeePass.Group,
        Entry = KeePass.Entry,
        ExtData = KeePass.ExtData,
        Database = KeePass.Database = function (manager) {
        this.manager = manager;
        this.algorithm = null;
        this.groupCount = 0;
        this.groups = {};
        this.subGroups = [];
        this.entries = {};
        this.extData = null;
        this.signature1 = 0x0000;
        this.signature2 = 0x0000;
        this.flags = 0x000;
        this.version = 0x000;
        this.masterSeed = '';
        this.encryptionIV = '';
        this.masterSeed2 = '';
        this.keyEncryptionRounds = 0x0000;
    };

    Database.prototype.addGroup = function (group) {
        this.subGroups.push(group);
    };

    Database.prototype._validateAndParse = function (decryptedPartByteArray) {
        var self = this;

        if (decryptedPartByteArray.length > 2147483446 || (decryptedPartByteArray.length === 0 && (groupCount !== 0 || entryCount !== 0))) {
            self.manager.status(null);
            E.fireDatabaseOpenError(self.manager, S.error_invalid_key);
            throw S.error_invalid_key;
        }

        self.manager.status(S.verifying_contents);

        /* TODO: something seems to go wrong in the last 4 bytes of
         * decryption. Enable this again once decryption fixed.
         * crypto.SHA256(decryptedPartByteArray, function (ev) {
         *     var thisContentsHash = ev.target.result;
         *
         *     if (this.contentsHash != CryptoJS.SHA256(decryptedPart)) {
         *         self.manager.status(null);
         *         E.fireDatabaseOpenError(self.manager, S.error_invalid_key);
         *         throw S.error_invalid_key;
         *     }
         *     self._prepareDecryptedData(decryptedPartByteArray);
         * });
         */

        self._prepareDecryptedData(decryptedPartByteArray);

    };

    Database.prototype._prepareDecryptedData = function (decryptedPartByteArray) {
        var self = this,
            toHash = struct.Pack('<4I16A32AI',
                                 self.signature1,
                                 self.signature2,
                                 self.flags,
                                 self.versions,
                                 self.masterSeed,
                                 self.masterSeed2,
                                 self.keyEncRounds);
        self.manager.status(S.loading_contents);

        crypto.SHA256(toHash, function (ev) {
            var headerHash = ev.target.result;
            self.extData = new ExtData(headerHash);

            self._parseDecryptedFile(decryptedPartByteArray);
        });

    };

    Database.prototype._parseDecryptedFile = function (decryptedPartByteArray) {
        var fieldType, fieldSize, lastGroupLevel, lastGroup = this,
        group, entry, currentGroup, currentEntry, pos = 0, self = this;

        lastGroupLevel = currentGroup = pos = 0;
        group = new Group({
            database: self,
            parent: self
        });
        while (currentGroup < self.groupCount) {
            fieldType = struct.Unpack('<H', decryptedPartByteArray, pos)[0];
            pos += 2;
            fieldSize = struct.Unpack('<I', decryptedPartByteArray, pos)[0];
            pos += 4;

            group.addField(fieldType, fieldSize, decryptedPartByteArray, pos);

            if (fieldType === 0xFFFF) {
                currentGroup += 1;
                self.groups[group.id] = group;
                if (group.level <= lastGroupLevel) {
                    while (lastGroup && lastGroup.level >= group.level) {
                        lastGroup = lastGroup.parent;
                    }
                }
                if (lastGroup) {
                    lastGroup.addGroup(group);
                    group.parent = lastGroup;
                }
                lastGroupLevel = group.level;
                lastGroup = group;
                group = new Group({
                    database: self
                });
            }

            pos += fieldSize;
        }

        currentEntry = 0;
        entry = new Entry({
            database: self
        });
        while (currentEntry < self.entryCount) {
            fieldType = struct.Unpack('<H', decryptedPartByteArray, pos)[0];
            pos += 2;
            fieldSize = struct.Unpack('<I', decryptedPartByteArray, pos)[0];
            pos += 4;
            entry.addField(fieldType, fieldSize, decryptedPartByteArray, pos);

            if (fieldType === 0xFFFF) {
                currentEntry += 1;
                self.entries[entry.uuid] = entry;
                self.groups[entry.groupId].addEntry(entry);
                entry = new Entry({
                    database: self
                });
            }

            pos += fieldSize;
        }

        self.manager.status(null);
        E.fireDatabaseOpened(self.manager);
    };

    Database.prototype._decryptWithTransformedKey = function(transformedMasterKey, dataByteArray) {
    	var cipherParams,
    	    encryptedPart = dataByteArray.subarray ? dataByteArray.subarray(C.HEADER_SIZE) : dataByteArray.slice(C.HEADER_SIZE),
    	    self = this;

        if (!transformedMasterKey) {
            E.fireDatabaseOpenError(self.manager, S.error_failed_to_open);
            throw S.error_failed_to_open;
        }

        // Hash the master password with the salt in the file
        crypto.SHA256(self.masterSeed.concat(transformedMasterKey), function(ev) {
            var finalKey = ev.target.result, decryptedPart, decryptedPartByteArray;

            if ((dataByteArray.length - C.HEADER_SIZE) % 16 !== 0) {
                E.fireDatabaseOpenError(self.manager, S.error_bad_file_size);
                throw S.error_bad_file_size;
            }

            self.manager.status(S.decrypting_db);

            if (self.algorithm === C.ALGO_AES) {
                // Decrypt! The first bytes aren't encrypted (that's the header)
                crypto.decryptAESCBC(encryptedPart, function (ev) {
                    var decryptedPartByteArray = ev.target.result;
                    self._validateAndParse(decryptedPartByteArray);
                });
            } else if (self.algorithm === C.ALGO_TWOFISH) {
                cipherParams = CryptoJS.lib.CipherParams.create({
                    ciphertext: U.byteArrayToWordArray(encryptedPart),
                    key: U.byteArrayToWordArray(finalKey),
                    mode: CryptoJS.mode.CBC,
                    iv: U.byteArrayToWordArray(self.encryptionIV),
                    padding: CryptoJS.pad.Pkcs7,
                    algorithm: CryptoJS.algo.AES
                });
                decryptedPart = CryptoJS.TwoFish.decrypt(cipherParams,
                finalKey, {
                    mode: CryptoJS.mode.CBC,
                    iv: U.byteArrayToWordArray(self.encryptionIV),
                    padding: CryptoJS.pad.Pkcs7
                });

                decryptedPartByteArray = U.wordArrayToByteArray(decryptedPart);
                self._validateAndParse(decryptedPartByteArray);
            } else {
                self.manager.status(null);
                E.fireDatabaseOpenError(self.manager, S.error_failed_to_open);
                throw S.error_failed_to_open;
            }
        });
    };

    Database.prototype.read = function (dataByteArray) {
        var self = this;

        this.header = struct.Unpack('<4I16A16A2I32A32AI', dataByteArray, 0);
        this.groupCount = this.header[6];
        this.entryCount = this.header[7];
        this.contentsHash = this.header[8];
        this.signature1 = this.header[0];
        this.signature2 = this.header[1];
        this.flags = this.header[2];
        this.version = this.header[3];
        this.masterSeed = this.header[4];
        this.encryptionIV = this.header[5];
        this.masterSeed2 = this.header[9];
        this.keyEncryptionRounds = this.header[10];

        if (this.signature1 === C.PWM_DBSIG_1_KDBX_P && this.signature2 === C.PWM_DBSIG_2_KDBX_P) {
            throw S.error_unsupported_file;
        }
        if (this.signature1 === C.PWM_DBSIG_1_KDBX_R && this.signature2 === C.PWM_DBSIG_2_KDBX_R) {
            throw S.error_unsupported_file;
        }
        if (this.signature1 !== C.PWM_DBSIG_1 && this.signature2 !== C.PWM_DBSIG_2) {
            throw S.error_bad_signature;
        }
        if ((this.version & 0xFFFFFF00) !== (C.PWM_DBVER_DW & 0xFFFFFF00)) {
            // Design decision: I'm not going to support this antiquated crap.
            // the chances of anyone having these old versions and this being the
            // first time they open them in a modern version of KeePass is tiny.
            /*
            if (this.version == 0x00020000 || this.version == 0x00020001 || this.version == 0x00020002) {
                return this.openDatabaseV2(data);
            } else if (this.version <= 0x00010002) {
                return this.openDatabaseV1(data);
            } else {
                throw "Failed to open database.";
            }*/
            throw S.error_unsupported_version;
        }

        if (this.groupCount === 0) {
            throw S.error_empty_db;
        }

        // Select algorithm
        if (this.flags & C.PWM_FLAG_RIJNDAEL) {
            this.algorithm = C.ALGO_AES;
        } else if (this.flags & C.PWM_FLAG_TWOFISH) {
            this.algorithm = C.ALGO_TWOFISH;
        } else {
            throw S.error_failed_to_open;
        }

        // Generate pTransformedMasterKey from pMasterKey
        this.manager._transformMasterKey(this.masterSeed2, this.keyEncryptionRounds, function (transformedMasterKey) {
            self._decryptWithTransformedKey(transformedMasterKey, dataByteArray);
        });
    };
}());