function signedWordArrayToUnsignedWordArray(wa) {
    return (wa.words || wa).map(
	function(w) {
	    return w < 0 ? w + 4294967296 : w;
	});
}

function byteArrayToWordArray(arr) {
    var words = [], i,
    	padding = 4 - (arr.length % 4), byte1, byte2, byte3, byte4;
    for (i = 0; i < arr.length + padding; i += 4) {
	byte1 = arr[i];
	byte2 = arr[i+1]===undefined ? 0 : arr[i+1];
	byte3 = arr[i+2]===undefined ? 0 : arr[i+2];
	byte4 = arr[i+3]===undefined ? 0 : arr[i+3];
	words.push((byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4);
    }
    return CryptoJS.lib.WordArray.create(words, arr.length);
}

function wordArrayToByteArray(arr) {
    return arr.toString(CryptoJS.enc.Latin1).split('').map(function(i){return i.charCodeAt(0);});
}

function Database(manager) {
    this.manager = manager;
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
}

Database.prototype.addGroup = function(group) {
    this.subGroups.push(group);
};

Database.prototype.read = function(data) {
    var dataByteArray = data.split('').map(function(i){return i.charCodeAt(0);}),
        header = struct.Unpack('<4I16A16A2I32A32AI', dataByteArray, 0),
        groupCount = header[6],
        entryCount = header[7],
        contentsHash = byteArrayToWordArray(header[8]),
        algorithm, finalKey, decryptedPart, decryptedPartByteArray, headerHash,
        cipherParams, currentGroup, fieldType, fieldSize, transformedMasterKey,
        currentEntry, group, entry, lastGroupLevel, lastGroup = this;

    this.signature1 = header[0];
    this.signature2 = header[1];
    this.flags = header[2];
    this.version = header[3];
    this.masterSeed = byteArrayToWordArray(header[4]);
    this.encryptionIV = byteArrayToWordArray(header[5]);
    this.masterSeed2 = byteArrayToWordArray(header[9]);
    this.keyEncryptionRounds = header[10];

    if (this.signature1 == PWM_DBSIG_1_KDBX_P && this.signature2 == PWM_DBSIG_2_KDBX_P) {
        throw "Unsupported file.";
    }
    if (this.signature1 == PWM_DBSIG_1_KDBX_R && this.signature2 == PWM_DBSIG_2_KDBX_R) {
        throw "Unsupported file.";
    }
    if (this.signature1 != PWM_DBSIG_1 && this.signature2 != PWM_DBSIG_2) {
        throw "Invalid file signature";
    }
    if ((this.version & 0xFFFFFF00) != (PWM_DBVER_DW & 0xFFFFFF00)) {
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
	throw "Unsupported file version.";
    }

    if (groupCount == 0) {
        throw "Database empty.";
    }

    // Select algorithm
    if (this.flags & PWM_FLAG_RIJNDAEL) {
        algorithm = ALGO_AES;
    } else if (flags & PWM_FLAG_TWOFISH) {
        algorithm = ALGO_TWOFISH;
    } else {
        throw "Failed to open database.";
    }

    // Generate pTransformedMasterKey from pMasterKey
    transformedMasterKey = this.manager._transformMasterKey(this.masterSeed2, this.keyEncryptionRounds);
    if (!transformedMasterKey) {
        throw "Failed to open database.";
    }

    // Hash the master password with the salt in the file
    finalKey = CryptoJS.SHA256(this.masterSeed.concat(transformedMasterKey));

    if ((data.length - HEADER_SIZE) % 16 != 0) {
        throw "Invalid file size.";
    }

    encryptedPart = CryptoJS.enc.Latin1.parse(data.slice(HEADER_SIZE));

    if (algorithm == ALGO_AES) {
        // Decrypt! The first bytes aren't encrypted (that's the header)
	// TODO: something seems to go wrong in the last 4 bytes.
	cipherParams = CryptoJS.lib.CipherParams.create(
		{ciphertext: encryptedPart,
		 key: finalKey,
		 mode: CryptoJS.mode.CBC,
                 iv: this.encryptionIV,
                 padding: CryptoJS.pad.Pkcs7,
                 algorithm: CryptoJS.algo.AES});
        decryptedPart = CryptoJS.AES.decrypt(cipherParams,
        				     finalKey,
                                             {mode: CryptoJS.mode.CBC,
                                              iv: this.encryptionIV,
                                              padding: CryptoJS.pad.Pkcs7});
    } else if (algorithm == ALGO_TWOFISH) {
	cipherParams = CryptoJS.lib.CipherParams.create(
		{ciphertext: encryptedPart});
        decryptedPart = CryptoJS.TwoFish.decrypt(cipherParams,
        					 finalKey,
                                                 {mode: CryptoJS.mode.CBC,
                                                  iv: this.encryptionIV,
            					  padding: CryptoJS.pad.Pkcs7});
    } else {
        throw "Failed to open database.";
    }

    if (decryptedPart.words.length > 2147483446 ||
        (decryptedPart.words.length == 0 && (groupCount!=0 || entryCount !=0))) {
        throw "Invalid key.";
    }

    decryptedPartByteArray = wordArrayToByteArray(decryptedPart);

    /* TODO: enable this again once decryption fixed
     * if (contentsHash != CryptoJS.SHA256(decryptedPart)) {
        throw "Invalid key.";
    }*/

    function _hashHeader (data) {
	// SHA256 of header - encryption IV, group count, entry count & contents hash
	var headerSize = 124,
	    endCount = 32 + 4, // masterSeed2 + keyEncRounds
	    startCount = headerSize - endCount - 32, // signature1, signature2, flags, version, masterSeed
	    toHash = data.slice(0, startCount) + data.slice(headerSize - endCount, endCount);

	return CryptoJS.SHA256(CryptoJS.enc.Latin1.parse(toHash)).toString(CryptoJS.enc.Latin1).slice(0, 32);
    }

    headerHash = _hashHeader(data);
    this.extData = new ExtData(headerHash);

    lastGroupLevel = currentGroup = pos = 0;
    group = new Group({database: this, parent: this});
    while (currentGroup < groupCount) {
        fieldType = struct.Unpack('<H', decryptedPartByteArray, pos)[0];
        pos += 2;
        fieldSize = struct.Unpack('<I', decryptedPartByteArray, pos)[0];
        pos += 4;

        group.addField(fieldType, fieldSize, decryptedPartByteArray, pos);

        if (fieldType == 0xFFFF) {
            currentGroup++;
	    this.groups[group.id] = group;
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
	    group = new Group({database: this});
        }

        pos += fieldSize;
    }

    currentEntry = 0;
    entry = new Entry({database: this});
    while (currentEntry < entryCount) {
        fieldType = struct.Unpack('<H', decryptedPartByteArray, pos)[0];
        pos += 2;
        fieldSize = struct.Unpack('<I', decryptedPartByteArray, pos)[0];
        pos += 4;
        entry.addField(fieldType, fieldSize, decryptedPartByteArray, pos);

        if (fieldType == 0xFFFF) {
            currentEntry++;
	    this.entries[entry.uuid] = entry;
	    this.groups[entry.groupId].addEntry(entry);
	    entry = new Entry({database: this});
        }

        pos += fieldSize;
    }
};