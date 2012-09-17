(function () {
    "use strict";

    var KeePass = window.KeePass = window.KeePass || {};

    var readTime = KeePass.Time.readTime,
        Entry = KeePass.Entry = function (initStructure) {
        var k = null;
        this.database = null;
        this.uuid = '';
        this.groupId = 0x00;
        this.imageId = 0x00;
        this.title = '';
        this.url = '';
        this.userName = '';
        this.password = '';
        this.additional = '';
        this.created = new Date(0);
        this.lastModified = new Date(0);
        this.lastAccessed = new Date(0);
        this.expires = new Date(0);
        this.binaryDescription = '';
        this.binaryData = '';

        for (k in initStructure) {
    	if (initStructure.hasOwnProperty(k)) {
    	    this[k] = initStructure[k];
    	}
        }
    };

    Entry.prototype.addField = function(fieldType, fieldSize, decryptedPart, pos) {
        var fmt;
        switch(fieldType) {
        case 0x0000:
    	this.database.extData.read(data, fieldSize, null, this, pos);
    	break;
        case 0x0001:
    	this.uuid = struct.Unpack('<16s', decryptedPart, pos)[0];
    	break;
        case 0x0002:
    	this.groupId = struct.Unpack('<I', decryptedPart, pos)[0];
    	break;
        case 0x0003:
    	this.imageId = struct.Unpack('<I', decryptedPart, pos)[0];
    	break;
        case 0x0004:
    	fmt = '<' + (fieldSize - 1).toString() + 's';
    	this.title = struct.Unpack(fmt, decryptedPart, pos)[0];
    	break;
        case 0x0005:
    	fmt = '<' + (fieldSize - 1).toString() + 's';
    	this.url = struct.Unpack(fmt, decryptedPart, pos)[0];
    	break;
        case 0x0006:
    	fmt = '<' + (fieldSize - 1).toString() + 's';
    	this.userName = struct.Unpack(fmt, decryptedPart, pos)[0];
    	break;
        case 0x0007:
    	fmt = '<' + (fieldSize - 1).toString() + 's';
    	this.password = struct.Unpack(fmt, decryptedPart, pos)[0];
    	break;
        case 0x0008:
    	fmt = '<' + (fieldSize - 1).toString() + 's';
    	this.additional = struct.Unpack(fmt, decryptedPart, pos)[0];
    	break;
        case 0x0009:
    	this.created = readTime(decryptedPart, pos);
    	break;
        case 0x000A:
    	this.lastModified = readTime(decryptedPart, pos);
    	break;
        case 0x000B:
    	this.lastAccessed = readTime(decryptedPart, pos);
    	break;
        case 0x000C:
    	this.expires = readTime(decryptedPart, pos);
    	break;
        case 0x000D:
    	fmt = '<' + (fieldSize - 1).toString() + 's';
    	this.binaryDescription = struct.Unpack(fmt, decryptedPart, pos)[0];
    	break;
        case 0x000E:
    	fmt = '<' + fieldSize.toString() + 'A';
    	this.binaryData = struct.Unpack(fmt, decryptedPart, pos)[0];
    	break;
        case 0xFFFF:
    	if (fieldSize!=0) {
    	    throw "";
    	}
        }
    };
}());