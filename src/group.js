(function() {
    "use strict";

    var KeePass = window.KeePass = window.KeePass || {};

    var readTime = KeePass.Time.readTime,
        Group = KeePass.Group = function (initStructure) {
        var k = null;
        this.database = null;
        this.id = '';
        this.imageId = 0x00;
        this.name = '';
        this.created = new Date(1970, 1, 1);
        this.lastModified = new Date(1970, 1, 1);
        this.lastAccessed = new Date(1970, 1, 1);
        this.expires = new Date(1970, 1, 1);
        this.level = 0;
        this.flags = 0x00;
        this.subGroups = [];
        this.entries = {};
        this.parent = null;

        for (k in initStructure) {
    	if (initStructure.hasOwnProperty(k)) {
    	    this[k] = initStructure[k];
    	}
        }
    };

    Group.prototype.addField = function(fieldType, fieldSize, decryptedPart, pos) {
	var fmt;
        switch(fieldType) {
        case 0x0000:
    	this.database.extData.read(data, fieldSize, this, null, pos);
    	break;
        case 0x0001:
    	this.id = struct.Unpack('<I', decryptedPart, pos)[0];
    	break;
        case 0x0002:
    	fmt = '<' + (fieldSize - 1).toString() + 's';
    	this.name = struct.Unpack(fmt, decryptedPart, pos, fieldSize)[0];
    	break;
        case 0x0003:
    	this.created = readTime(decryptedPart, pos);
    	break;
        case 0x0004:
    	this.lastModified = readTime(decryptedPart, pos);
    	break;
        case 0x0005:
    	this.lastAccessed = readTime(decryptedPart, pos);
    	break;
        case 0x0006:
    	this.expires = readTime(decryptedPart, pos);
    	break;
        case 0x0007:
    	this.imageId = struct.Unpack('<I', decryptedPart, pos)[0];
    	break;
        case 0x0008:
    	this.level = struct.Unpack('<H', decryptedPart, pos)[0];
    	break;
        case 0x0009:
    	this.flags = struct.Unpack('<I', decryptedPart, pos)[0];
    	break;
        case 0xFFFF:
    	if (fieldSize!=0) {
    	    throw "";
    	}
        }
    };

    Group.prototype.addGroup = function(group) {
        this.subGroups.push(group);
    };

    Group.prototype.addEntry = function(entry) {
        this.entries[entry.uuid] = entry;
    };
}());