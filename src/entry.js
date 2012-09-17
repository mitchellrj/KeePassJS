function Entry(initStructure) {
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
    this.created = new Date(1970, 1, 1);
    this.lastModified = new Date(1970, 1, 1);
    this.lastAccessed = new Date(1970, 1, 1);
    this.expires = new Date(1970, 1, 1);
    this.binaryDescription = '';
    this.binaryData = '';

    for (k in initStructure) {
	if (initStructure.hasOwnProperty(k)) {
	    this[k] = initStructure[k];
	}
    }
}

Entry.prototype.size = function() {
    return 16 + 4 + 4 + (this.title.length + 1) + (this.url.length + 1) +
        (this.userName.length + 1) + 4 + (this.password.length + 1) +
        (this.additional.length + 1) + 4 * TIME_SIZE +
        (this.binaryDescription.length + 1) + this.binaryData.length + 4;
};

Entry.prototype.serialize = function () {
    return struct.Pack(
	    '16A' + // uuid
	    'I' + // groupId
	    'I' + // imageId
	    (this.title.length + 1).toString() + 's' + // title
	    (this.url.length + 1).toString() + 's' + // url
	    (this.userName.length + 1).toString() + 's' + // username
	    'I' + // password length
	    (this.password.length + 1).toString() + 's' + // password
	    (this.additional.length + 1).toString() + 's' + // notes
	    TIME_SIZE.toString() + 's' + // created
	    TIME_SIZE.toString() + 's' + // mofidied
	    TIME_SIZE.toString() + 's' + // accessed
	    TIME_SIZE.toString() + 's' + // expires
	    (this.binaryDescription.length + 1).toString() + 's' + // binary description
	    (this.binaryData.length).toString() + 's' + // binary data
	    'I', // binary data length
	    this.uuid,
	    this.groupId,
	    this,imageId,
	    this.title + '\x00',
	    this.url + '\x00',
	    this.userName + '\x00',
	    this.password.length,
	    this.password + '\x00',
	    this.additional + '\x00',
	    serializeTime(this.created),
	    serializeTime(this.lastModified),
	    serializeTime(this.lastAccessed),
	    serializeTime(this.expires),
	    this.binaryDescription + '\x00',
	    this.binaryData,
	    this.binaryData.length
	    );
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