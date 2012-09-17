(function() {

    var KeePass = window.KeePass = window.KeePass || {};

    // Random data to pad the file out to prevent guessing attacks

    var ExtData = KeePass.ExtData = function (headerHash) {
        this.headerHash = headerHash;
    };

    ExtData.prototype.read = function (data, size, group, entry, pos) {
        if (size===0) {
    	return;
        }
        var eos = false,
            result = true,
            fieldType = 0, fieldSize = 0, fieldData = '';

        while(!eos) {
    	fieldType = struct.Unpack('<H', data, pos);
    	fieldSize = struct.Unpack('<I', data, pos +=2);
    	pos += 4;
    	if (fieldSize > 0) {
    	    fieldData = data.slice(pos, pos + fieldSize);
    	}

    	switch(fieldType) {
    	case 0x0000:
    	    // Ignore field
    	    break;
    	case 0x0001:
    	    if (fieldSize == this.headerHash.length) {
    		result = this.headerHash == fieldData;
    	    }
    	    break;
    	case 0x0002:
    	    // Ignore random data
    	    break;
    	case 0xFFFF:
    	    eos = true;
    	    break;
    	default:
    	    throw "";
    	    break;
    	}
    	if (!result) {
    	    throw "";
    	}
        }
    };
}());