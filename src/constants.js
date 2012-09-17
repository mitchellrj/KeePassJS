(function() {
    "use strict";

    var KeePass = window.KeePass = window.KeePass || {};
    var C = KeePass.constants = KeePass.constants || {};

    //Database file signature bytes
    C.PWM_DBSIG_1 = 0x9AA2D903;
    C.PWM_DBSIG_2 = 0xB54BFB65;
    C.PWM_DBVER_DW = 0x00030004;

    // KeePass 2.x database file signatures (pre-release and release)
    C.PWM_DBSIG_1_KDBX_P = 0x9AA2D903;
    C.PWM_DBSIG_2_KDBX_P = 0xB54BFB66;
    C.PWM_DBSIG_1_KDBX_R = 0x9AA2D903;
    C.PWM_DBSIG_2_KDBX_R = 0xB54BFB67;

    C.PWM_FLAG_SHA2 = 1;
    C.PWM_FLAG_RIJNDAEL = 2;
    C.PWM_FLAG_ARCFOUR = 4;
    C.PWM_FLAG_TWOFISH = 8;

    C.ALGO_AES = 0;
    C.ALGO_TWOFISH = 1;

    C.HEADER_SIZE = 124;

    C.CB64_PROTOCOL_LEN = 9;

    C.PWS_DEFAULT_KEY_FILENAME = 'pwsafe.key';
}());