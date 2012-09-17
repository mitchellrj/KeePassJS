(function () {
    /*global CryptoJS:true */
    'use strict';

    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var BlockCipher = C_lib.BlockCipher;
    var C_algo = C.algo;

    var wMax = 0xffffffff;;

    function getByte(x, n) {
        return (x >>> (n * 8)) & 0xFF;
    }

    function G0(x, m) {
        return m[0][getByte(x, 0)] ^ m[1][getByte(x, 1)] ^ m[2][getByte(x, 2)] ^ m[3][getByte(x, 3)];
    }

    function G1(x, m) {
        return m[0][getByte(x, 3)] ^ m[1][getByte(x, 0)] ^ m[2][getByte(x, 1)] ^ m[3][getByte(x, 2)];
    }

    function rotw(w, n) {
        return (w << n | w >>> (32 - n)) & wMax;
    }

    function frnd(r, blk, keySchedule, m) {
        var a = G0(blk[0], m);
        var b = G1(blk[1], m);
        blk[2] = rotw(blk[2] ^ (a + b + keySchedule[4 * r + 8]) & wMax, 31);
        blk[3] = rotw(blk[3], 1) ^ (a + 2 * b + keySchedule[4 * r + 9]) & wMax;
        a = G0(blk[2], m);
        b = G1(blk[3], m);
        blk[0] = rotw(blk[0] ^ (a + b + keySchedule[4 * r + 10]) & wMax, 31);
        blk[1] = rotw(blk[1], 1) ^ (a + 2 * b + keySchedule[4 * r + 11]) & wMax;
    }

    function irnd(i, blk, keySchedule, m) {
        var a = G0(blk[0], m);
        var b = G1(blk[1], m);
        blk[2] = rotw(blk[2], 1) ^ (a + b + keySchedule[4 * i + 10]) & wMax;
        blk[3] = rotw(blk[3] ^ (a + 2 * b + keySchedule[4 * i + 11]) & wMax, 31);
        a = G0(blk[2], m);
        b = G1(blk[3], m);
        blk[0] = rotw(blk[0], 1) ^ (a + b + keySchedule[4 * i + 8]) & wMax;
        blk[1] = rotw(blk[1] ^ (a + 2 * b + keySchedule[4 * i + 9]) & wMax, 31);
    }

    function encryptBlock(M, offset, keySchedule, m) {
        var blk = [
            M[offset] ^ keySchedule[0],
            M[offset + 1] ^ keySchedule[1],
            M[offset + 2] ^ keySchedule[2],
            M[offset + 3] ^ keySchedule[3]];
        for (var j = 0; j < 8; j++) {
            frnd(j, blk, keySchedule, m);
        }
        M[offset] = blk[2] ^ keySchedule[4];
        M[offset + 1] = blk[3] ^ keySchedule[5];
        M[offset + 2] = blk[0] ^ keySchedule[6];
        M[offset + 3] = blk[1] ^ keySchedule[7];
    }

    function decryptBlock(M, offset, keySchedule, m) {
	var j, blk = [
            M[offset] ^ keySchedule[4],
            M[1 + offset] ^ keySchedule[5],
            M[2 + offset] ^ keySchedule[6],
            M[3 + offset] ^ keySchedule[7]
        ];
        for (j = 7; j >= 0; j--) {
            irnd(j, blk, keySchedule, m);
        }
        M[offset] = blk[2] ^ keySchedule[0];
	M[offset + 1] = blk[3] ^ keySchedule[1];
	M[offset + 2] = blk[0] ^ keySchedule[2];
	M[offset + 3] = blk[1] ^ keySchedule[3];
    }

    var TwoFish = C_algo.TwoFish = BlockCipher.extend({
        _doReset: function() {
            var inKey = this._key.words;
            var i, a, b, c, d, meKey = [],
                moKey = [],
                kLen,
                sKey = [],
                keySchedule = [],
                f01, f5b, fef,
                q0 = [
                    [8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4],
                    [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5]
                ],
                q1 = [
                    [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
                    [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8]
                ],
                q2 = [
                    [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1],
                    [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15]
                ],
                q3 = [
                    [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10],
                    [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10]
                ],
                ror4 = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15],
                ashx = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7],
                q = [
                    [],
                    []
                ],
                m = [
                    [],
                    [],
                    [],
                    []
                ];

            function ffm5b(x) {
                return x ^ (x >> 2) ^ [0, 90, 180, 238][x & 3];
            }

            function ffmEf(x) {
                return x ^ (x >> 1) ^ (x >> 2) ^ [0, 238, 180, 90][x & 3];
            }

            function mdsRem(p, q) {
                var i, t, u;
                for (i = 0; i < 8; i++) {
                    t = q >>> 24;
                    q = ((q << 8) & wMax) | p >>> 24;
                    p = (p << 8) & wMax;
                    u = t << 1;
                    if (t & 128) {
                        u ^= 333;
                    }
                    q ^= t ^ (u << 16);
                    u ^= t >>> 1;
                    if (t & 1) {
                        u ^= 166;
                    }
                    q ^= u << 24 | u << 8;
                }
                return q;
            }

            function qp(n, x) {
                var a, b, c, d;
                a = x >> 4;
                b = x & 15;
                c = q0[n][a ^ b];
                d = q1[n][ror4[b] ^ ashx[a]];
                return q3[n][ror4[d] ^ ashx[c]] << 4 | q2[n][c ^ d];
            }

            function hFun(x, keySchedule, kLen) {
                var a = getByte(x, 0),
                    b = getByte(x, 1),
                    c = getByte(x, 2),
                    d = getByte(x, 3);

                switch (kLen) {
                case 4:
                    a = q[1][a] ^ getByte(keySchedule[3], 0);
                    b = q[0][b] ^ getByte(keySchedule[3], 1);
                    c = q[0][c] ^ getByte(keySchedule[3], 2);
                    d = q[1][d] ^ getByte(keySchedule[3], 3);
                case 3:
                    a = q[1][a] ^ getByte(keySchedule[2], 0);
                    b = q[1][b] ^ getByte(keySchedule[2], 1);
                    c = q[0][c] ^ getByte(keySchedule[2], 2);
                    d = q[0][d] ^ getByte(keySchedule[2], 3);
                case 2:
                    a = q[0][q[0][a] ^ getByte(keySchedule[1], 0)] ^ getByte(keySchedule[0], 0);
                    b = q[0][q[1][b] ^ getByte(keySchedule[1], 1)] ^ getByte(keySchedule[0], 1);
                    c = q[1][q[0][c] ^ getByte(keySchedule[1], 2)] ^ getByte(keySchedule);
                    d = q[1][q[1][d] ^ getByte(keySchedule[1], 3)] ^ getByte(keySchedule[0], 3);
                }
                return m[0][a] ^ m[1][b] ^ m[2][c] ^ m[3][d];
            }

            for (i = 0; i < 256; i++) {
                q[0][i] = qp(0, i);
                q[1][i] = qp(1, i);
            }
            for (i = 0; i < 256; i++) {
                f01 = q[1][i];
                f5b = ffm5b(f01);
                fef = ffmEf(f01);
                m[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24);
                m[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24);
                f01 = q[0][i];
                f5b = ffm5b(f01);
                fef = ffmEf(f01);
                m[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24);
                m[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24);
            }

            kLen = inKey.length / 2;
            for (i = 0; i < kLen; i++) {
                a = inKey[i + i];
                meKey[i] = a;
                b = inKey[i + i + 1];
                moKey[i] = b;
                sKey[kLen - i - 1] = mdsRem(a, b);
            }

            for (i = 0; i < 40; i += 2) {
                a = 0x1010101 * i;
                b = a + 0x1010101;
                a = hFun(a, meKey, kLen);
                b = rotw(hFun(b, moKey, kLen), 8);
                keySchedule[i] = (a + b) & wMax;
                keySchedule[i + 1] = rotw(a + 2 * b, 9);
            }
            for (i = 0; i < 256; i++) {
                a = b = c = d = i;
                switch (kLen) {
                case 4:
                    a = q[1][a] ^ getByte(sKey[3], 0);
                    b = q[0][b] ^ getByte(sKey[3], 1);
                    c = q[0][c] ^ getByte(sKey[3], 2);
                    d = q[1][d] ^ getByte(sKey[3], 3);
                case 3:
                    a = q[1][a] ^ getByte(sKey[2], 0);
                    b = q[1][b] ^ getByte(sKey[2], 1);
                    c = q[0][c] ^ getByte(sKey[2], 2);
                    d = q[0][d] ^ getByte(sKey[2], 3);
                case 2:
                    m[0][i] = m[0][q[0][q[0][a] ^ getByte(sKey[1], 0)] ^ getByte(sKey[0], 0)];
                    m[1][i] = m[1][q[0][q[1][b] ^ getByte(sKey[1], 1)] ^ getByte(sKey[0], 1)];
                    m[2][i] = m[2][q[1][q[0][c] ^ getByte(sKey[1], 2)] ^ getByte(sKey[0], 2)];
                    m[3][i] = m[3][q[1][q[1][d] ^ getByte(sKey[1], 3)] ^ getByte(sKey[0], 3)];
                }
            }
            this.keySchedule = keySchedule;
            this.m = m;
        },
        decryptBlock: function (M, offset) {
            decryptBlock(M, offset, this.keySchedule, this.m);
        },
        encryptBlock: function (M, offset) {
            encryptBlock(M, offset, this.keySchedule, this.m);
        }
    });

   /**
    * Shortcut functions to the cipher's object interface.
    *
    * @example
    *
    *     var ciphertext = CryptoJS.TwoFish.encrypt(message, key, cfg);
    *     var plaintext  = CryptoJS.TwoFish.decrypt(ciphertext, key, cfg);
    */
   C.TwoFish = BlockCipher._createHelper(TwoFish);

})();