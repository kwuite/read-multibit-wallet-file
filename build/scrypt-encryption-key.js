"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var ByteBuffer = require("bytebuffer");
var scrypt = require('scrypt-async');
var DEFAULT_N = 16384;
var DEFAULT_R = 8;
var DEFAULT_P = 1;
var DEFAULT_DERIVED_KEY_LENGTH = 32;
var DEFAULT_SALT = new Buffer([
    0x35, 0x51, 0x03, 0x80, 0x75, 0xa3, 0xb0, 0xc5
]);
var ScryptEncryptionKey = (function () {
    function ScryptEncryptionKey(password, salt, n, r, p, derivedKeyLength) {
        this.password = password;
        this.salt = salt || DEFAULT_SALT;
        this.n = n || DEFAULT_N;
        this.r = r || DEFAULT_R;
        this.p = p || DEFAULT_P;
        this.derivedKeyLength = derivedKeyLength || DEFAULT_DERIVED_KEY_LENGTH;
    }
    Object.defineProperty(ScryptEncryptionKey.prototype, "passwordBuffer", {
        get: function () {
            if (!this._passwordBuffer) {
                var bytes = Buffer.from(this.password, 'utf8');
                this._passwordBuffer = ByteBuffer.wrap(bytes);
            }
            return this._passwordBuffer;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ScryptEncryptionKey.prototype, "keyPromise", {
        get: function () {
            var _this = this;
            if (!this._keyPromise) {
                this._keyPromise = new Promise(function (resolve, reject) {
                    var pw = new Uint8Array(_this.passwordBuffer.toBuffer());
                    scrypt(pw, _this.salt, Math.log2(_this.n), _this.r, _this.derivedKeyLength, function (hash) {
                        console.log('Raw hash type:', Object.prototype.toString.call(hash));
                        console.log('Raw hash length:', hash.length);
                        console.log('Raw hash bytes:', Array.from(hash));
                        var hashBuffer = Buffer.from(hash);
                        console.log('Buffer type:', Object.prototype.toString.call(hashBuffer));
                        console.log('Buffer length:', hashBuffer.length);
                        console.log('Buffer bytes:', Array.from(hashBuffer));
                        if (hashBuffer.byteLength !== _this.derivedKeyLength) {
                            reject(new Error("Invalid hash length. Expected " + _this.derivedKeyLength + " but got " + hashBuffer.byteLength));
                            return;
                        }
                        var wrappedBuffer = ByteBuffer.wrap(hashBuffer);
                        console.log('Final ByteBuffer length:', wrappedBuffer.capacity());
                        resolve(wrappedBuffer);
                    });
                });
            }
            return this._keyPromise;
        },
        enumerable: true,
        configurable: true
    });
    return ScryptEncryptionKey;
}());
exports.ScryptEncryptionKey = ScryptEncryptionKey;
