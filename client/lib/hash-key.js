var crypto = require('crypto');

/**
 * Hash a key using md4 & base64 encoding. Md4 is used as the implementation
 * in node is the fastest hashing alg supported.
 * @param {string} key value to hash
 * @return {string} hashed key
 */
var hashKey = function hashKey(key) {
    return crypto
        .createHash('md4')
        .update(key)
        .digest('base64');
};

module.exports = hashKey;

