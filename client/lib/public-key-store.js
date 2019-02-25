var _ = require('lodash');
var uuid = require('uuid');
var querystring = require("querystring");

var hashKey = require('./hash-key');
var getRemotePublicKey = require('./remote-public-key');
var generateToken = require('./generate-token');

function setCachedPublicKey(client, cacheKey, publicKey) {
    client.log('debug', 'Caching public key for ' + client.config.cert_timeout_sec + 's');
    client.tokenCache.set(cacheKey, publicKey, client.config.cert_timeout_sec);
}

function getCachedPublicKey(client, cacheKey, refresh, xRequestId, callback) {
    if (refresh) {
        return getRemotePublicKey(client, cacheKey, xRequestId, function(err, publicKey) {
            if (err) {
                callback(err);
                return
            }
            setCachedPublicKey(client, cacheKey, publicKey);
            callback(null, publicKey);
            return;
        });
    } else {
        client.tokenCache.get(cacheKey, function getPublicKeyIfNotInCacheThenVerify(error, publicKey) {
            if (publicKey && _.isString(publicKey)) {
                client.log('debug', 'Using public key from cache');
                callback(null, publicKey);
                return;
            }

            return getRemotePublicKey(client, cacheKey, xRequestId, function (err, publicKey) {
                if (err) {
                    callback(err);
                    return
                }
                setCachedPublicKey(client, cacheKey, publicKey);
                callback(null, publicKey);
                return;
            });
        });
    }
}

function obtainToken(client, opts, callback) {
    var id = opts.id;
    var secret = opts.secret;
    var xRequestId = opts.xRequestId || uuid.v4();

    var cacheKey = client._formatCacheKey(
        "obtain_token:" + hashKey(id)
    );

    // try cache first
    client.tokenCache.get(cacheKey, function (err, reply) {
        if (reply) {
            var data;
            if (_.isObject(reply)) {
                data = reply;
                reply = JSON.stringify(data);
            } else {
                data = JSON.parse(reply);
            }
            // at this point data is a JSON Object
            // and reply is a stringified JSON Object
            client.debug("Found cached token for key " + cacheKey + ": " + reply);

            if (data.access_token) {
                // recalc expires_in
                var now = Date.now() / 1000;
                var expiresIn = data.expires_at - now;
                client.debug("New expires_in is " + expiresIn);
                if (expiresIn > 0) {
                    data.expires_in = expiresIn;
                    callback(null, data);
                    return;
                }
            }
            // either expiresIn<=0, or malformed data, remove from redis and retry
            client._removeTokenFromCache(id, secret, function (err) {
                if (err) {
                    callback(err, null);
                } else {
                    generateToken(client, cacheKey, xRequestId, id, secret, callback);
                    return;
                }
            });
            return;
        }
        generateToken(client, cacheKey, xRequestId, id, secret, callback);
        return;
    });
}

module.exports = {
    set: setCachedPublicKey,
    get: getCachedPublicKey,
    obtainToken: obtainToken,
};

