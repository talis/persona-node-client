var uuid = require('uuid');
var ERROR_TYPES = require('./error-types');

function getRemotePublicKey(client, cacheKey, xRequestId, callback) {
    var options = {
        hostname: client.config.persona_host,
        port: client.config.persona_port,
        path: client.apiVersionPrefix + '/oauth/keys',
        method: 'GET',
        headers: {
            'User-Agent': client.userAgent,
            'X-Request-Id': xRequestId || uuid.v4()
        }
    };

    client.log('debug', 'Fetching public key from Persona');
    client.http.request(options, function onResponse(response) {
        var publicKey = '';

        if (response.statusCode !== 200) {
            client.log('error', 'Error fetching public key from Persona: ' + response.statusCode);
            callback(ERROR_TYPES.COMMUNICATION_ISSUE, null);
            return;
        }

        response.on('data', function onData(chunk) {
            publicKey += chunk;
        });

        response.on('end', function onEnd() {
            callback(null, publicKey);
            return;
        });
    }).on('error', function onError(error) {
        client.log('error', 'Fetching public key from Persona encountered an unknown error');
        callback(error, null);
        return;
    }).end();
}

module.exports = getRemotePublicKey;
