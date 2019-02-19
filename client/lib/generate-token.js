var querystring = require('querystring');

function generateToken(client, cacheKey, xRequestId, id, secret, callback) {

    client.debug("Did not find token in cache for key " + cacheKey + ", obtaining from server");
    // obtain directly from persona
    var form_data = {
        'grant_type': 'client_credentials'
    },
    post_data = querystring.stringify(form_data),
    options = {
        hostname: client.config.persona_host,
        port: client.config.persona_port,
        auth: id + ":" + secret,
        path: client.apiVersionPrefix + client.config.persona_oauth_route,
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': post_data.length,
            'User-Agent': client.userAgent,
            'X-Request-Id': xRequestId
        }
    };

    var req = client.http.request(options, function (resp) {
        var str = "";
        if (resp.statusCode === 200) {

            resp.on("data", function (chunk) {
                str += chunk;
            });
            resp.on("end", function () {
                var data;
                try {
                    data = JSON.parse(str);
                } catch (e) {
                    callback("Error parsing response from persona: " + str, null);
                    return;
                }
                if (data.error) {
                    callback(data.error, null);
                } else if (data.access_token) {
                    // cache token
                    var cacheFor = data.expires_in - 60, // cache for token validity minus 60s
                        now = (new Date().getTime() / 1000);
                    data.expires_at = now + data.expires_in;
                    if (cacheFor > 0) {
                        client.tokenCache.set(cacheKey, JSON.stringify(data), cacheFor);
                        callback(null, data);
                    } else {
                        callback(null, data);
                    }
                } else {
                    callback("Could not get access token", null);
                }
            });
        } else {
            var err = "Generate token failed with status code " + resp.statusCode;
            client.error(err);
            callback(err, null);
        }
    });
    req.on("error", function (e) {
        var err = "OAuth::generateToken problem: " + e.message;
        client.error(err);
        callback(err, null);
    });
    req.write(post_data);
    req.end();
}

module.exports = generateToken;
