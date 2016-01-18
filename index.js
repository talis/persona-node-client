"use strict";

var cryptojs = require('crypto-js'),
    url = require('url'),
    querystring = require('querystring'),
    _ = require('lodash');

// log severities
var DEBUG = "debug";
var ERROR = "error";

var VALIDATED_TYPES = {
    PERSONA: "verified_by_persona",
    CACHE: "verified_by_cache"
};

var ERROR_TYPES = {
    VALIDATION_FAILURE : "validation_failure",
    COMMUNICATION_ISSUE :"communication_issue",
    INVALID_TOKEN : "invalid_token",
    INSUFFICIENT_SCOPE : "insufficient_scope"
};

/**
 * Constructor you must pass in a config object with the following properties set:
 *
 * mandatory params
 * config.persona_host = "localhost";
 * config.persona_port = 443;
 * config.persona_scheme = "https";
 * config.persona_oauth_route = "/oauth/tokens/";
 * config.redis_host
 * config.redis_port
 * config.redis_db
 *
 * optional params:
 * config.enable_debug : true|false
 * config.logger: <pass in a logger that has debug() and error() functions>
 *
 * This library stores no default configuration of its own. It relies on the application/service
 * it is embedded in to supply this information.
 *
 * @param config
 * @constructor
 */
var PersonaClient = function (config) {
    this.config = config || {};

    var requiredAttributes = [
        'persona_host', 'persona_port', 'persona_scheme',
        'persona_oauth_route', 'redis_host', 'redis_port',
        'redis_db'
    ];

    for (var i = 0; i < requiredAttributes.length; i++) {
        var attribute = requiredAttributes[i];

        if (this.config[attribute] === undefined) {
            var name = attribute.replace(/_/g, ' ');
            throw new Error("You must specify the " + name);
        }
    }

    // connect to redis and switch to the configured db
    var redis = require('redis');
    this.redisClient = redis.createClient(this.config.redis_port, this.config.redis_host);
    this.redisClient.select(this.config.redis_db);

    // need to instantiate this based on the configured scheme
    this.http = require(this.config.persona_scheme);

    this.debug("Persona Client Created");
};

/**
 * Validate bearer token against cache or persona
 * @param token: Token to validate
 * @param scope: Requested scope
 * @param overrideScope: Backup scope to use instead of scope
 * @param next: Callback, function(err, validatedBy)
 */
PersonaClient.prototype.validateToken = function (token, scope, overridingScope, next) {
    if (!next) {
        throw "No callback (next attribute) provided";
    }

    if (token == null) {
        next(ERROR_TYPES.INVALID_TOKEN, null);
        return;
    }

    var _this = this,
        cacheKey = token + ((scope) ? "@" + scope : "");
    // if we were given a scope then append the scope to the token to create a cachekey

    this.debug("Validating token: " + cacheKey);
    this.redisClient.get("access_token:" + cacheKey, function (err, reply) {
        if (reply === "OK") {
            _this.debug("Token " + cacheKey + " verified by cache");
            next(null, VALIDATED_TYPES.CACHE);
        } else {
            var requestPath = _this.config.persona_oauth_route + token;
            var usingScope = scope || overridingScope || null;

            if (usingScope != null) {
                requestPath += "?scope=" + usingScope;
            }

            var options = {
                hostname: _this.config.persona_host,
                port: _this.config.persona_port,
                path: requestPath,
                method: 'HEAD'
            };

            _this.debug(JSON.stringify(options));

            _this.http.request(options, function (oauthResp) {
                if (oauthResp.statusCode === 204) {
                    // put this key in redis with an expire
                    _this.redisClient.multi().set("access_token:" + cacheKey, 'OK').expire("access_token:" + cacheKey, 60).exec(function (err, results) {
                        _this.debug("cache: " + JSON.stringify(err) + JSON.stringify(results));
                    });
                    _this.debug("Verification passed for token " + cacheKey + ", cached for 60s");
                    next(null, VALIDATED_TYPES.PERSONA);
                } else {
                    if (usingScope && usingScope !== "su") {
                        // try su, they are allowed to perform any operation
                        _this.validateToken (token, "su", overridingScope, next);
                    } else {
                        _this.debug("Verification failed for token " + cacheKey + " with status code " + oauthResp.statusCode);
                        if (oauthResp.statusCode === 403) {
                            next(ERROR_TYPES.INSUFFICIENT_SCOPE, null);
                        } else {
                            next(ERROR_TYPES.VALIDATION_FAILURE, null);
                        }
                    }
                }
            }).on ("error", function (e) {
                _this.error("OAuth::validateToken problem: " + e.message);
                next(e.message, null);
            }).end();
        }
    });
};

/**
 * Express middleware that can be used to verify a token
 * @param req
 * @param res
 * @param next
 */
PersonaClient.prototype.validateHTTPBearerToken = function (req, res, next, scope) {
    var token = this.getToken(req);
    this.validateToken(token, req.param("scope"), scope, function (err, validatedBy) {
        if (!err) {
            next(null, validatedBy);
            return;
        }

        switch(err) {
        case ERROR_TYPES.INVALID_TOKEN:
            res.status(401);
            res.json({
                "error": "no_token",
                "error_description": "No token supplied"
            });
            break;
        case ERROR_TYPES.VALIDATION_FAILURE:
            res.status(401);
            res.set("Connection", "close");
            res.json({
                "error": "invalid_token",
                "error_description": "The token is invalid or has expired"
            });
            break;
        case ERROR_TYPES.INSUFFICIENT_SCOPE:
            res.status(403);
            res.set("Connection", "close");
            res.json({
                "error": "insufficient_scope",
                "error_description": "The supplied token is missing a required scope"
            });
            break;
        default:
            res.status(500);
            res.set("Connection", "close");
            res.json({
                "error": "unexpected_error",
                "error_description": err
            });
        }
    });
};

/**
 * Extract a token from the request - try the header first, followed by the request params
 * @param req
 * @return {*}
 */
PersonaClient.prototype.getToken = function (req) {
    if (req.header("Authorization")) {
        var result = req.header("Authorization").match(/Bearer\s(\S+)/);
        if (result && result.length > 1) {
            return result[1];
        }
    }
    if (req.param('access_token')) {
        return req.param('access_token');
    }
    return null;
};

/**
 * Create a presigned URL
 * @param urlToSign
 * @param secret
 * @param expires
 * @param callback
 */
PersonaClient.prototype.presignUrl = function (urlToSign, secret, expires, callback) {
    if (!urlToSign) {
        throw new Error("You must provide a URL to sign");
    }
    if (!secret) {
        throw new Error("You must provide a secret with which to sign the url");
    }

    if (!expires) {
        expires = Math.floor(new Date().getTime() / 1000) + 900; // 15 minutes
    }

    var parsedURL = url.parse(urlToSign);
    var parsedQuery = querystring.parse(parsedURL.query);

    if (!parsedQuery.expires) {
        var expParam = urlToSign.indexOf("?") ? "&expires=" + expires : "?expires=" + expires;
        if (urlToSign.indexOf('#') !== -1) {
            urlToSign = urlToSign.replace("#", '' + expParam + '#');
        } else {
            urlToSign += expParam;
        }

        parsedURL = url.parse(urlToSign);
    }

    // generate a hash by re-signing the fullURL we where passed but with the 'signature' parameter removed
    var hash = cryptojs.HmacSHA256(urlToSign, secret);

    // now insert the hash into the query string
    var signedUrl = parsedURL.protocol + '//' + parsedURL.host + parsedURL.path + '&signature=' + hash + (parsedURL.hash ? parsedURL.hash : '');

    callback(null, signedUrl);
};

/**
 * Validate a presigned URL
 * @param presignedUrl
 * @param secret
 * @param callback
 */
PersonaClient.prototype.isPresignedUrlValid = function (presignedUrl, secret) {
    if (!presignedUrl) {
        throw new Error("You must provide a URL to validate");
    }
    if (!secret) {
        throw new Error("You must provide a secret with which to validate the url");
    }

    // we need to ensure we have a URL passed over
    var parsedURL = url.parse(presignedUrl);
    var parsedQuery = querystring.parse(parsedURL.query);
    var signature = parsedQuery.signature;
    var expiry = parsedQuery.expires;

    this.debug("Validating presignedUrl: " + presignedUrl + " with secret: " + secret);
    if (signature) {
        // replace the signature im the URL...the original secret will have been created from the full URL WITHOUT the signature (obviously!)
        var presignedUrlMinusSignature = presignedUrl.replace('&signature=' + signature, '');
        this.debug("presignedUrl minus signature: " + presignedUrlMinusSignature);
        // generate a hash by re-signing the fullURL we where passed but with the 'signature' parameter removed
        var hash = cryptojs.HmacSHA256(presignedUrlMinusSignature, secret);
        this.debug("hash generated for presignedurl: " + hash);

        // check if the hash we created matches the passed signature
        if (hash.toString() === signature) {
            this.debug("generated hash matched signature");
            if (expiry) {
                var epochNow = new Date().getTime() / 1000;
                this.debug("checking expiry: " + expiry + ' against epochNow: ' + epochNow);
                if (expiry < epochNow) {
                    this.debug("failed, presigned url has expired");
                    return false;
                }
            } else {
                this.debug("failed, presigned url has no expiry");
                return false;
            }

            this.debug("presigned url is valid");
            return true;
        } else {
            this.debug("failed, generated hash did not match the signature");
            return false;
        }
    } else {
        this.debug("failed, no signature provided");
        return false;
    }
};

/**
 * Obtain a new token for the given id and secret
 * @param id
 * @param secret
 * @param callback
 */
PersonaClient.prototype.obtainToken = function (id, secret, callback) {
    if (!id) {
        throw new Error("You must provide an ID to obtain a token");
    }
    if (!secret) {
        throw new Error("You must provide a secret to obtain a token");
    }

    var _this = this,
        cacheKey = "obtain_token:" + cryptojs.HmacSHA256(id, secret);

    // try cache first
    this.redisClient.get(cacheKey, function (err, reply) {
        if (err) {
            callback(err, null);
        } else {
            if (reply == null) {
                _this.debug("Did not find token in cache for key " + cacheKey + ", obtaining from server");
                // obtain directly from persona
                var form_data = {
                        'grant_type': 'client_credentials'
                    },
                    post_data = querystring.stringify(form_data),
                    options = {
                        hostname: _this.config.persona_host,
                        port: _this.config.persona_port,
                        auth: id + ":" + secret,
                        path: '/oauth/tokens',
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Content-Length': post_data.length
                        }
                    };
                var req = _this.http.request(options, function (resp) {
                    if (resp.statusCode === 200) {
                        var str = '';
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
                                    _this.redisClient.multi().set(cacheKey, JSON.stringify(data)).expire(cacheKey, cacheFor).exec(function (err) {
                                        if (err) {
                                            callback(err, null);
                                        } else {
                                            callback(null, data);
                                        }
                                    });
                                } else {
                                    callback(null, data);
                                }
                            } else {
                                callback("Could not get access token", null);
                            }
                        });
                    } else {
                        var err = "Generate token failed with status code " + resp.statusCode;
                        _this.error(err);
                        callback(err, null);
                    }
                });
                req.on("error", function (e) {
                    var err = "OAuth::generateToken problem: " + e.message;
                    _this.error(err);
                    callback(err, null);
                });
                req.write(post_data);
                req.end();
            } else {
                _this.debug("Found cached token for key " + cacheKey + ": " + reply);
                var data;
                try {
                    data = JSON.parse(reply);
                } catch (e) {
                    callback("Error parsing cached token: " + reply, null);
                    return;
                }
                if (data.access_token) {
                    // recalc expires_in
                    var now = new Date().getTime() / 1000;
                    var expiresIn = data.expires_at - now;
                    _this.debug("New expires_in is " + expiresIn);
                    if (expiresIn > 0) {
                        data.expires_in = expiresIn;
                        callback(null, data);
                        return;
                    }
                }
                // either expiresIn<=0, or malformed data, remove from redis and retry
                _this._removeTokenFromCache(id, secret, function (err) {
                    if (err) {
                        callback(err, null);
                    } else {
                        // iterate
                        _this.obtainToken(id, secret, callback);
                    }
                });
            }
        }
    });

};

/**
 * Request an application authorization (client_id/secret pair) for a user with guid, authing with id and secret.
 * Use title to describe the purpose.
 * @param guid
 * @param title
 * @param id
 * @param secret
 * @param callback
 */
PersonaClient.prototype.requestAuthorization = function (guid, title, id, secret, callback) {
    try {
        _.map([guid, title, id, secret], function (arg) {
            if (!_.isString(arg)) {
                throw "guid, title, id and secret are required strings";
            }
        });
    } catch (e) {
        callback(e,null);
        return;
    }

    var _this = this;
    _this.obtainToken (id,secret,function (err,token) { // todo: push down into person itself. You should be able to request an authorization using basic auth with client id/secret
        if (err) {
            callback("Request authorization failed with error: "+err,null);
        } else {
            var post_data = JSON.stringify({
                    'title': title
                }),
                options = {
                    hostname: _this.config.persona_host,
                    port: _this.config.persona_port,
                    path: '/oauth/users/' + guid + '/authorizations',
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + token.access_token,
                        'Content-Type': 'application/json',
                        'Content-Length': post_data.length
                    }
                },
                req = _this.http.request(options, function (resp) {
                    if (resp.statusCode === 200) {
                        var str = '';
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
                            } else if (data.client_id && data.client_secret) {
                                callback(null, data);
                            } else {
                                callback("Could not request authorization", null);
                            }
                        });
                    } else {
                        var err = "Request authorization failed with status code " + resp.statusCode;
                        _this.error(err);
                        callback(err, null);
                    }
                });
            req.on("error", function (e) {
                var err = "OAuth::requestAuthorization problem: " + e.message;
                _this.error(err);
                callback(err, null);
            });
            req.write(post_data);
            req.end();
        }
    });
};

/**
 * Delete the authorization defined by authorization_client_id, using id and secret to auth
 * @param authorization_client_id
 * @param id
 * @param secret
 * @param callback
 */
PersonaClient.prototype.deleteAuthorization = function (guid, authorization_client_id, id, secret, callback) {
    try {
        _.map([guid, authorization_client_id, id, secret], function (arg) {
            if (!_.isString(arg)) {
                throw "guid, authorization_client_id, id and secret are required strings";
            }
        });
    } catch (e) {
        callback(e,null);
        return;
    }

    var _this = this;
    _this.obtainToken(id,secret,function (err,token) { // todo: push down into person itself. You should be able to request an authorization using basic auth with client id/secret
        if (err) {
            callback("Request authorization failed with error: "+err);
        } else {
            var options = {
                    hostname: _this.config.persona_host,
                    port: _this.config.persona_port,
                    path: '/oauth/users/' + guid + '/authorizations/' + authorization_client_id,
                    method: 'DELETE',
                    headers: {
                        'Authorization': 'Bearer ' + token.access_token,
                        'Content-Type': 'application/json',
                        'Content-Length': 0
                    }
                },
                req = _this.http.request(options, function (resp) {
                    if (resp.statusCode === 204) {
                        callback(null);
                    } else {
                        var err = "Delete authorization failed with status code " + resp.statusCode;
                        _this.error(err);
                        callback(err);
                    }
                });
            req.on("error", function (e) {
                var err = "OAuth::deleteAuthorization problem: " + e.message;
                _this.error(err);
                callback(err);
            });
            req.end();
        }
    });
};

/**
 * Update a users profile
 * @param {string} guid
 * @param {object} profile Profile data - must be an object containing profile params
 * @param {string} token
 * @callback callback
 */
PersonaClient.prototype.updateProfile = function(guid, profile, token, callback){

    try {
        _.map([guid, token], function (arg) {
            if (!_.isString(arg)) {
               throw "guid and token are required strings";
            }
        });
        _.map([profile], function (arg) {
            if (!_.isObject(arg)) {
                throw "profile is a required object";
            }
        });

    } catch (e) {
        callback(e,null);
        return;
    }

    var _this = this;
    // Get a profile
    var profileData = JSON.stringify(profile),
        options = {
            hostname: _this.config.persona_host,
            port: _this.config.persona_port,
            path: '/users/' + guid + '/profile',
            method: 'PUT',
            headers: {
                'Authorization': 'Bearer ' + token
            },
            data:{
               profile:JSON.stringify(profile)
            }
        },
        req = _this.http.request(options, function (resp) {
            if (resp.statusCode === 200) {

                var str = '';
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

                    if(data){
                        if (data.error) {
                            callback(data.error, null);
                        } else if (data) {
                            callback(null, data);
                        }
                    } else {
                        callback("Could not update Profile", null);
                    }
                });
            } else {
                var err = "updateProfile failed with status code " + resp.statusCode;
                _this.error(err);
                callback(err, null);
            }
      });

    req.on("error", function (e) {
        var err = "updateProfile problem: " + e.message;
        _this.error(err);
        callback(err, null);
    });
    req.write(profileData);
    req.end();
};

/**
 * Get a user profile by a GUID
 * @param {string} guid
 * @param {string} token
 * @callback callback
 */
PersonaClient.prototype.getProfileByGuid = function(guid, token, callback){

    try {
        _.map([guid, token], function (arg) {
            if (!_.isString(arg)) {
                throw "guid and token are required strings";
            }
        });
    } catch (e) {
        callback(e,null);
        return;
    }

    var _this = this;
    // Get a profile
    var options = {
        hostname: _this.config.persona_host,
        port: _this.config.persona_port,
        path: '/users/' + (_.isArray(guid) ? guid.join(',') : guid),
        method: 'GET',
        headers: {
           'Authorization': 'Bearer ' + token
        }
    },
    req = _this.http.request(options, function (resp) {
        if (resp.statusCode === 200) {

            var str = '';
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

                if(data){
                  if (data.error) {
                      callback(data.error, null);
                  } else {
                     callback(null, data);
                  }
                } else {
                    callback("Could not get Profile By Guid", null);
                }
            });
        } else {
          var err = "getProfileByGuid failed with status code " + resp.statusCode;
          _this.error(err);
          callback(err, null);
        }
    });

    req.on("error", function (e) {
        var err = "getProfileByGuid problem: " + e.message;
        _this.error(err);
        callback(err, null);
    });
    req.end();
};
/**
 * Removes any tokens that are cached for the given id and secret
 * @param id
 * @param secret
 * @param callback
 * @private
 */
PersonaClient.prototype._removeTokenFromCache = function (id, secret, callback) {
    var cacheKey = "obtain_token:" + cryptojs.HmacSHA256(id, secret),
        _this = this;
    _this.redisClient.del(cacheKey, function (err) {
        _this.debug("Deleting " + cacheKey + " and retrying obtainToken..");
        callback(err);
    });
};

/**
 * Get scope information for a user
 * @param guid
 * @param token
 * @param callback
 */
PersonaClient.prototype.getScopesForUser = function(guid, token, callback) {
    try {
        _.map([guid, token], function (arg) {
            if (!_.isString(arg)) {
                throw "guid and token are required strings";
            }
        });
    } catch (e) {
        callback(e,null);
        return;
    }

    var _this = this;

    var options = {
            hostname: _this.config.persona_host,
            port: _this.config.persona_port,
            path: "/1/clients/" + guid,
            method: 'GET',
            headers: {
                Authorization: "Bearer " + token,
            },
        },
        req = _this.http.request(options, function (resp) {
            if (resp.statusCode === 200) {
                var str = '';

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

                    if (data && data.scope) {
                        callback(null, data.scope);
                    } else if (data && data.error) {
                        callback(data.error, null);
                    } else {
                        callback("Could not get Scopes for Guid", null);
                    }
                });
            } else {
                var err = "getScopesForUser failed with status code " + resp.statusCode;
                _this.error(err);
                callback(err, null);
            }
        });

    req.on("error", function (e) {
        var err = "getScopesForUser problem: " + e.message;
        _this.error(err);
        callback(err, null);
    });

    req.end();
};

/**
 * Helper method to set the scopes for a user - can add or remove a scope by passing scopeChange appropriately
 * @param guid
 * @param token
 * @param scopeChange
 * @param callback
 */
PersonaClient.prototype._setScopesForUser = function(guid, token, scopeChange, callback) {
    try {
        _.map([guid, token], function (arg) {
            if (!_.isString(arg)) {
                throw "guid, token are required strings";
            }
        });

        if (!scopeChange) {
            throw "scopeChange is required";
        }
    } catch (e) {
        callback(e, null);
        return;
    }

    var _this = this;

    var options = {
            hostname: _this.config.persona_host,
            port: _this.config.persona_port,
            path: "/1/clients/" + guid,
            method: 'PATCH',
            json: true,
            headers: {
                Authorization: "Bearer " + token,
                'Content-Type': 'application/json',
            },
        },
        req = _this.http.request(options, function (resp) {
            var data = "";

            resp.on('data', function (chunk) {
                data += chunk;
            });

            resp.on('end', function(){
                var err = null;

                // call to set scopes returns 204 if successful
                if (resp.statusCode !== 204) {
                    err = "setScopesForUser failed with status code " + resp.statusCode;
                    _this.error(err);
                }

                callback(err, null);
            });
        });

    req.on("error", function (e) {
        var err = "setScopesForUser problem: " + e.message;
        _this.error(err);
        callback(err, null);
    });

    req.write(JSON.stringify({scope:scopeChange}));
    req.end();
};

/**
 * Add a specific scope to a user
 * @param guid
 * @param token
 * @param scope
 * @param callback
 */
PersonaClient.prototype.addScopeToUser = function(guid, token, scope, callback) {
    try {
        _.map([guid, token, scope], function (arg) {
            if (!_.isString(arg)) {
                throw "guid, token and scope are required strings";
            }
        });
    } catch (e) {
        callback(e, null);
        return;
    }

    var _this = this;
    var scopeChange = {$add:scope};

    _this._setScopesForUser(guid, token, scopeChange, callback);
};

/**
 * Remove a specific scope from a user
 * @param guid
 * @param token
 * @param scope
 * @param callback
 */
PersonaClient.prototype.removeScopeFromUser = function(guid, token, scope, callback) {
    try {
        _.map([guid, token, scope], function (arg) {
            if (!_.isString(arg)) {
                throw "guid, token and scope are required strings";
            }
        });
    } catch (e) {
        callback(e, null);
        return;
    }

    var _this = this;
    var scopeChange = {$remove:scope};

    _this._setScopesForUser(guid, token, scopeChange, callback);
};

/**
 * Log wrapping functions
 * @param severity ( debug or error )
 * @param message
 * @returns {boolean}
 */
PersonaClient.prototype.log = function (severity, message) {
    if (!this.config.enable_debug) {
        return true;
    }

    if (this.config.logger) {
        if (severity === DEBUG) {
            this.config.logger.debug("[persona_client] " + message);
        } else if (severity === ERROR) {
            this.config.logger.error("[persona_client] " + message);
        } else {
            console.log(severity + ": [persona_client] " + message);
        }
    } else {
        console.log(severity + ": [persona_client] " + message);
    }
};

PersonaClient.prototype.debug = function (message) {
    this.log(DEBUG, message);
};
PersonaClient.prototype.error = function (message) {
    this.log(ERROR, message);
};

/**
 * The only way to get an instance of the Persona Client is through
 * this method
 * @param config
 * @returns {PersonaClient}
 */
exports.createClient = function (config) {
    return new PersonaClient(config);
};
