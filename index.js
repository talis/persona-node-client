"use strict";

var cryptojs = require("crypto-js");
var url = require("url");
var querystring = require("querystring");
var _ = require("lodash");
var jwt = require("jsonwebtoken");
var CacheService = require("cache-service");

// log severities
var DEBUG = "debug";
var ERROR = "error";

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
 *
 * optional params:
 * config.enable_debug : true|false
 * config.logger: <pass in a logger that has debug() and error() functions>
 * config.cache: { module: <redis|node-cache>, options: <cache-service-options> }
 *
 * deprecated params:
 * config.redis_host
 * config.redis_port
 * config.redis_db
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
        'persona_oauth_route'
    ];

    for (var i = 0; i < requiredAttributes.length; i++) {
        var attribute = requiredAttributes[i];

        if (this.config[attribute] === undefined) {
            var name = attribute.replace(/_/g, ' ');
            throw new Error("You must specify the " + name);
        }
    }

    var CacheServiceModule;
    var cacheOptions = {};
    var log = this.log.bind(this);

    if(this.config.cache) {
        log("debug", "Using cache module " + this.config.cache.module + " with: " + JSON.stringify(this.config.cache));
        CacheServiceModule = require( "cache-service-" + this.config.cache.module || "node-cache" );
        if (this.config.cache.options) {
            cacheOptions = this.config.cache.options;
        }
    } else if (this.config.redis_host && this.config.redis_port) {
        // Legacy config, set up as redis cache
        log("warn", "Setting cache options via config.redis is deprecated");
        // connect to redis and switch to the configured db
        CacheServiceModule = require("cache-service-redis");
        cacheOptions.redisData = {
            hostname: this.config.redis_host,
            port: this.config.redis_port
        };
    } else  {
        log("warn", "No cache settings defined, using default in-memory cache");
        CacheServiceModule = require("cache-service-node-cache");
    }
    var cacheModule = new CacheServiceModule(cacheOptions);
    this.tokenCache = new CacheService({verbose: this.config.debug}, [cacheModule]);

    // need to instantiate this based on the configured scheme
    this.http = require(this.config.persona_scheme);

    this.debug("Persona Client Created");
};

/**
 * Validate bearer token locally, via JWT verification.
 * @param {string} token -  Token to validate.
 * @param {string=} scope - Optional requested scope that if provided, is also used to validate against.
 * @callback next - Called with either an error as the first param or "ok" as the result in the second param.
 */
PersonaClient.prototype.validateToken = function (token, scope, next) {
    var publicKeyCacheName = "public_key";

    if (!next) {
        throw "No callback (next attribute) provided";
    } else if (typeof next !== "function") {
        throw "Parameter 'next' is not a function";
    }

    if (token == null) {
        return next(ERROR_TYPES.INVALID_TOKEN, null);
    }

    var headScopeThenVerify = function headScope(scope, callback) {
        var log = this.log.bind(this);
        log("debug", "Verifying token against scope " + scope + " via Persona");

        var options = {
            hostname: this.config.persona_host,
            port: this.config.persona_port,
            path: this.config.persona_oauth_route + token + "?scope=" + scope,
            method: "HEAD"
        };

        this.http.request(options, function onSuccess(response) {
            switch(response.statusCode) {
            case 204:
                log("debug", "Verification of token via Persona passed");
                return callback(null, "ok");
            case 401:
                log("debug", "Verification of token via Persona failed");
                return callback(ERROR_TYPES.VALIDATION_FAILURE, null);
            case 403:
                if(scope === "su") {
                    // We tried using su and can go no further
                    log("debug", "Verification of token via Persona failed with insufficient scope");
                    return callback(ERROR_TYPES.INSUFFICIENT_SCOPE, null);
                } else {
                    // Try again with su
                    log("debug", "Verification of token via Persona using scope " + scope + " failed, trying su...");
                    return headScopeThenVerify("su", callback);
                }
                break;
            default:
                log("error", "Error verifying token via Persona: " + response.statusCode);
                return callback(ERROR_TYPES.COMMUNICATION_ISSUE, null);
            }
        }).on("error", function onError(error) {
            log("error", "Verification of token via Persona encountered an unknown error");
            return callback(error, null);
        }).end();
    };
    headScopeThenVerify = headScopeThenVerify.bind(this);

    var verifyToken = function verifyToken(publicKey) {
        var debug = this.debug.bind(this);
        var jwtConfig = {
            algorithms: ["RS256"]
        };

        jwt.verify(token, publicKey, jwtConfig, function onVerify(error, decodedToken) {
            if(error) {
                debug("Verifying token locally failed");
                return next(ERROR_TYPES.VALIDATION_FAILURE, null);
            }

            if(scope && decodedToken.hasOwnProperty("scopeCount")) {
                debug("Token has too many scopes (" + decodedToken.scopeCount + ") to put in payload, asking Persona...");
                return headScopeThenVerify(scope, next);
            } else if (scope == null || _.includes(decodedToken.scopes, "su") || _.includes(decodedToken.scopes, scope)) {
                debug("Verifying token locally passed");
                return next(null, "ok");
            } else {
                debug("Verification of token locally failed with insufficient scope (" + scope + ")");
                return next(ERROR_TYPES.INSUFFICIENT_SCOPE, null);
            }
        });
    };
    verifyToken = verifyToken.bind(this);

    var cachePublicKey = function cachePublicKey(publicKey) {
        // cache the public key for 10 minutes
        var cacheFor = 60 * 10;
        this.debug("Caching public key for " + cacheFor + "s");
        this.tokenCache.set(publicKeyCacheName, publicKey, cacheFor);
    };
    cachePublicKey = cachePublicKey.bind(this);

    var onCacheQueried = function getPublicKeyIfNotInCacheThenVerify(error, publicKey) {
        var log = this.log.bind(this);
        if (publicKey == null) {
            log("debug", "Fetching public key from Persona");
            var options = {
                hostname: this.config.persona_host,
                port: this.config.persona_port,
                path: "/oauth/keys",
                method: "GET"
            };

            this.http.request(options, function onSuccess(response) {
                if(response.statusCode === 200) {
                    var publicKey = "";
                    response.on("data", function onData(chunk) {
                        publicKey += chunk;
                    });
                    response.on("end", function onEnd() {
                        cachePublicKey(publicKey);
                        return verifyToken(publicKey);
                    });
                } else {
                    log("error", "Error fetching public key from Persona: " + response.statusCode);
                    return next(ERROR_TYPES.COMMUNICATION_ISSUE, null);
                }
            }).on("error", function onError(error) {
                log("error", "Fetching public key from Persona encountered an unknown error");
                return next(error, null);
            }).end();
        } else {
            this.debug("Using public key from cache");
            return verifyToken(publicKey);
        }
    };
    this.tokenCache.get(publicKeyCacheName, onCacheQueried.bind(this));
};

/**
 * Express middleware that can be used to verify a token.
 * @param {Object} request - HTTP request object.
 * @param {Object} response - HTTP response object. If you want to validate against a scope (pre-2.0 behavior), provide it as req.params.scope
 * @callback next - Called with either an error as the first param or "ok" as the result in the second param.
 */
PersonaClient.prototype.validateHTTPBearerToken = function (request, response, next) {
    if (arguments.length > 3) {
        throw "Usage: validateHTTPBearerToken(request, response, next)";
    }
    var token = this.getToken(request);
    this.validateToken(token, request.param("scope"), function (error, validationResult) {
        if (!error) {
            next(null, validationResult);
            return;
        }

        switch(error) {
        case ERROR_TYPES.INVALID_TOKEN:
            response.status(401);
            response.json({
                "error": "no_token",
                "error_description": "No token supplied"
            });
            break;
        case ERROR_TYPES.VALIDATION_FAILURE:
            response.status(401);
            response.set("Connection", "close");
            response.json({
                "error": "invalid_token",
                "error_description": "The token is invalid or has expired"
            });
            break;
        case ERROR_TYPES.INSUFFICIENT_SCOPE:
            response.status(403);
            response.set("Connection", "close");
            response.json({
                "error": "insufficient_scope",
                "error_description": "The supplied token is missing a required scope"
            });
            break;
        default:
            response.status(500);
            response.set("Connection", "close");
            response.json({
                "error": "unexpected_error",
                "error_description": error
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
    this.tokenCache.get(cacheKey, function (err, reply) {
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
                    _this.debug(JSON.stringify(resp));
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
                                    _this.tokenCache.set(cacheKey, JSON.stringify(data), cacheFor);
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
                var data;
                if (_.isObject(reply)) {
                    data = reply;
                    reply = JSON.stringify(data);
                } else {
                    data = JSON.parse(reply);
                }
                _this.debug("Found cached token for key " + cacheKey + ": " + reply);

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
PersonaClient.prototype.updateProfile = function(guid, profile, token, callback) {

    try {
        [guid, token].forEach(function checkParamIsString(param) {
            if (!_.isString(param)) {
                throw "guid and token are required strings";
            }
        });
        if (!_.isObject(profile)) {
            throw "profile is a required object";
        }

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
                profile: JSON.stringify(profile)
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
        path: "/users/" + (_.isArray(guid) ? guid.join(",") : guid),
        method: "GET",
        headers: {
            "Authorization": "Bearer " + token
        }
    },
    req = _this.http.request(options, function (resp) {
        if (resp.statusCode === 200) {

            var str = "";
            resp.on("data", function (chunk) {
                str += chunk;
            });
            resp.on("end", function () {
                var data;
                try {
                    data = JSON.parse(str);
                } catch (e) {
                    return callback("Error parsing response from persona: " + str, null);
                }

                if(data) {
                    if (data.error) {
                        return callback(data.error, null);
                    } else {
                        return callback(null, data);
                    }
                }
                return callback("Could not get Profile By Guid", null);
            });
        } else {
            var err = "getProfileByGuid failed with status code " + resp.statusCode;
            _this.error(err);
            return callback(err, null);
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
    _this.tokenCache.del(cacheKey, function (err) {
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
                Authorization: "Bearer " + token
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
                'Content-Type': 'application/json'
            }
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
