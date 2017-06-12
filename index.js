"use strict";

var cryptojs = require("crypto-js");
var url = require("url");
var querystring = require("querystring");
var _ = require("lodash");
var jwt = require("jsonwebtoken");
var CacheService = require("cache-service");
var fs = require("fs");
var uuid = require('uuid');

var clientVer = JSON.parse(fs.readFileSync(__dirname + '/package.json', 'utf8')).version || 'unknown';

var PUBLIC_KEY_CACHE_NAME = "public_key";

// log severities
var DEBUG = "debug";
var ERROR = "error";

var ERROR_TYPES = {
    VALIDATION_FAILURE: 'validation_failure',
    COMMUNICATION_ISSUE: 'communication_issue',
    INVALID_TOKEN: 'invalid_token',
    INSUFFICIENT_SCOPE: 'insufficient_scope',
    INVALID_ARGUMENTS: 'invalid_arguments',
};

/**
 * Validate method opts
 * @param opts
 * @param mandatoryKeys null|array|object a simple array of madatory keys, or key/value where value is a function to validate the value of key in opts
 * @throws Error
 */
var validateOpts = function validateOpts(opts, mandatoryKeys) {
    var error = new Error();
    error.name = ERROR_TYPES.INVALID_ARGUMENTS;

    if (!_.isObject(opts)) {
        throw new Error('Expecting opts to be an object');
    }

    if (_.isArray(mandatoryKeys)) {
        mandatoryKeys.forEach(function eachMandatoryKey(mandatoryKey) {
            if (_.isEmpty(opts[mandatoryKey])) {
                error.message = mandatoryKey + ' in opts cannot be empty';
                throw error;
            }
        });
    } else if (_.isObject(mandatoryKeys)) {
        _.keysIn(mandatoryKeys).forEach(function eachMandatoryKey(mandatoryKey) {
            var validationFn = mandatoryKeys[mandatoryKey];
            if (_.isEmpty(opts[mandatoryKey])) {
                error.message = mandatoryKey + ' in opts cannot be empty';
                throw error;
            } else if (!validationFn(opts[mandatoryKey])) {
                error.message = mandatoryKey + ' failed ' + validationFn.name + ' validation';
                throw error;
            }
        });
    } else {
        error.message = 'mandatoryKeys must be empty, array or object';
        throw error;
    }
};

/**
 * Constructor you must pass in an appId string identifying your app, plus an optional config object with the
 * following properties set:
 *
 * optional params:
 * config.persona_host = string, defaults to "users.talis.com";
 * config.persona_port = string|integer, defaults to 443;
 * config.persona_scheme = string, defaults to "https";
 * config.persona_oauth_route = string, defaults to "/oauth/tokens/";
 * config.enable_debug : true|false
 * config.logger: <pass in a logger that has debug() and error() functions>
 * config.cache: { module: <redis|node-cache>, options: <cache-service-options> }
 * config.cert_background_refresh: true|false defaults to true
 * config.cert_timeout_sec: int, defaults to 600
 *
 * deprecated params:
 * config.redis_host
 * config.redis_port
 * config.redis_db
 *
 * This library stores no default configuration of its own. It relies on the application/service
 * it is embedded in to supply this information.
 *
 * @param appUA an identifying user agent string for your app, compatible with user agent formatting
 * as per https://tools.ietf.org/html/rfc7231#section-5.5.3 e.g. 'my-app', 'my-app/0.1',
 * 'my-app/0.1 (Ubuntu/12.04; nodejs/0.10.13)`
 * @param config object containing config
 * @constructor
 */
var PersonaClient = function (appUA, config) {
    if (!_.isString(appUA)) {
        throw new Error("Expected string appId as first parameter");
    }

    // establish config, including defaults
    this.config = config || {};
    if (!_.has(this.config,"cert_timeout_sec")) {
        this.config.cert_timeout_sec = 600;
    } else {
        this.config.cert_timeout_sec = parseInt(this.config.cert_timeout_sec,10);
        if (_.isNaN(this.config.cert_timeout_sec)) {
            throw new Error("Cert config timeout could not be parsed as integer");
        }
    }

    // now set refresh interval ms to be equal or just under cert timeout sec
    this.pk_auto_refresh_timeout_ms =  (this.config.cert_timeout_sec>10) ? (this.config.cert_timeout_sec - 10) * 1000 : this.config.cert_timeout_sec * 1000;

    this.userAgent = (process && _.has(process,["version","env.NODE_ENV"])) ? appUA+
      " persona-node-client/"+clientVer+" (nodejs/"+process.version+"; NODE_ENV="+
      process.env.NODE_ENV+")" : appUA + " persona-node-client/"+clientVer;

    // default connection config
    _.merge({
        persona_host: "users.talis.com",
        persona_port: 443,
        persona_scheme: "https",
        persona_oauth_route: "/oauth/tokens/"
    },this.config);

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

    if (this.config.cert_background_refresh !== false) {
        this._getPublicKey(function retrievedCert() {
            this.refreshTimerId = setInterval(function refreshCert() {
                this._getPublicKey(function retrievedPublicKey() {
                    log('debug', 'retrieved public key');
                }, true);
            }.bind(this), this.pk_auto_refresh_timeout_ms);
        }.bind(this),true);
    }

    this.log('debug', "Persona Client Created");
};

/**
 * Retrieve Persona's public key that is used to sign the JWTs.
 * @param {callback} cb function(err, publicCert)
 * @param {boolean=} refresh (optional) refresh the public key
 * @private
 */
PersonaClient.prototype._getPublicKey = function getPublicKey(cb, refresh, xRequestId) {
    var log = this.log.bind(this);

    var cachePublicKey = function cachePublicKey(publicKey) {
        log('debug', 'Caching public key for ' + this.config.cert_timeout_sec + 's');
        this.tokenCache.set(PUBLIC_KEY_CACHE_NAME, publicKey, this.config.cert_timeout_sec);
    }.bind(this);

    var getCachedPublicKey = function getCachedPublicKey(cb) {
        this.tokenCache.get(PUBLIC_KEY_CACHE_NAME, function getPublicKeyIfNotInCacheThenVerify(error, publicKey) {
            if (_.isString(publicKey)) {
                log('debug', 'Using public key from cache');
                return cb(publicKey);
            }

            return cb(null);
        });
    }.bind(this);

    var getRemotePublicKey = function getRemotePublicKey(cb) {
        var options = {
            hostname: this.config.persona_host,
            port: this.config.persona_port,
            path: '/oauth/keys',
            method: 'GET',
            headers: {
                'User-Agent': this.userAgent,
                'X-Request-Id': xRequestId || uuid.v4()
            }
        };

        log('debug', 'Fetching public key from Persona');
        this.http.request(options, function onResponse(response) {
            var publicKey = '';

            if (response.statusCode !== 200) {
                log('error', 'Error fetching public key from Persona: ' + response.statusCode);
                return cb(ERROR_TYPES.COMMUNICATION_ISSUE, null);
            }

            response.on('data', function onData(chunk) {
                publicKey += chunk;
            });

            response.on('end', function onEnd() {
                cachePublicKey(publicKey);
                return cb(null, publicKey);
            });
        }).on('error', function onError(error) {
            log('error', 'Fetching public key from Persona encountered an unknown error');
            return cb(error, null);
        }).end();
    }.bind(this);

    if (refresh === true) {
        getRemotePublicKey(function retrievedPublicKey(err, publicKey) {
            if (err) {
                return cb(err, null);
            }

            return cb(null, publicKey);
        });
    } else {
        getCachedPublicKey(function retrieveKey(publicKey) {
            if (publicKey) {
                return cb(null, publicKey);
            }

            getRemotePublicKey(function retrievedPublicKey(err, updatedPublicKey) {
                return cb(err, updatedPublicKey);
            });
        });
    }
};

/**
 * Validate bearer token locally, via JWT verification.
 * @param {object} opts - Options object, must include token to validate, and optionally scope to
 * validate against, and optional xRequestId to pass through.
 * @callback next - Called with the following arguments:
 * 1st argument: an error string (see errorTypes) if validation failed for any reason otherwise
 * null.
 * 2nd argument: "ok" if validation passed otherwise null.
 * 3rd argument: The decoded JWT or null if there was no/invalid token or there was a problem
 * validating.
 */
PersonaClient.prototype.validateToken = function (opts, next) {
    validateOpts(opts,['token']);
    var token = opts.token;
    var scope = opts.scope;
    var xRequestId = opts.xRequestId || uuid.v4();

    if (!next) {
        throw "No callback (next attribute) provided";
    } else if (typeof next !== "function") {
        throw "Parameter 'next' is not a function";
    }

    if (token == null) {
        return next(ERROR_TYPES.INVALID_TOKEN, null);
    }

    var headScopeThenVerify = function headScope(scope, callback, decodedToken) {
        var scopes = scope == 'su' ? 'su' : 'su,' + scope;
        var log = this.log.bind(this);

        log("debug", "Verifying token against scope " + scope + " via Persona");

        var options = {
            hostname: this.config.persona_host,
            port: this.config.persona_port,
            path: this.config.persona_oauth_route + token + "?scope=" + scopes,
            method: "HEAD",
            headers: {
                'User-Agent': this.userAgent,
                'X-Request-Id': xRequestId
            }
        };

        this.http.request(options, function onSuccess(response) {
            switch(response.statusCode) {
            case 204:
                log("debug", "Verification of token via Persona passed");
                return callback(null, "ok", decodedToken);
            case 401:
                log("debug", "Verification of token via Persona failed");
                return callback(ERROR_TYPES.VALIDATION_FAILURE, null, decodedToken);
            case 403:
                log("debug", "Verification of token via Persona failed with insufficient scope");
                return callback(ERROR_TYPES.INSUFFICIENT_SCOPE, null, decodedToken);
            default:
                log("error", "Error verifying token via Persona: " + response.statusCode);
                return callback(ERROR_TYPES.COMMUNICATION_ISSUE, null, decodedToken);
            }
        }).on("error", function onError(error) {
            log("error", "Verification of token via Persona encountered an unknown error");
            return callback(error, null, decodedToken);
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
                return next(ERROR_TYPES.VALIDATION_FAILURE, null, decodedToken);
            }

            if(scope && decodedToken.hasOwnProperty("scopeCount")) {
                debug("Token has too many scopes (" + decodedToken.scopeCount + ") to put in payload, asking Persona...");
                return headScopeThenVerify(scope, next, decodedToken);
            } else if (scope == null || _.includes(decodedToken.scopes, "su") || _.includes(decodedToken.scopes, scope)) {
                debug("Verifying token locally passed");
                return next(null, "ok", decodedToken);
            } else {
                debug("Verification of token locally failed with insufficient scope (" + scope + ")");
                return next(ERROR_TYPES.INSUFFICIENT_SCOPE, null, decodedToken);
            }
        });
    }.bind(this);

    this._getPublicKey(function retrievedPublicKey(err, publicKey) {
        if (err) {
            return next(err, null, null);
        }

        return verifyToken(publicKey);
    },false,xRequestId);
};

/**
 * Express middleware that can be used to verify a token.
 * @param {Object} request - HTTP request object.
 * @param {Object} response - HTTP response object. If you want to validate against a scope (pre-2.0 behavior), provide it as req.params.scope
 * @callback next - Called with the following arguments:
 * 1st argument: an error string (see errorTypes) if validation failed for any reason otherwise
 * null.
 * 2nd argument: "ok" if validation passed otherwise null.
 * 3rd argument: The decoded JWT or null if there was no/invalid token or there was a problem
 * validating.
 */
PersonaClient.prototype.validateHTTPBearerToken = function validateHTTPBearerToken(request, response, next) {
    var config = {
        token: this._getToken(request),
        scope: request.param('scope'),
        xRequestId: this.getXRequestId(request),
    };

    if (arguments.length > 3) {
        throw new Error('Usage: validateHTTPBearerToken(request, response, next)');
    }

    function callback(error, validationResult, decodedToken) {
        if (!error) {
            next(null, validationResult, decodedToken);
            return;
        }

        switch (error) {
        case ERROR_TYPES.INVALID_TOKEN:
            response.status(401);
            response.json({
                'error': 'no_token',
                'error_description': 'No token supplied',
            });
            break;
        case ERROR_TYPES.VALIDATION_FAILURE:
            response.status(401);
            response.set('Connection', 'close');
            response.json({
                'error': 'invalid_token',
                'error_description': 'The token is invalid or has expired',
            });
            break;
        case ERROR_TYPES.INSUFFICIENT_SCOPE:
            response.status(403);
            response.set('Connection', 'close');
            response.json({
                'error': 'insufficient_scope',
                'error_description': 'The supplied token is missing a required scope',
            });
            break;
        default:
            response.status(500);
            response.set('Connection', 'close');
            response.json({
                'error': 'unexpected_error',
                'error_description': 'Unexpected error occurred',
            });
        }

        next(error, null, decodedToken);
        return;
    }

    try {
        this.validateToken(config, callback);
    } catch (exception) {
        if (exception.name === ERROR_TYPES.INVALID_ARGUMENTS) {
            return callback(ERROR_TYPES.INVALID_TOKEN, null, null);
        }

        return callback(exception.message, null, null);
    }
};

/**
 * Extract a token from the request - try the header first, followed by the request params
 * @param req
 * @return {*}
 * @private
 */
PersonaClient.prototype._getToken = function (req) {
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
 * @deprecated since version 3.0.0
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
 * @deprecated since version 3.0.0
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
 * @param opts array, id and secret are mandatory, xRequestId is optional
 * @param callback
 */
PersonaClient.prototype.obtainToken = function (opts, callback) {
    validateOpts(opts,["id","secret"]);
    var id = opts.id;
    var secret = opts.secret;
    var xRequestId = opts.xRequestId || uuid.v4();

    var _this = this;
    var cacheKey = "obtain_token:" + cryptojs.HmacSHA256(id, secret);

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
                            'Content-Length': post_data.length,
                            'User-Agent': _this.userAgent,
                            'X-Request-Id': xRequestId
                        }
                    };
                var req = _this.http.request(options, function (resp) {
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
                        _this.obtainToken({id: id, secret: secret, xRequestId: xRequestId}, callback);
                    }
                });
            }
        }
    });

};

/**
 * Request an application authorization (client_id/secret pair) for a user with guid, authing with id and secret.
 * Use title to describe the purpose.
 * @param opts array, mandatory params are guid, title, id, secret; optional params xRequestId
 * @param callback
 */
PersonaClient.prototype.requestAuthorization = function (opts, callback) {
    validateOpts(opts,{"guid": _.isString,"title": _.isString,"id": _.isString,"secret": _.isString});
    var guid = opts.guid;
    var title = opts.title;
    var id = opts.id;
    var secret = opts.secret;
    var xRequestId = opts.xRequestId || uuid.v4();

    var _this = this;
    _this.obtainToken ({id: id,secret: secret, xRequestId: xRequestId},function (err,token) { // todo: push down into person itself. You should be able to request an authorization using basic auth with client id/secret
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
                        'Content-Length': post_data.length,
                        'User-Agent': _this.userAgent,
                        'X-Request-Id': xRequestId
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
 * Delete the authorization defined by opts.authorizationClientId, using id and secret to auth
 * @param opts array, mandatory keys are authorizationClientId, id and secret; optional xRequestId
 * @param callback
 */
PersonaClient.prototype.deleteAuthorization = function (opts, callback) {
    validateOpts(opts,{guid: _.isString,authorizationClientId: _.isString,id: _.isString,secret: _.isString});
    var guid = opts.guid;
    var authorizationClientId = opts.authorizationClientId;
    var id = opts.id;
    var secret = opts.secret;
    var xRequestId = opts.xRequestId || uuid.v4();

    var _this = this;
    _this.obtainToken({id: id,secret: secret, xRequestId: xRequestId},function (err,token) { // todo: push down into person itself. You should be able to request an authorization using basic auth with client id/secret
        if (err) {
            callback("Request authorization failed with error: "+err);
        } else {
            var options = {
                    hostname: _this.config.persona_host,
                    port: _this.config.persona_port,
                    path: '/oauth/users/' + guid + '/authorizations/' + authorizationClientId,
                    method: 'DELETE',
                    headers: {
                        'Authorization': 'Bearer ' + token.access_token,
                        'Content-Type': 'application/json',
                        'Content-Length': 0,
                        'User-Agent': _this.userAgent,
                        'X-Request-Id': xRequestId
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
 * @param {object} opts object, madatory: profile, token, guid; optional: xRequestId
 * @param {function} callback
 * @callback callback
 */
PersonaClient.prototype.updateProfile = function(opts, callback) {
    validateOpts(opts,{guid: _.isString, token: _.isString, profile: _.isObject});
    var guid = opts.guid;
    var profile = opts.profile;
    var token = opts.token;
    var xRequestId = opts.xRequestId || uuid.v4();

    var _this = this;
    // Get a profile
    var profileData = JSON.stringify(profile),
        options = {
            hostname: _this.config.persona_host,
            port: _this.config.persona_port,
            path: '/users/' + guid + '/profile',
            method: 'PUT',
            headers: {
                'Authorization': 'Bearer ' + token,
                'User-Agent': _this.userAgent,
                'X-Request-Id': xRequestId
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
 * @param {object} opts - mandatory guid and token; optional xRequestId
 * @param {function} callback
 * @callback callback
 */
PersonaClient.prototype.getProfileByGuid = function(opts, callback){
    validateOpts(opts,{guid: _.isString,token: _.isString});
    var guid = opts.guid;
    var token = opts.token;
    var xRequestId = opts.xRequestId || uuid.v4();

    var _this = this;
    // Get a profile
    var options = {
        hostname: _this.config.persona_host,
        port: _this.config.persona_port,
        path: "/users/" + (_.isArray(guid) ? guid.join(",") : guid),
        method: "GET",
        headers: {
            "Authorization": "Bearer " + token,
            'User-Agent': _this.userAgent,
            'X-Request-Id': xRequestId
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
 * Get all profiles for an array of GUIDs.
 *
 * TODO Neither the client lib nor Persona impose restriction on amount of GUIDs requested. Limit in calling app for now.
 *
 * @param  {object}   opts     [description]
 * @param  {array}    opts.guids  Array of GUIDs to fetch profiles for
 * @param  {string}   opts.token  Auth token
 * @param  {string}   opts.xRequestId Optional request ID to pass through in logging.
 * @param  {Function} callback
 */
PersonaClient.prototype.getProfilesForGuids = function getProfilesForGuids(opts, callback) {
    validateOpts(opts,{ guids: _.isArray, token: _.isString });
    var log = this.log.bind(this);
    var guids = opts.guids;
    var token = opts.token;
    var xRequestId = opts.xRequestId || uuid.v4();
    var _this = this;

    var ids = guids.join(',');

    var options = {
        hostname: _this.config.persona_host,
        port: _this.config.persona_port,
        path: '/users?guids=' + ids,
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + token,
            'User-Agent': _this.userAgent,
            'X-Request-Id': xRequestId
        }
    };

    var personaReq = _this.http.request(options, function personaReq(personaResp) {
        var userString = '';

        personaResp.on('data', function onData(chunk) {
            userString += chunk;
        });

        personaResp.on('end', function onEnd() {
            if (personaResp.statusCode === 200) {
                var data = JSON.parse(userString);
                var results = [];
                if (!_.isEmpty(data)) {
                    if (_.isArray(data)) {
                        results = data;
                    } else {
                        results.push(data);
                    }
                }
                callback(null, results);
            } else {
                var error = new Error();
                var statusCode = personaResp.statusCode || 0;
                error.http_code = statusCode;
                log('error', 'getProfilesForGuids failed with status code ' + statusCode);
                callback(error, null);
            }
        });
    });

    personaReq.on('error', function (err) {
        callback(err, null);
    });

    personaReq.on('clientError', function (err) {
        callback(err, null);
    });

    personaReq.end();
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
 * @param {object} opts mandatory: guid, token; optional: xRequestId
 * @param {function} callback
 * @param callback
 */
PersonaClient.prototype.getScopesForUser = function(opts, callback) {
    validateOpts(opts,{guid: _.isString,token: _.isString});
    var guid = opts.guid;
    var token = opts.token;
    var xRequestId = opts.xRequestId || uuid.v4();

    var _this = this;

    var options = {
            hostname: _this.config.persona_host,
            port: _this.config.persona_port,
            path: "/1/clients/" + guid,
            method: 'GET',
            headers: {
                Authorization: "Bearer " + token,
                'User-Agent': _this.userAgent,
                'X-Request-Id': xRequestId
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
 * @param xRequestId
 * @param callback
 */
PersonaClient.prototype._applyScopeChange = function(guid, token, scopeChange, xRequestId, callback) {
    if (_.isFunction(xRequestId)) {
        callback = xRequestId; // third param is actually next(), for backwards compat.
        xRequestId = uuid.v4();
    }

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
                'User-Agent': _this.userAgent,
                'X-Request-Id': xRequestId
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
 * @param {object} opts mandatory: guid, token, scope; optional: xRequestId
 * @param {function} callback
 * @param callback
 */
PersonaClient.prototype.addScopeToUser = function(opts, callback) {
    validateOpts(opts,{guid: _.isString,token: _.isString,scope: _.isString});

    var guid = opts.guid;
    var token = opts.token;
    var scope = opts.scope;
    var xRequestId = opts.xRequestId || uuid.v4();

    var _this = this;
    var scopeChange = {$add:scope};

    _this._applyScopeChange(guid, token, scopeChange, xRequestId, callback);
};

/**
 * Remove a specific scope from a user
 * @param {object} opts mandatory: guid, token, scope; optional: xRequestId
 * @param {function} callback
 * @param callback
 */
PersonaClient.prototype.removeScopeFromUser = function(opts, callback) {
    validateOpts(opts,{guid: _.isString,token: _.isString,scope: _.isString});

    var guid = opts.guid;
    var token = opts.token;
    var scope = opts.scope;
    var xRequestId = opts.xRequestId || uuid.v4();

    var _this = this;
    var scopeChange = {$remove:scope};

    _this._applyScopeChange(guid, token, scopeChange, xRequestId, callback);
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
 * @param req Request||null
 * @returns {*}
 */
PersonaClient.prototype.getXRequestId = function(req) {
    if (_.has(req,"header") && _.isFunction(req.header) && _.isString(req.header('X-Request-Id'))) {
        return req.header('X-Request-Id');
    } else {
        return uuid.v4();
    }
};

exports.errorTypes = ERROR_TYPES;

/**
 * The only way to get an instance of the Persona Client is through
 * this method
 * @param appUA
 * @param config
 * @returns {PersonaClient}
 */
exports.createClient = function (appUA,config) {
    return new PersonaClient(appUA,config);
};
