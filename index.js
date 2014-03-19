'use strict';

var cryptojs = require('crypto-js');
var url = require('url');
var querystring = require('querystring');

// log severities
var DEBUG = "debug";
var ERROR = "error";

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
    this.config = config = config || {};

    //TODO: find a less verbose way of doing this

    if (this.config.persona_host === undefined) {
        throw new Error("You must specify the Persona server host");
    }
    if (this.config.persona_port === undefined) {
        throw new Error("You must specify the Persona server port");
    }
    if (this.config.persona_scheme === undefined) {
        throw new Error("You must specify the Persona server scheme (http/https)");
    }
    if (this.config.persona_oauth_route === undefined) {
        throw new Error("You must specify the Persona oauth route");
    }

    if (this.config.redis_host === undefined) {
        throw new Error("You must specify the Redis host to use as a cache");
    }
    if (this.config.redis_port === undefined) {
        throw new Error("You must specify the Redis port");
    }
    if (this.config.redis_db === undefined) {
        throw new Error("You must specify the Redis db");
    }
    // connect to redis and switch to the configured db
    var redis = require('redis');
    this.redisClient = redis.createClient(this.config.redis_port, this.config.redis_host);
    this.redisClient.select(this.config.redis_db);

    // need to instantiate this based on the configured scheme
    this.http = require(this.config.persona_scheme);


    this.debug("Persona Client Created");
};

PersonaClient.prototype.validateToken = function (req, res, next) {
    var token = this.getToken(req),
        _this = this;

    if (token == null) {
        res.status(401);
        res.json({
            "error": "no_token",
            "error_description": "No token supplied"
        });
        throw "OAuth validation failed for " + token;
    }

    // if we were given a scope then append the scope to the token to create a cachekey
    var cacheKey = token;
    if (req.param("scope")) {
        cacheKey += "@" + req.param("scope");
    }

    this.debug("Validating token: " + cacheKey);

    this.redisClient.get("access_token:" + cacheKey, function (err, reply) {
        if (reply === "OK") {
            _this.debug("Token " + cacheKey + " verified by cache");
            next(null, "verified_by_cache");
        } else {

            var requestPath = _this.config.persona_oauth_route + token;
            if (req.param("scope")) {
                requestPath += "?scope=" + req.param("scope");
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
                    next(null, "verified_by_persona");
                } else {
                    _this.debug("Verification failed for token " + cacheKey + " with status code " + oauthResp.statusCode);
                    res.status(401);
                    res.set("Connection", "close");
                    res.json({
                        "error": "invalid_token",
                        "error_description": "The token is invalid or has expired"
                    });
                }
            }).on("error", function (e) {
                _this.error("OAuth::validateToken problem: " + e.message);
                res.status(500);
                res.set("Connection", "close");
                res.json({
                    "error": "unexpected_error",
                    "error_description": e.message
                });
            }).end();
        }
    });

};

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
 * @param expiry
 * @param callback
 */
PersonaClient.prototype.presignUrl = function(urlToSign, secret, expiry, callback){
    if(!urlToSign){
        throw new Error("You must provide a URL to sign");
    }
    if(!secret){
        throw new Error("You must provide secret with which to sign the url");
    }

    if(!expiry){
        expiry = new Date().getTime() + 900; // 15 minutes
    }

    var parsedURL = url.parse(urlToSign);
    var parsedQuery = querystring.parse(parsedURL.query);

    if(!parsedQuery.expiry){
        var expParam = urlToSign.indexOf("?") ? "&expiry=" + expiry : "?expiry=" + expiry;
        if(urlToSign.indexOf('#') !== -1){
            urlToSign = urlToSign.replace("#", ''+expParam+'#');
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
PersonaClient.prototype.isPresignedUrlValid = function(presignedUrl, secret, callback) {
    if(!presignedUrl){
        throw new Error("You must provide a URL to validate");
    }
    if(!secret){
        throw new Error("You must provide secret with which to validate the url");
    }

    // we need to ensure we have a URL passed over
    var parsedURL = url.parse(presignedUrl);
    var parsedQuery = querystring.parse(parsedURL.query);
    var signature = parsedQuery.signature;
    var expiry = parsedQuery.expiry;

    if (signature) {
        // replace the signature im the URL...the original secret will have been created from the full URL WITHOUT the signature (obviously!)
        var presignedUrlMinusSignature = presignedUrl.replace('&signature=' + signature, '');

        // generate a hash by re-signing the fullURL we where passed but with the 'signature' parameter removed
        var hash = cryptojs.HmacSHA256(presignedUrlMinusSignature, secret);

        // check if the hash we created matches the passed signature
        if (hash.toString() === signature) {

            if (expiry) {
                if (expiry < new Date().getTime()) {
                    return callback({error: "invalid_request", error_description: "presigned url has expired"}, null);
                }
            } else {
                return callback({error: "invalid_request", error_description: "presigned url has no expiry parameter"}, null);
            }

            var message = {
                message: 'success',
                description: 'Presigned URL is valid'
            };

            return callback(null, message);
        } else {
            return callback({error: "invalid_request", error_description: "invalid URL"}, null);
        }
    } else {
        return callback({error: "invalid_request", error_description: "no signature parameter found on URL"}, null);
    }
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