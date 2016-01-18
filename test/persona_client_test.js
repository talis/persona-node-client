'use strict';

var async = require('async');
var should = require('should');
var assert = require('assert');
var persona = require('../index.js');
var _getOAuthToken = require('./utils')._getOAuthToken;
var _getStubRequest = require('./utils')._getStubRequest;
var _getStubResponse = require('./utils')._getStubResponse;
var cryptojs = require('crypto-js');
var sinon = require('sinon');
var _ = require("lodash");
// This is for mocking out some http responses in some tests
var PassThrough = require('stream').PassThrough;
describe("Persona Client Test Suite", function(){

    describe("- Constructor tests", function(){

        it("should throw error if config.persona_host is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({});
            };
            personaClient.should.throw("You must specify the persona host");
            done();
        });
        it("should throw error if config.persona_port is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({persona_host:"persona"});
            };
            personaClient.should.throw("You must specify the persona port");
            done();
        });
        it("should throw error if config.persona_scheme is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80
                });
            };
            personaClient.should.throw("You must specify the persona scheme");
            done();
        });
        it("should throw error if config.persona_oauth_route is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http"
                });
            };
            personaClient.should.throw("You must specify the persona oauth route");
            done();
        });
        it("should throw error if config.redis_host is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens"
                });
            };
            personaClient.should.throw("You must specify the redis host");
            done();
        });
        it("should throw error if config.redis_port is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens",
                    redis_host:"persona"
                });
            };
            personaClient.should.throw("You must specify the redis port");
            done();
        });
        it("should throw error if config.redis_db is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens",
                    redis_host:"persona",
                    redis_port:6379
                });
            };
            personaClient.should.throw("You must specify the redis db");
            done();
        });
        it("should NOT throw any error if all config params are defined", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens",
                    redis_host:"persona",
                    redis_port:6379,
                    redis_db:0
                });
            };
            personaClient.should.not.throw();
            done();
        });
    });

    describe("- Generate and Validate Presigned Url Tests", function(){

        var secret = "canyoukeepasecret";

        it("should throw error if no URL is provided to sign", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var presignUrl = function(){
                return personaClient.presignUrl(null, secret, null, function(err, result){});
            };

            presignUrl.should.throw("You must provide a URL to sign");
            done();

        });

        it("should throw error if no secret is provided to sign with", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var urlToSign = 'http://192.168.10.62:3000/player?shortcode=google&expires=1395160411633';

            var presignUrl = function(){
                return personaClient.presignUrl(urlToSign, null, null, function(err, result){});
            };

            presignUrl.should.throw("You must provide a secret with which to sign the url");
            done();

        });

        it("should generate presigned URL", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });
            
            var urlToSign = 'http://192.168.10.62:3000/player?shortcode=google&expires=1395160411633';
            var expectedHash = cryptojs.HmacSHA256(urlToSign, secret);

            personaClient.presignUrl(urlToSign, secret, null, function(err, result){
                if(err) return done(err);

                result.should.equal('http://192.168.10.62:3000/player?shortcode=google&expires=1395160411633&signature='+expectedHash);
                done();
            });

        });

        it("should generate presigned URL and add default expiry", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var urlToSign = 'http://192.168.10.62:3000/player?shortcode=google';

            personaClient.presignUrl(urlToSign, secret, null, function(err, result){
                if(err) return done(err);

                result.should.contain('&expires=');
                done();
            });

        });

        it("should generate presigned URL and add passed expiry", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var urlToSign = 'http://192.168.10.62:3000/player?shortcode=google';

            var baseUrl = 'http://192.168.10.62:3000/player?shortcode=google';
            var expiry = new Date().getTime() + 86400;

            var urlWithExp = baseUrl + '&expires=' + expiry;

            var expectedHash = cryptojs.HmacSHA256(urlWithExp, secret);

            var expectedURL = baseUrl + '&expires=' + expiry + '&signature=' + expectedHash;

            personaClient.presignUrl(urlToSign, secret, expiry, function(err, result){
                if(err) return done(err);

                result.should.equal(expectedURL);
                done();
            });

        });

        it("should generate presigned URL that has hash component", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var urlToSign = 'http://192.168.10.62:3000/player?shortcode=google&expires=1395160411633#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
            var expectedHash = cryptojs.HmacSHA256(urlToSign, secret);
            var expectedUrl = 'http://192.168.10.62:3000/player?shortcode=google&expires=1395160411633&signature=' + expectedHash + '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';

            personaClient.presignUrl(urlToSign, secret, null, function(err, result){
                if(err) return done(err);

                result.should.equal(expectedUrl);

                done();
            });

        });

        it("should generate presigned URL that has hash component and add default expiry", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var urlHash = '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
            var urlToSign = 'http://192.168.10.62:3000/player?shortcode=google' + urlHash;

            personaClient.presignUrl(urlToSign, secret, null, function(err, result){
                if(err) return done(err);

                result.should.contain('&expires=');
                result.should.contain(urlHash);

                done();
            });

        });

        it("should generate presigned URL that has hash component and add passed expiry", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var urlHash = '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
            var baseUrl = 'http://192.168.10.62:3000/player?shortcode=google';
            var urlToSign = baseUrl + urlHash;
            var expiry = new Date().getTime() + 86400;

            var urlWithExp = baseUrl + '&expires=' + expiry + urlHash;

            var expectedHash = cryptojs.HmacSHA256(urlWithExp, secret);

            var expectedURL = baseUrl + '&expires=' + expiry + '&signature=' + expectedHash + urlHash;

            personaClient.presignUrl(urlToSign, secret, expiry, function(err, result){
                if(err) return done(err);

                result.should.equal(expectedURL);

                done();
            });

        });

        it("should throw error if no presigned URL is provided to validate", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var validateUrl = function(){
                return personaClient.isPresignedUrlValid(null, secret);
            };

            validateUrl.should.throw("You must provide a URL to validate");
            done();

        });

        it("should throw error if no secret is provided to validate", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var urlToValidate = 'http://192.168.10.62:3000/player?shortcode=google&expires=1395229157990&signature=ae1ef4f1f2e8a45643e51ab34cc1d08dd627f5bb6e9569b84bcce622040a41fb#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';

            var validateUrl = function(){
                return personaClient.isPresignedUrlValid(urlToValidate, null);
            };

            validateUrl.should.throw("You must provide a secret with which to validate the url");
            done();

        });

        it("should validate a presigned URL with no querystring or hash parameters", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var baseUrl = 'http://192.168.10.62:3000/player';
            var expiry = new Date().getTime() + 86400;

            var urlWithExp = baseUrl + '?expires=' + expiry;

            var hash = cryptojs.HmacSHA256(urlWithExp, secret);

            var urlToValidate = baseUrl + '?expires=' + expiry + '&signature=' + hash;

            var result = personaClient.isPresignedUrlValid(urlToValidate, secret);

            result.should.equal(true);

            done();
        });

        it("should validate a presigned URL", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var urlHash = '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
            var baseUrl = 'http://192.168.10.62:3000/player?shortcode=google';
            var urlToSign = baseUrl + urlHash;
            var expiry = new Date().getTime() + 86400;

            var urlWithExp = baseUrl + '&expires=' + expiry + urlHash;

            var hash = cryptojs.HmacSHA256(urlWithExp, secret);

            var urlToValidate = baseUrl + '&expires=' + expiry + '&signature=' + hash + urlHash;

            var result = personaClient.isPresignedUrlValid(urlToValidate, secret);

            result.should.equal(true);

            done();
        });

        it("should validate a presigned URL has an expiry", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var urlHash = '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
            var baseUrl = 'http://192.168.10.62:3000/player?shortcode=google';
            var urlToSign = baseUrl + urlHash;
            var hash = cryptojs.HmacSHA256(urlToSign, secret);

            var urlToValidate = baseUrl + '&signature=' + hash + urlHash;

            var result = personaClient.isPresignedUrlValid(urlToValidate, secret);

            result.should.equal(false);

            done();
        });

        it("should validate a presigned URL has expired", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var urlHash = '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
            var baseUrl = 'http://192.168.10.62:3000/player?shortcode=google';
            var urlToSign = baseUrl + urlHash;
            var expiry = Math.floor(new Date().getTime()/1000) - 5;

            var urlWithExp = baseUrl + '&expires=' + expiry + urlHash;

            var hash = cryptojs.HmacSHA256(urlWithExp, secret);

            var urlToValidate = baseUrl + '&expires=' + expiry + '&signature=' + hash + urlHash;

            var result = personaClient.isPresignedUrlValid(urlToValidate, secret);

            result.should.equal(false);

            done();
        });

        it("should validate a presigned URL is invalid", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var urlHash = '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
            var baseUrl = 'http://192.168.10.62:3000/player?shortcode=google';
            var urlToSign = baseUrl + urlHash;
            var expiry = new Date().getTime() + 86400;

            var urlWithExp = baseUrl + '&expiry=' + expiry + urlHash + '23'; // add additional data that will cause an invalid hash to be generated

            var hash = cryptojs.HmacSHA256(urlWithExp, secret);

            var urlToValidate = baseUrl + '&expiry=' + expiry + '&signature=' + hash + urlHash;

            var result = personaClient.isPresignedUrlValid(urlToValidate, secret);

            result.should.equal(false);

            done();
        });

    });

    describe("- Validate Token tests", function(){

        it("should not validate an invalid token", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var req = _getStubRequest("skldfjlskj", null);
            var res = _getStubResponse();

            // the callback wont be called internally because this is middleware
            // therefore we need to call validate token and wait a couple of seconds for the
            // request to fail and asser the response object
            personaClient.validateHTTPBearerToken(req, res, null);
            setTimeout(function(){
                res._statusWasCalled.should.equal(true);
                res._jsonWasCalled.should.equal(true);
                res._setWasCalled.should.equal(true);

                res._status.should.equal(401);
                res._json.error.should.equal("invalid_token");
                res._json.error_description.should.equal("The token is invalid or has expired");
                done();
            }, 2000);
        });

        it("should validate a generated token", function(done){
            // use _getOAuthToken to generate a token outside of the node client
            _getOAuthToken(null, function(err, token){
                var personaClient = persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens/",
                    redis_host:"localhost",
                    redis_port:6379,
                    redis_db:0,
                    enable_debug: false
                });

                var req = _getStubRequest(token, null);
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function(err, result){
                    assert.equal(res._statusWasCalled, false);
                    assert.equal(res._jsonWasCalled, false);
                    assert.equal(res._setWasCalled, false);

                    assert.equal(result, "verified_by_persona");
                    done();
                });
            });
        });

        it("should validate a scoped token", function(done){
            // use _getOAuthToken to generate a token outside of the node client
            _getOAuthToken("primate", function(err, token){
                var personaClient = persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens/",
                    redis_host:"localhost",
                    redis_port:6379,
                    redis_db:0,
                    enable_debug: false
                });

                var req = _getStubRequest(token, "primate");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function(err, result){
                    assert.equal(res._statusWasCalled, false);
                    assert.equal(res._jsonWasCalled, false);
                    assert.equal(res._setWasCalled, false);

                    assert.equal(result, "verified_by_persona");
                    done();
                });
            });
        });

        it("should validate token using the cache", function(done){
            // use _getOAuthToken to generate a token outside of the node client
            _getOAuthToken(null, function(err, token){
                var personaClient = persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens/",
                    redis_host:"localhost",
                    redis_port:6379,
                    redis_db:0,
                    enable_debug: false
                });

                async.series([
                    function(callback){
                        // first request should be validated by persona
                        var req = _getStubRequest(token, null);
                        var res = _getStubResponse();

                        personaClient.validateHTTPBearerToken(req, res, function(err, result){
                            assert.equal(res._statusWasCalled, false);
                            assert.equal(res._jsonWasCalled, false);
                            assert.equal(res._setWasCalled, false);
                            assert.equal(result, "verified_by_persona");

                            callback(null, "done");
                        });
                    },
                    function(callback){
                        // second request should be validated by cache since node client has cached the validated token
                        var req = _getStubRequest(token, null);
                        var res = _getStubResponse();

                        personaClient.validateHTTPBearerToken(req, res, function(err, result){
                            assert.equal(res._statusWasCalled, false);
                            assert.equal(res._jsonWasCalled, false);
                            assert.equal(res._setWasCalled, false);
                            assert.equal(result, "verified_by_cache");

                            callback(null, "done");
                        });
                    }
                ], function(err, result){
                    if(err) return done(err);

                    done();
                });
            });
        });

        it("should validate scoped token using the cache", function(done){
            // use _getOAuthToken to generate a token outside of the node client
            _getOAuthToken("primate", function(err, token){
                var personaClient = persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens/",
                    redis_host:"localhost",
                    redis_port:6379,
                    redis_db:0,
                    enable_debug: false
                });

                async.series([
                    function(callback){
                        // first request should be validated by persona
                        var req = _getStubRequest(token, "primate");
                        var res = _getStubResponse();

                        personaClient.validateHTTPBearerToken(req, res, function(err, result){
                            assert.equal(res._statusWasCalled, false);
                            assert.equal(res._jsonWasCalled, false);
                            assert.equal(res._setWasCalled, false);
                            assert.equal(result, "verified_by_persona");

                            callback(null, "done");
                        });
                    },
                    function(callback){
                        // second request should be validated by cache since node client has cached the validated token
                        var req = _getStubRequest(token, "primate");
                        var res = _getStubResponse();

                        personaClient.validateHTTPBearerToken(req, res, function(err, result){
                            if(err) return callback(err);

                            assert.equal(res._statusWasCalled, false);
                            assert.equal(res._jsonWasCalled, false);
                            assert.equal(res._setWasCalled, false);
                            assert.equal(result, "verified_by_cache");

                            callback(null, "done");
                        });
                    }
                ], function(err, result){
                    if(err) return done(err);

                    done();
                });
            });
        });

        it("should not validate an invalid scoped token", function(done){
            // use _getOAuthToken to generate a token outside of the node client
            _getOAuthToken("primate", function(err, token){
                var personaClient = persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens/",
                    redis_host:"localhost",
                    redis_port:6379,
                    redis_db:0,
                    enable_debug: false
                });

                async.series([
                    function(callback){
                        // first request should be validated by persona
                        var req = _getStubRequest(token, "primate");
                        var res = _getStubResponse();

                        personaClient.validateHTTPBearerToken(req, res, function(err, result){
                            assert.equal(res._statusWasCalled, false);
                            assert.equal(res._jsonWasCalled, false);
                            assert.equal(res._setWasCalled, false);
                            assert.equal(result, "verified_by_persona");

                            callback(null, "done");
                        });
                    },
                    function(callback){
                        // second request should fail, because the scope we are requesting cant possibly be valid
                        var req = _getStubRequest(token, "wibble");
                        var res = _getStubResponse();

                        personaClient.validateHTTPBearerToken(req, res, null);
                        setTimeout(function(){
                            res._statusWasCalled.should.equal(true);
                            res._jsonWasCalled.should.equal(true);
                            res._setWasCalled.should.equal(true);

                            res._status.should.equal(403);
                            res._json.error.should.equal("insufficient_scope");
                            res._json.error_description.should.equal("The supplied token is missing a required scope");

                            callback(null, "done");
                        },4000);
                    }
                ], function(err, result){
                    if(err) return done(err);

                    done();
                });
            });
        });

       it("should correctly validate an invalid scoped token - Persona route version 1 - should return 401", function(done){
            // use _getOAuthToken to generate a token outside of the node client

            _getOAuthToken("primate", function(err, token){
                var personaClient = persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/1/oauth/tokens/",
                    redis_host:"localhost",
                    redis_port:6379,
                    redis_db:0,
                    enable_debug: false
                });

                var req = _getStubRequest(token, "fred");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, null);
                setTimeout(function(){
                    res._statusWasCalled.should.equal(true);
                    res._jsonWasCalled.should.equal(true);
                    res._setWasCalled.should.equal(true);

                    res._status.should.equal(401);
                    res._json.error.should.equal("invalid_token");
                    res._json.error_description.should.equal("The token is invalid or has expired");

                    done();
                },4000);
            });
        });

       it("should correctly validate an invalid scoped token - Persona route version 2 - should return 403", function(done){
            // use _getOAuthToken to generate a token outside of the node client

            _getOAuthToken("primate", function(err, token){
                var personaClient = persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens/",
                    redis_host:"localhost",
                    redis_port:6379,
                    redis_db:0,
                    enable_debug: false
                });

                var req = _getStubRequest(token, "fred");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, null);
                setTimeout(function(){
                    res._statusWasCalled.should.equal(true);
                    res._jsonWasCalled.should.equal(true);
                    res._setWasCalled.should.equal(true);

                    res._status.should.equal(403);
                    res._json.error.should.equal("insufficient_scope");
                    res._json.error_description.should.equal("The supplied token is missing a required scope");

                    done();
                },4000);
            });
        });

       it("validateToken: should correctly validate an invalid scoped token - Persona route version 1 - should return validation_failure", function(done){
            // use _getOAuthToken to generate a token outside of the node client

            _getOAuthToken("primate", function(err, token){
                var personaClient = persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/1/oauth/tokens/",
                    redis_host:"localhost",
                    redis_port:6379,
                    redis_db:0,
                    enable_debug: false
                });

                personaClient.validateToken(token, "fred", null, function(err) {
                    err.should.equal("validation_failure");
                    done();
                });
            });
        });

       it("validateToken: should correctly validate an invalid scoped token - Persona route version 2 - should return insufficient_scope", function(done){
            // use _getOAuthToken to generate a token outside of the node client

            _getOAuthToken("primate", function(err, token){
                var personaClient = persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens/",
                    redis_host:"localhost",
                    redis_port:6379,
                    redis_db:0,
                    enable_debug: false
                });

                personaClient.validateToken(token, "fred", null, function(err) {
                    err.should.equal("insufficient_scope");
                    done();
                });
            });
        });

    });

    describe("- Generate token tests", function() {
        var clock;
        beforeEach(function () {
            clock = sinon.useFakeTimers();
        });

        afterEach(function () {
            clock.restore();
        });

        it("should throw error if there is no id",function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var validateUrl = function(){
                return personaClient.obtainToken(null,"bananas",function(err,data) {});
            };

            validateUrl.should.throw("You must provide an ID to obtain a token");
            done();
        });
        it("should throw error if there is no secret",function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            var validateUrl = function(){
                return personaClient.obtainToken("primate",null,function(err,data) {});
            };

            validateUrl.should.throw("You must provide a secret to obtain a token");
            done();
        });
        it("should return a token, and cache that token",function(done) {
            global.http = require('http');
            var requestStub = sinon.stub(http, 'request');

            var now = new Date().getTime() / 1000;
            var expected = {access_token: 'thisisatoken', expires_in: now + 1800, scope: 'primate', token_type: 'tokentype'};
            var response = new PassThrough();

            response.statusCode = 200;
            response.write(JSON.stringify(expected));
            response.end();

            var request = new PassThrough();

            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            requestStub.callsArgWith(1, response).returns(request);

            personaClient._removeTokenFromCache("primate","bananas",function(err) {
                assert(err===null);
                personaClient.obtainToken("primate","bananas",function(err,data1) {
                    assert(err===null);
                    data1.should.have.property("access_token");
                    data1.should.have.property("expires_in");
                    data1.expires_in.should.equal(1800);
                    data1.should.have.property("scope");
                    data1.should.have.property("token_type");
                    clock.tick(3000); //move clock forward by 1s to make sure expires_in is different

                    personaClient.obtainToken("primate","bananas",function(err,data2) {
                        assert(err===null);
                        data2.should.have.property("access_token");
                        data2.should.have.property("expires_in");
                        data2.should.have.property("scope");
                        data2.should.have.property("token_type");

                        data1.access_token.should.equal(data2.access_token);
                        data1.expires_in.should.not.equal(data2.expires_in);

                        http.request.restore();

                        done();
                    });
                });
            });
        });
        it("should not return a token",function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.obtainToken("primate","wrong_password",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("Generate token failed with status code 400");
                assert(data===null);
                done();
            });
        });
    });

    describe("- Request authorization tests",function(){
        it("should throw an error if guid is not present", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.requestAuthorization(null,"test title","some_id","some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, title, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if guid is not a string", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.requestAuthorization({},"test title","some_id","some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, title, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if title is not present", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.requestAuthorization("guid",null,"some_id","some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, title, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if title is not a string", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.requestAuthorization("guid",{},"some_id","some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, title, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if client id is not present", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.requestAuthorization("guid","test title",null,"some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, title, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if client id is not a string", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.requestAuthorization("guid","test title",{},"some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, title, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if client secret is not present", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.requestAuthorization("guid","test title","some_id",null,function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, title, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if client secret is not a string", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.requestAuthorization("guid","test title","some_id",{},function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, title, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should return 400 if id and secret not valid", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.requestAuthorization("guid","test title","some_id","some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("Request authorization failed with error: Generate token failed with status code 400");
                assert(data===null);
                done();
            });
        });

        xit("should return 401 if token scope not valid", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            // todo: how do I get a token without su scope? bah! Also fix persona before enabling this test
            _getOAuthToken("invalid_scope",function(err,token) {
                personaClient.requestAuthorization("guid_does_not_exist","test title","some_id","some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("Request authorization failed with status code 404");
                    assert(data===null);
                    done();
                });
            })
        });

        it("should return 404 if user does not exist", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.requestAuthorization("guid_does_not_exist","test title","primate","bananas",function(err,data) { // todo: move these creds somewhere else
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("Request authorization failed with status code 404");
                assert(data===null);
                done();
            });
        });

        xit("should return credentials", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            // todo: how to get a valid guid?
            personaClient.requestAuthorization("guid_does_exist","test title","some_id","some_secret",function(err,data) {
                assert(err===null);
                assert(data!==null);
                data.should.be.an.Object;
                done();
            });
        });

    });

    describe("- Delete authorization tests",function(){
        it("should throw an error if guid is not present", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.deleteAuthorization(null,"some_client_id","some_id","some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, authorization_client_id, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if guid is not a string", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.deleteAuthorization({},"some_client_id","some_id","some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, authorization_client_id, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if authorization_client_id is not present", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.deleteAuthorization("guid", null,"some_id","some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, authorization_client_id, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if authorization_client_id is not a string", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.deleteAuthorization("guid", {},"some_id","some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, authorization_client_id, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if client id is not present", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.deleteAuthorization("guid", "authorization_client_id",null,"some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, authorization_client_id, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if client id is not a string", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.deleteAuthorization("guid", "authorization_client_id",{},"some_secret",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, authorization_client_id, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if client secret is not present", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.deleteAuthorization("guid", "authorization_client_id","some_id", null,function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, authorization_client_id, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should throw an error if client secret is not a string", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.deleteAuthorization("guid", "authorization_client_id","some_id", null,function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid, authorization_client_id, id and secret are required strings");
                assert(data===null);
                done();
            });
        });

        it("should return 400 if id and secret not valid", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.deleteAuthorization("guid", "authorization_client_id","some_id", "some_secret",function(err) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("Request authorization failed with error: Generate token failed with status code 400");
                done();
            });
        });

        xit("should return 401 if token scope not valid", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            // todo: how do I get a token without su scope? bah! Also fix persona first before enabling this test
            _getOAuthToken("invalid_scope",function(err,token) {
                personaClient.deleteAuthorization("guid", "authorization_client_id","some_id", "some_secret",function(err) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("Request authorization failed with status code 404");
                    done();
                });
            })
        });

        it("should return 204 if user does not exist", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.deleteAuthorization("guid_does_not_exist", "authorization_client_id","primate", "bananas",function(err) { //todo: move those credentials
                assert(err==null);
                done();
            });
        });

        it("should return 204 if user does exist", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            // todo: how do a get a valid guid?
            personaClient.deleteAuthorization("guid", "authorization_client_id","primate", "bananas",function(err) { //todo: move those credentials
                assert(err==null);
                done();
            });
        });

    })

    describe("- Get user profile by guid tests", function(){
        it("should throw an error if guid is not present", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.getProfileByGuid(null,"",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid and token are required strings");
                assert(data===null);
                done();
            });
        });
        it("should throw an error if guid is not a string", function(done) {
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.getProfileByGuid({},"token",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid and token are required strings");
                assert(data===null);
                done();
            });
        });
        it("should throw an error if token is not present", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.getProfileByGuid("GUID",null,function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid and token are required strings");
                assert(data===null);
                done();
            });
        });
        it("should throw an error if token is not a string", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.getProfileByGuid("GUID",{},function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid and token are required strings");
                assert(data===null);
                done();
            });
        });
        it("should fail with a status code of 404 for a user not found", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });
            personaClient.obtainToken("primate","bananas",function(err,data1) {
                personaClient.getProfileByGuid('GUID', data1.access_token, function(err, data){
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("getProfileByGuid failed with status code 404");
                    assert(data===null);
                    done();
                });
            });
        });
        it("should return a user object if user found", function(done){

            global.http = require('http');
            var requestStub = sinon.stub(http, 'request');

            var expected = {guid:'123',profile: {first_name:'Max', surname:'Payne'}};
            var response = new PassThrough();

            response.statusCode = 200;
            response.write(JSON.stringify(expected));
            response.end();

            var request = new PassThrough();

            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
              });

            requestStub.callsArgWith(1, response).returns(request);

            // stub out the call to get obtainToken by providing a fake redisClient that returns known data
            var now = new Date().getTime() / 1000;
            var reply = {access_token: 'thisisatoken', expires_at: now + 1000};

            sinon.stub(personaClient.redisClient, "get").callsArgWith(1,null,JSON.stringify(reply));

            personaClient.obtainToken("primate","bananas",function(err,data1) {
                personaClient.getProfileByGuid('guid_does_exist', data1.access_token, function(err, data){

                    assert(err===null);
                    assert(data!==null);

                    data.should.be.an.Object;
                    data.should.eql(expected);

                    http.request.restore();
                    personaClient.redisClient.get.restore();
                    done();
                });
            });
        });
    });

    describe("- Update user profile tests", function(){
        it("should throw an error if guid is not set", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.updateProfile(null,{}, "",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid and token are required strings");
                assert(data===null);
                done();
            });
        });
        it("should throw an error if guid is not a string", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.updateProfile({},{}, "",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid and token are required strings");
                assert(data===null);
                done();
            });
        });
        it("should throw an error if profile is not set", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.updateProfile("GUID",null, "",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("profile is a required object");
                assert(data===null);
                done();
            });
        });
        it("should throw an error if profile not an object", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.updateProfile("GUID","PROFILE", "",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("profile is a required object");
                assert(data===null);
                done();
            });
        });
        it("should throw an error if token is not set", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.updateProfile("GUID",{}, null,function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid and token are required strings");
                assert(data===null);
                done();
            });
        });
        it("should throw an error if token it not a string", function(done){
            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });

            personaClient.updateProfile("GUID",{}, {},function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("guid and token are required strings");
                assert(data===null);
                done();
            });
        });
        it("should return a user if success", function(done){
            global.http = require('http');
            var requestStub = sinon.stub(http, 'request');

            var expected = {guid:'123',profile: {first_name:'Max', surname:'Payne'}};
            var response = new PassThrough();
            response.statusCode = 200;
            response.write(JSON.stringify(expected));
            response.end();
            var request = new PassThrough();

            var personaClient = persona.createClient({
                persona_host:"persona",
                persona_port:80,
                persona_scheme:"http",
                persona_oauth_route:"/oauth/tokens/",
                redis_host:"localhost",
                redis_port:6379,
                redis_db:0,
                enable_debug: false
            });
            requestStub.callsArgWith(1, response).returns(request);

            // stub out the call to get obtainToken by providing a fake redisClient that returns known data
            var now = new Date().getTime() / 1000;
            var reply = {access_token: 'thisisatoken', expires_at: now + 1000};

            sinon.stub(personaClient.redisClient, "get").callsArgWith(1,null,JSON.stringify(reply));

            personaClient.obtainToken("primate","bananas",function(err,data1) {
                personaClient.updateProfile('guid_does_exist', expected.profile, data1.access_token, function(err, data){
                    assert(err===null);
                    assert(data!==null);

                    data.should.be.an.Object;
                    data.should.eql(expected);

                    http.request.restore();
                    personaClient.redisClient.get.restore();
                    done();
                });
            });
        });
    });

});
