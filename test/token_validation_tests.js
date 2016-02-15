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

describe("Persona Client Test Suite - Token Validation Tests", function(){
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

    });
});