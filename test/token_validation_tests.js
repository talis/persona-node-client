"use strict";

var should = require("should");
var assert = require("assert");
var jwt = require("jsonwebtoken");
var fs = require("fs");
var nock = require("nock");
var sinon = require("sinon");
var persona = require("../index");
var _getStubRequest = require("./utils")._getStubRequest;
var _getStubResponse = require("./utils")._getStubResponse;
var guid = require("./utils").guid;
var runBeforeEach = require("./utils").beforeEach;
var runAfterEach = require("./utils").afterEach;
var leche = require("leche");
var withData = leche.withData;
var lodash = require('lodash');

describe("Persona Client Test Suite - Token Validation Tests", function() {

    var personaClient;
    var privateKey = fs.readFileSync(__dirname + "/keys/privkey.pem", "utf-8");
    var publicKey = fs.readFileSync(__dirname + "/keys/pubkey.pem", "utf-8");
    withData({
        "default-cache": {
            persona_host: process.env.PERSONA_TEST_HOST || "persona",
            persona_port: process.env.PERSONA_TEST_PORT || 80,
            persona_scheme: process.env.PERSONA_TEST_SCHEME || "http",
            persona_oauth_route: "/oauth/tokens/",
            enable_debug: false,
            cert_background_refresh: false,
        },
        "redis": {
            persona_host: process.env.PERSONA_TEST_HOST || "persona",
            persona_port: process.env.PERSONA_TEST_PORT || 80,
            persona_scheme: process.env.PERSONA_TEST_SCHEME || "http",
            persona_oauth_route: "/oauth/tokens/",
            cache: {
                module: "redis",
                options: {
                    redisData: {
                        hostname: "localhost",
                        port: 6379,
                        detect_buffers: true,
                        return_buffers: true
                    }
                }
            },
            enable_debug: false,
            cert_background_refresh: false,
        },
        "legacy-config-options": {
            persona_host: process.env.PERSONA_TEST_HOST || "persona",
            persona_port: process.env.PERSONA_TEST_PORT || 80,
            persona_scheme: process.env.PERSONA_TEST_SCHEME || "http",
            persona_oauth_route: "/oauth/tokens/",
            redis_host: "localhost",
            redis_port: 6379,
            redis_db: 0,
            enable_debug: false,
            cert_background_refresh: false,
        }
    }, function(personaClientConfig) {
        beforeEach(function(done) {
            this.nockAssertions = runBeforeEach(this.currentTest.title, "token_validation");

            personaClient = persona.createClient(personaClientConfig);
            sinon.spy(personaClient.http, "request");
            // Some tests rely on the cache being in a clean state
            personaClient.tokenCache.flush(function onFlushed() {
                done();
            });
        });

        afterEach(function afterEachTest() {
            if (this.nockAssertions) {
                lodash.forEach(this.nockAssertions, function verifyEachNockRequest(nockAssertion) {
                    nockAssertion.done();
                });
            }

            runAfterEach(this.currentTest.title, "token_validation");
            personaClient.http.request.restore();
        });

        it('should retrieve cert straight away if auto update is on', function autoUpdateTest(done) {
            var config = lodash.clone(personaClientConfig);
            config.cert_background_refresh = true;

            persona.PUBLIC_KEY_AUTO_REFRESH_TIMEOUT = 0.6;
            var client = persona.createClient(config);

            setTimeout(function fin() {
                clearInterval(client.refreshTimerId);
                return done();
            }, 1000);
        });

        it("should not validate an invalid token", function(done) {
            var req = _getStubRequest("skldfjlskj", null);
            var res = _getStubResponse();

            // the callback wont be called internally because this is middleware
            // therefore we need to call validate token and wait a couple of seconds for the
            // request to fail and assert the response object
            personaClient.validateHTTPBearerToken(req, res, function validatedToken(err) {
                err.should.be.equal(persona.errorTypes.VALIDATION_FAILURE);
                res._statusWasCalled.should.equal(true);
                res._jsonWasCalled.should.equal(true);
                res._setWasCalled.should.equal(true);

                res._status.should.equal(401);
                res._json.error.should.equal("invalid_token");
                res._json.error_description.should.equal("The token is invalid or has expired");

                done();
            });
        });

        it("should validate a token without scope", function(done) {
            var payload = {
                scopes: [
                    "standard_user"
                ]
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1h",
                audience: "standard_user"
            };

            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                var req = _getStubRequest(token, null);
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function validatedToken(err, result) {
                    if (err) {
                        return done(err);
                    }
                    assert.equal(res._statusWasCalled, false);
                    assert.equal(res._jsonWasCalled, false);
                    assert.equal(res._setWasCalled, false);

                    assert.equal(result, "ok");
                    done();
                });
            });
        });

        it("should validate a scoped token", function(done) {
            var payload = {
                scopes: [
                    "standard_user"
                ]
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1h",
                audience: "standard_user"
            };

            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                var req = _getStubRequest(token, "standard_user");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function validatedToken(err, result) {
                    if (err) {
                        return done(err);
                    }
                    assert.equal(res._statusWasCalled, false);
                    assert.equal(res._jsonWasCalled, false);
                    assert.equal(res._setWasCalled, false);

                    assert.equal(result, "ok");
                    done();
                });
            });
        });

        it("should not validate an invalid scoped token", function(done) {
            var payload = {
                scopes: [
                    "standard_user"
                ]
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1h",
                audience: "standard_user"
            };

            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                var req = _getStubRequest(token, "wibble");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function validatedToken(err) {
                    err.should.be.equal(persona.errorTypes.INSUFFICIENT_SCOPE);
                    res._statusWasCalled.should.equal(true);
                    res._jsonWasCalled.should.equal(true);
                    res._setWasCalled.should.equal(true);

                    res._status.should.equal(403);
                    res._json.error.should.equal("insufficient_scope");
                    res._json.error_description.should.equal("The supplied token is missing a required scope");

                    done();
                });
            });
        });

        it("should not validate an expired token", function(done) {
            var payload = {
                scopes: [
                    "standard_user"
                ]
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1",
                audience: "standard_user"
            };

            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                var req = _getStubRequest(token, "standard_user");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function validatedToken(err, success) {
                    err.should.be.equal(persona.errorTypes.VALIDATION_FAILURE);
                    res._statusWasCalled.should.equal(true);
                    res._jsonWasCalled.should.equal(true);
                    res._setWasCalled.should.equal(true);

                    res._status.should.equal(401);
                    res._json.error.should.equal("invalid_token");
                    res._json.error_description.should.equal("The token is invalid or has expired");

                    done();
                });
            });
        });

        it("should validate a token with su scope, even when it is not asked for", function(done) {
            var payload = {
                scopes: [
                    "su",
                    "super_user"
                ]
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1h",
                audience: "super_user"
            };

            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                var req = _getStubRequest(token, "other_scope");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function validatedToken(err, result) {
                    if (err) {
                        return done(err);
                    }
                    assert.equal(res._statusWasCalled, false);
                    assert.equal(res._jsonWasCalled, false);
                    assert.equal(res._setWasCalled, false);

                    assert.equal(result, "ok");
                    done();
                });
            });
        });

        it("should validate a scoped token when the list of scopes is too many to return", function(done) {
            var payload = {
                scopeCount: 26
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1h",
                audience: "fatuser"
            };

            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                // We can't replay the recorded response as the token in that request will expire
                nock("http://persona").head(/\/oauth\/tokens\/.*\?scope=fatuser/).reply(204);

                var req = _getStubRequest(token, "fatuser");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function validatedToken(error, result) {
                    if(error) {
                        return done(error);
                    }
                    assert.equal(res._statusWasCalled, false);
                    assert.equal(res._jsonWasCalled, false);
                    assert.equal(res._setWasCalled, false);

                    assert.equal(result, "ok");
                    done();
                });
            });
        });

        it("should validate a token with su scope when checked via persona, even when it is not asked for", function(done) {
            var payload = {
                scopeCount: 26
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1h",
                audience: "fatuser"
            };

            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                // First respond that the scope is insufficient then respond ok for su
                nock("http://persona").head(/\/oauth\/tokens\/.*\?scope=other_scope/).reply(403);
                nock("http://persona").head(/\/oauth\/tokens\/.*\?scope=su/).reply(204);

                var req = _getStubRequest(token, "other_scope");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function validatedToken(err, result) {
                    if (err) {
                        return done(err);
                    }
                    assert.equal(res._statusWasCalled, false);
                    assert.equal(res._jsonWasCalled, false);
                    assert.equal(res._setWasCalled, false);

                    assert.equal(result, "ok");
                    done();
                });
            });
        });

        it("should not validate an invalid scoped token when the list of scopes is too many to return", function(done) {
            var payload = {
                scopeCount: 26
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1h",
                audience: "fatuser"
            };

            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                // We can't replay the recorded response as the token in that request will expire
                nock("http://persona").head(/\/oauth\/tokens\/.*\?scope=invalid/).reply(403);
                nock("http://persona").head(/\/oauth\/tokens\/.*\?scope=su/).reply(403);

                var req = _getStubRequest(token, "invalid");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function validatedToken(err) {
                    err.should.be.equal(persona.errorTypes.INSUFFICIENT_SCOPE);
                    res._statusWasCalled.should.equal(true);
                    res._jsonWasCalled.should.equal(true);
                    res._setWasCalled.should.equal(true);

                    res._status.should.equal(403);
                    res._json.error.should.equal("insufficient_scope");
                    res._json.error_description.should.equal("The supplied token is missing a required scope");

                    done();
                });
            });
        });

        it("should not validate a token when the server-side check returns 401", function(done) {

            var payload = {
                scopeCount: 26
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1h",
                audience: "fatuser"
            };

            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                // We can't replay the recorded response as the token in that request will expire
                nock("http://persona").head(/\/oauth\/tokens\/.*\?scope=fatuser/).reply(401);

                var req = _getStubRequest(token, "fatuser");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function(err, success) {
                    err.should.be.equal(persona.errorTypes.VALIDATION_FAILURE);
                    res._statusWasCalled.should.equal(true);
                    res._jsonWasCalled.should.equal(true);
                    res._setWasCalled.should.equal(true);

                    res._status.should.equal(401);
                    res._json.error.should.equal("invalid_token");
                    res._json.error_description.should.equal("The token is invalid or has expired");

                    done();
                });
            });
        });

        it("should not validate a token when the server-side check returns an error", function(done) {
            var payload = {
                scopeCount: 26
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1h",
                audience: "fatuser"
            };

            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                // We can't replay the recorded response as the token in that request will expire
                nock("http://persona").head(/\/oauth\/tokens\/.*\?scope=fatuser/).reply(500);

                var req = _getStubRequest(token, "fatuser");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function(err, success) {
                    err.should.be.equal(persona.errorTypes.COMMUNICATION_ISSUE);
                    res._statusWasCalled.should.equal(true);
                    res._jsonWasCalled.should.equal(true);
                    res._setWasCalled.should.equal(true);

                    res._status.should.equal(500);
                    res._json.error.should.equal("unexpected_error");
                    res._json.error_description.should.equal("communication_issue");

                    done();
                });
            });
        });

        it("should not validate a token when the public key is incorrect", function(done) {
            // stub response file contains a public key that has been tampered with.

            var payload = {
                scopes: [
                    "standard_user"
                ]
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1h",
                audience: "standard_user"
            };

            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                var req = _getStubRequest(token, "standard_user");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function validatedToken(err) {
                    err.should.be.equal(persona.errorTypes.VALIDATION_FAILURE);
                    res._statusWasCalled.should.equal(true);
                    res._jsonWasCalled.should.equal(true);
                    res._setWasCalled.should.equal(true);

                    res._status.should.equal(401);
                    res._json.error.should.equal("invalid_token");
                    res._json.error_description.should.equal("The token is invalid or has expired");

                    done();

                });
            });
        });

        it("should not validate a token when there is a problem fetching the public key", function(done) {
            var payload = {
                scopes: [
                    "standard_user"
                ]
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1h",
                audience: "standard_user"
            };

            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                nock('http://persona').get(/\/oauth\/keys/).reply(504);
                var req = _getStubRequest(token, "standard_user");
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function validatedToken(err, success) {
                    err.should.be.equal(persona.errorTypes.COMMUNICATION_ISSUE);
                    res._statusWasCalled.should.equal(true);
                    res._jsonWasCalled.should.equal(true);
                    res._setWasCalled.should.equal(true);

                    res._status.should.equal(500);
                    res._json.error.should.equal("unexpected_error");
                    res._json.error_description.should.equal("communication_issue");

                    done();
                });
            });
        });

        it("should use a cached public key when validating a token", function(done) {
            var payload = {
                scopes: [
                    "standard_user"
                ]
            };

            var jwtSigningOptions = {
                jwtid: guid(),
                algorithm: "RS256",
                expiresIn: "1h",
                audience: "standard_user"
            };

            // First make sure the cache has the key
            personaClient.tokenCache.set("public_key", publicKey);
            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                var req = _getStubRequest(token, null);
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function validatedToken(err, result) {
                    if (err) {
                        return done(err);
                    }
                    assert.equal(res._statusWasCalled, false);
                    assert.equal(res._jsonWasCalled, false);
                    assert.equal(res._setWasCalled, false);

                    assert.equal(result, "ok");
                    assert.equal(personaClient.http.request.called, false);

                    done();
                });
            });
        });
    });
});
