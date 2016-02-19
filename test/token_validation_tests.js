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

describe("Persona Client Test Suite - Token Validation Tests", function() {

    var personaClient;
    var privateKey = fs.readFileSync(__dirname + "/keys/privkey.pem");
    var publicKey = fs.readFileSync(__dirname + "/keys/pubkey.pem");

    beforeEach(function(done) {
        runBeforeEach(this.currentTest.title, "token_validation");

        personaClient = persona.createClient({
            persona_host: "persona",
            persona_port: 80,
            persona_scheme: "http",
            persona_oauth_route: "/oauth/tokens/",
            redis_host: "localhost",
            redis_port: 6379,
            redis_db: 0,
            enable_debug: false
        });

        // Some tests rely on the cache being in a clean state
        personaClient.redisClient.flushdb(function onFlushed() {
           done();
        });
    });

    afterEach(function() {
        runAfterEach(this.currentTest.title, "token_validation");
    });

    it("should not validate an invalid token", function(done) {
        var req = _getStubRequest("skldfjlskj", null);
        var res = _getStubResponse();

        // the callback wont be called internally because this is middleware
        // therefore we need to call validate token and wait a couple of seconds for the
        // request to fail and assert the response object
        personaClient.validateHTTPBearerToken(req, res, function() {
            done("validation passed when it should not have");
        });
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

            personaClient.validateHTTPBearerToken(req, res, function(err, result) {
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

            personaClient.validateHTTPBearerToken(req, res, function(err, result) {
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

            personaClient.validateHTTPBearerToken(req, res, function() {
                done("validation passed when it should not have");
            });
            setTimeout(function(){
                res._statusWasCalled.should.equal(true);
                res._jsonWasCalled.should.equal(true);
                res._setWasCalled.should.equal(true);

                res._status.should.equal(403);
                res._json.error.should.equal("insufficient_scope");
                res._json.error_description.should.equal("The supplied token is missing a required scope");

                done();
            }, 2000);
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

            personaClient.validateHTTPBearerToken(req, res, function() {
                done("validation passed when it should not have");
            });
            setTimeout(function() {
                res._statusWasCalled.should.equal(true);
                res._jsonWasCalled.should.equal(true);
                res._setWasCalled.should.equal(true);

                res._status.should.equal(401);
                res._json.error.should.equal("invalid_token");
                res._json.error_description.should.equal("The token is invalid or has expired");

                done();
            }, 2000);
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

            personaClient.validateHTTPBearerToken(req, res, function(err, result) {
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

            personaClient.validateHTTPBearerToken(req, res, function(error, result) {
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

            personaClient.validateHTTPBearerToken(req, res, function(err, result) {
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

            personaClient.validateHTTPBearerToken(req, res, function() {
                done("validation passed when it should not have");
            });
            setTimeout(function() {
                res._statusWasCalled.should.equal(true);
                res._jsonWasCalled.should.equal(true);
                res._setWasCalled.should.equal(true);

                res._status.should.equal(403);
                res._json.error.should.equal("insufficient_scope");
                res._json.error_description.should.equal("The supplied token is missing a required scope");

                done();
            }, 2000);
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

            personaClient.validateHTTPBearerToken(req, res, function() {
                done("validation passed when it should not have");
            });
            setTimeout(function() {
                res._statusWasCalled.should.equal(true);
                res._jsonWasCalled.should.equal(true);
                res._setWasCalled.should.equal(true);

                res._status.should.equal(401);
                res._json.error.should.equal("invalid_token");
                res._json.error_description.should.equal("The token is invalid or has expired");

                done();
            }, 2000);
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

            personaClient.validateHTTPBearerToken(req, res, function() {
                done("validation passed when it should not have");
            });
            setTimeout(function() {
                res._statusWasCalled.should.equal(true);
                res._jsonWasCalled.should.equal(true);
                res._setWasCalled.should.equal(true);

                res._status.should.equal(500);
                res._json.error.should.equal("unexpected_error");
                res._json.error_description.should.equal("communication_issue");

                done();
            }, 2000);
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

            personaClient.validateHTTPBearerToken(req, res, function() {
                done("validation passed when it should not have");
            });
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
            var req = _getStubRequest(token, "standard_user");
            var res = _getStubResponse();

            personaClient.validateHTTPBearerToken(req, res, function() {
                done("validation passed when it should not have");
            });
            setTimeout(function(){
                res._statusWasCalled.should.equal(true);
                res._jsonWasCalled.should.equal(true);
                res._setWasCalled.should.equal(true);

                res._status.should.equal(500);
                res._json.error.should.equal("unexpected_error");
                res._json.error_description.should.equal("communication_issue");

                done();
            }, 2000);
        });
    });

    it("should use a cached public key when validating a token", function(done) {
        sinon.spy(personaClient.http, "request");

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
        personaClient.redisClient.set("public_key", publicKey, function() {
            jwt.sign(payload, privateKey, jwtSigningOptions, function(token) {
                var req = _getStubRequest(token, null);
                var res = _getStubResponse();

                personaClient.validateHTTPBearerToken(req, res, function(err, result) {
                    assert.equal(res._statusWasCalled, false);
                    assert.equal(res._jsonWasCalled, false);
                    assert.equal(res._setWasCalled, false);

                    assert.equal(result, "ok");
                    assert.equal(personaClient.http.request.called, false);
                    personaClient.http.request.restore();
                    done();
                });
            });
        });
    });
});
