"use strict";

var should = require("should");
var assert = require("assert");
var persona = require("../index");
var sinon = require("sinon");
var runBeforeEach = require("./utils").beforeEach;
var runAfterEach = require("./utils").afterEach;
var leche = require("leche");
var withData = leche.withData;

describe("Persona Client Test Suite - Constructor & Token Tests", function() {

    beforeEach(function() {
        runBeforeEach(this.currentTest.title, "persona_client");
    });

    afterEach(function() {
        runAfterEach(this.currentTest.title, "persona_client");
    });

    describe("- Constructor tests", function() {

        it("should throw error if config.persona_host is not supplied", function(done) {
            var personaClient = function() {
                return persona.createClient({});
            };
            personaClient.should.throw("You must specify the persona host");
            done();
        });
        it("should throw error if config.persona_port is not supplied", function(done) {
            var personaClient = function() {
                return persona.createClient({persona_host: "persona"});
            };
            personaClient.should.throw("You must specify the persona port");
            done();
        });
        it("should throw error if config.persona_scheme is not supplied", function(done) {
            var personaClient = function(){
                return persona.createClient({
                    persona_host: "persona",
                    persona_port: 80
                });
            };
            personaClient.should.throw("You must specify the persona scheme");
            done();
        });
        it("should throw error if config.persona_oauth_route is not supplied", function(done) {
            var personaClient = function() {
                return persona.createClient({
                    persona_host: "persona",
                    persona_port: 80,
                    persona_scheme: "http"
                });
            };
            personaClient.should.throw("You must specify the persona oauth route");
            done();
        });

        it("should NOT throw any error if all config params are defined", function(done) {
            var personaClient = function() {
                return persona.createClient({
                    persona_host: "persona",
                    persona_port: 80,
                    persona_scheme: "http",
                    persona_oauth_route: "/oauth/tokens",
                    cache: {
                        module: "redis",
                        options: {
                            redisData: {
                                hostname: "localhost",
                                port: 6379
                            }
                        }
                    }
                });
            };
            personaClient.should.not.throw();
            done();
        });
    });

    describe("- Generate token tests", function() {
        var clock;
        var oauthClient = process.env.PERSONA_TEST_OAUTH_CLIENT || "primate";
        var oauthSecret = process.env.PERSONA_TEST_OAUTH_SECRET || "bananas";

        withData({
            "default-cache": {
                persona_host: process.env.PERSONA_TEST_HOST || "persona",
                persona_port: process.env.PERSONA_TEST_PORT || 80,
                persona_scheme: process.env.PERSONA_TEST_SCHEME || "http",
                persona_oauth_route: "/oauth/tokens/",
                enable_debug: false
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
                            port: 6379
                        }
                    }
                },
                enable_debug: false
            },
            "legacy-config-options": {
                persona_host: process.env.PERSONA_TEST_HOST || "persona",
                persona_port: process.env.PERSONA_TEST_PORT || 80,
                persona_scheme: process.env.PERSONA_TEST_SCHEME || "http",
                persona_oauth_route: "/oauth/tokens/",
                redis_host: "localhost",
                redis_port: 6379,
                redis_db: 0,
                enable_debug: false
            }
        }, function(personaClientConfig) {
            beforeEach(function () {
                clock = sinon.useFakeTimers();
            });

            afterEach(function () {
                clock.restore();
            });

            it("should throw error if there is no id", function(done) {
                var personaClient = persona.createClient(personaClientConfig);

                var validateUrl = function() {
                    return personaClient.obtainToken(null, "bananas", function(err, data) {});
                };

                validateUrl.should.throw("You must provide an ID to obtain a token");
                done();
            });
            it("should throw error if there is no secret", function(done) {
                var personaClient = persona.createClient(personaClientConfig);

                var validateUrl = function(){
                    return personaClient.obtainToken(oauthClient, null, function(err, data) {});
                };

                validateUrl.should.throw("You must provide a secret to obtain a token");
                done();
            });
            it("should return a token, and cache that token", function(done) {
                var personaClient = persona.createClient(personaClientConfig);

                personaClient._removeTokenFromCache(oauthClient, oauthSecret, function(err) {
                    assert(err === null);
                    personaClient.obtainToken(oauthClient, oauthSecret, function(err, data1) {
                        assert(err===null);
                        data1.should.have.property("access_token");
                        data1.should.have.property("expires_in");
                        data1.expires_in.should.equal(3600);
                        data1.should.have.property("scope");
                        data1.should.have.property("token_type");
                        clock.tick(1000); //move clock forward by 1s to make sure expires_in is different

                        personaClient.obtainToken(oauthClient, oauthSecret, function(err, data2) {
                            assert(err===null);
                            data2.should.have.property("access_token");
                            data2.should.have.property("expires_in");
                            data2.should.have.property("scope");
                            data2.should.have.property("token_type");

                            data1.access_token.should.equal(data2.access_token);
                            data1.expires_in.should.not.equal(data2.expires_in);

                            done();
                        });
                    });
                });
            });
            it("should not return a token",function(done) {
                var personaClient = persona.createClient(personaClientConfig);

                personaClient.obtainToken("primate","wrong_password",function(err, data) {
                    assert(err != null);
                    err.should.be.a.String;
                    err.should.equal("Generate token failed with status code 400");
                    assert(data===null);
                    done();
                });
            });
        });
    });

});
