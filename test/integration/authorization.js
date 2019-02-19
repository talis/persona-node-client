"use strict";

var should = require("should");
var assert = require("assert");
var sinon = require("sinon");
var persona = require("../../index");
var _getOAuthToken = require("../utils")._getOAuthToken;
var runBeforeEach = require("../utils").beforeEach;
var runAfterEach = require("../utils").afterEach;
var leche = require("leche");
var withData = leche.withData;
var _ = require("lodash");

describe("Persona Client Test Suite - Authorization Tests", function() {

    var personaClient, spy;
    var oauthClient = process.env.PERSONA_TEST_OAUTH_CLIENT || "primate";
    var oauthSecret = process.env.PERSONA_TEST_OAUTH_SECRET || "bananas";

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
                        port: 6379
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
            cert_background_refresh: false
        }
    }, function(personaClientConfig) {
        beforeEach(function createClientAndStubs() {
            runBeforeEach(this.currentTest.parent.title + " " + this.currentTest.title, "authorization", true);

            personaClient = persona.createClient("test-suite",personaClientConfig);
            spy = sinon.spy(personaClient.http, "request");
            sinon.stub(personaClient.tokenCache, "get").yields(null, null);
        });

        afterEach(function restoreStubs() {
            runAfterEach(this.currentTest.parent.title + " " + this.currentTest.title, "authorization", true, spy);
            personaClient.tokenCache.get.restore();
            personaClient.http.request.restore();
        });

        describe("Request authorization tests",function() {
            _.map(["guid","title","id","secret"],function(optsKey) {
                var goodOpts = {guid: "some_guid", title: "some_title", id: "some_id", secret: "some_secret"};
                it("should throw an error if "+optsKey+" is not present", function(done) {
                    var badOpts = _.clone(goodOpts);
                    badOpts[optsKey] = null;
                    try {
                        personaClient.requestAuthorization(badOpts,function(err,data) {
                            done("callback should not be invoked");
                        });
                    } catch (err) {
                        err.message.should.equal(optsKey+" in opts cannot be empty");
                        done();
                    }
                });

                it("should throw an error if "+optsKey+" is not a string", function(done) {
                    var badOpts = _.clone(goodOpts);
                    badOpts[optsKey] = {foo:"bar"};
                    try {
                        personaClient.requestAuthorization(badOpts,function(err,data) {
                            done("callback should not be invoked");
                        });
                    } catch (err) {
                        err.message.should.equal(optsKey+" failed isString validation");
                        done();
                    }
                });
            });

            it("should return 400 if id and secret not valid", function(done) {
                personaClient.requestAuthorization({guid: "guid", title: "test title", id: "some_id", secret: "some_secret"},function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("Request authorization failed with error: Generate token failed with status code 400");
                    assert(data===null);
                    done();
                });
            });

            xit("should return 401 if token scope not valid", function(done) {
                // todo: how do I get a token without su scope? bah! Also fix persona before enabling this test
                _getOAuthToken("invalid_scope",function(err,token) {
                    personaClient.requestAuthorization({guid: "guid_does_not_exist", title: "test title", id: "some_id", secret: "some_secret"},function(err,data) {
                        assert(err!=null);
                        err.should.be.a.String;
                        err.should.equal("Request authorization failed with status code 404");
                        assert(data===null);
                        done();
                    });
                })
            });

            it("should return 404 if user does not exist", function(done) {
                personaClient.requestAuthorization({guid: "guid_does_not_exist", title: "test title", id: oauthClient, secret: oauthSecret}, function(err, data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("Request authorization failed with status code 404");
                    assert(data===null);
                    done();
                });
            });

            xit("should return credentials", function(done) {
                // todo: how to get a valid guid?
                personaClient.requestAuthorization({guid: "guid_does_exist", title: "test title", id: "some_id", secret: "some_secret"},function(err,data) {
                    if (err) {
                      done(err);
                    }
                    assert(data!==null);
                    data.should.be.an.Object;
                    done();
                });
            });

        });

        describe("Delete authorization tests",function(){
            _.map(["guid","authorizationClientId","id","secret"],function(optsKey) {
                var goodOpts = {guid: "some_guid", authorizationClientId: "some_client_id", id: "some_id", secret: "some_secret"};
                it("should throw an error if "+optsKey+" is not present", function(done) {
                    var badOpts = _.clone(goodOpts);
                    badOpts[optsKey] = null;
                    try {
                        personaClient.deleteAuthorization(badOpts,function(err,data) {
                            done("callback should not be invoked");
                        });
                    } catch (err) {
                        err.message.should.equal(optsKey+" in opts cannot be empty");
                        done();
                    }
                });

                it("should throw an error if "+optsKey+" is not a string", function(done) {
                    var badOpts = _.clone(goodOpts);
                    badOpts[optsKey] = {foo:"bar"};
                    try {
                        personaClient.deleteAuthorization(badOpts,function(err,data) {
                            done("callback should not be invoked");
                        });
                    } catch (err) {
                        err.message.should.equal(optsKey+" failed isString validation");
                        done();
                    }
                });
            });

            it("should return 400 if id and secret not valid", function(done) {
                personaClient.deleteAuthorization({guid: "guid", authorizationClientId: "authorization_client_id", id: "some_id", secret: "some_secret"},function(err) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("Request authorization failed with error: Generate token failed with status code 400");
                    done();
                });
            });

            xit("should return 401 if token scope not valid", function(done) {
                // todo: how do I get a token without su scope? bah! Also fix persona first before enabling this test
                _getOAuthToken("invalid_scope",function(err,token) {
                    personaClient.deleteAuthorization({guid: "guid", authorizationClientId: "authorization_client_id", id: "some_id", secret: "some_secret"},function(err) {
                        assert(err!=null);
                        err.should.be.a.String;
                        err.should.equal("Request authorization failed with status code 404");
                        done();
                    });
                })
            });

            it("should return 204 if user does not exist", function(done) {
                personaClient.deleteAuthorization({guid: "guid_does_not_exist", authorizationClientId: "authorization_client_id", id: oauthClient, secret: oauthSecret}, function(err) {
                    assert(err==null);
                    done();
                });
            });

            it("should return 204 if user does exist", function(done) {
                // todo: how do a get a valid guid?
                personaClient.deleteAuthorization({guid: "guid", authorizationClientId: "authorization_client_id", id: oauthClient, secret: oauthSecret}, function(err) {
                    assert(err==null);
                    done();
                });
            });
        });
    });

});
