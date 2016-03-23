"use strict";

var should = require("should");
var assert = require("assert");
var sinon = require("sinon");
var persona = require("../index");
var _getOAuthToken = require("./utils")._getOAuthToken;
var runBeforeEach = require("./utils").beforeEach;
var runAfterEach = require("./utils").afterEach;
var leche = require("leche");
var withData = leche.withData;

describe("Persona Client Test Suite - Authorization Tests", function() {

    var personaClient;
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
        beforeEach(function createClientAndStubs() {
            runBeforeEach(this.currentTest.parent.title + " " + this.currentTest.title, "authorization", true);

            personaClient = persona.createClient(personaClientConfig);
            sinon.stub(personaClient.tokenCache, "get").yields(null, null);
        });

        afterEach(function restoreStubs() {
            runAfterEach(this.currentTest.parent.title + " " + this.currentTest.title, "authorization", true);
            personaClient.tokenCache.get.restore();
        });

        describe("Request authorization tests",function() {

            it("should throw an error if guid is not present", function(done) {
                personaClient.requestAuthorization(null,"test title","some_id","some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, title, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if guid is not a string", function(done) {
                personaClient.requestAuthorization({},"test title","some_id","some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, title, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if title is not present", function(done) {
                personaClient.requestAuthorization("guid",null,"some_id","some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, title, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if title is not a string", function(done) {
                personaClient.requestAuthorization("guid",{},"some_id","some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, title, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if client id is not present", function(done) {
                personaClient.requestAuthorization("guid","test title",null,"some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, title, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if client id is not a string", function(done) {
                personaClient.requestAuthorization("guid","test title",{},"some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, title, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if client secret is not present", function(done) {
                personaClient.requestAuthorization("guid","test title","some_id",null,function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, title, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if client secret is not a string", function(done) {
                personaClient.requestAuthorization("guid","test title","some_id",{},function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, title, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should return 400 if id and secret not valid", function(done) {
                personaClient.requestAuthorization("guid","test title","some_id","some_secret",function(err,data) {
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
                personaClient.requestAuthorization("guid_does_not_exist", "test title", oauthClient, oauthSecret, function(err, data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("Request authorization failed with status code 404");
                    assert(data===null);
                    done();
                });
            });

            xit("should return credentials", function(done) {
                // todo: how to get a valid guid?
                personaClient.requestAuthorization("guid_does_exist","test title","some_id","some_secret",function(err,data) {
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
            it("should throw an error if guid is not present", function(done) {
                personaClient.deleteAuthorization(null,"some_client_id","some_id","some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, authorization_client_id, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if guid is not a string", function(done) {
                personaClient.deleteAuthorization({},"some_client_id","some_id","some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, authorization_client_id, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if authorization_client_id is not present", function(done) {
                personaClient.deleteAuthorization("guid", null,"some_id","some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, authorization_client_id, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if authorization_client_id is not a string", function(done) {
                personaClient.deleteAuthorization("guid", {},"some_id","some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, authorization_client_id, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if client id is not present", function(done) {
                personaClient.deleteAuthorization("guid", "authorization_client_id",null,"some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, authorization_client_id, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if client id is not a string", function(done) {
                personaClient.deleteAuthorization("guid", "authorization_client_id",{},"some_secret",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, authorization_client_id, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if client secret is not present", function(done) {
                personaClient.deleteAuthorization("guid", "authorization_client_id","some_id", null,function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, authorization_client_id, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should throw an error if client secret is not a string", function(done) {
                personaClient.deleteAuthorization("guid", "authorization_client_id","some_id", null,function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid, authorization_client_id, id and secret are required strings");
                    assert(data===null);
                    done();
                });
            });

            it("should return 400 if id and secret not valid", function(done) {
                personaClient.deleteAuthorization("guid", "authorization_client_id","some_id", "some_secret",function(err) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("Request authorization failed with error: Generate token failed with status code 400");
                    done();
                });
            });

            xit("should return 401 if token scope not valid", function(done) {
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
                personaClient.deleteAuthorization("guid_does_not_exist", "authorization_client_id", oauthClient, oauthSecret, function(err) {
                    assert(err==null);
                    done();
                });
            });

            it("should return 204 if user does exist", function(done) {
                // todo: how do a get a valid guid?
                personaClient.deleteAuthorization("guid", "authorization_client_id", oauthClient, oauthSecret, function(err) {
                    assert(err==null);
                    done();
                });
            });
        });
    });

});
