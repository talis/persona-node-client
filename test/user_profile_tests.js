"use strict";

var should = require("should");
var assert = require("assert");
var persona = require("../index");
var runBeforeEach = require("./utils").beforeEach;
var runAfterEach = require("./utils").afterEach;
var leche = require("leche");
var sinon = require("sinon");
var withData = leche.withData;

describe("Persona Client Test Suite - User Profile Tests", function() {

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
            cert_background_refresh: false,
        }
    }, function(personaClientConfig) {
        var personaClient, spy;
        beforeEach(function() {
            runBeforeEach(this.currentTest.title, "user_profile");
            personaClient = persona.createClient("test-suite",personaClientConfig);
            spy = sinon.spy(personaClient.http, "request");
        });

        afterEach(function() {
            runAfterEach(this.currentTest.title, "user_profile",spy);
            personaClient.http.request.restore();
        });

        describe("- Get user profile by guid tests", function() {
            it("should throw an error if guid is not present", function(done) {
                personaClient.getProfileByGuid(null,"",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid and token are required strings");
                    assert(data===null);
                    done();
                });
            });
            it("should throw an error if guid is not a string", function(done) {
                personaClient.getProfileByGuid({},"token",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid and token are required strings");
                    assert(data===null);
                    done();
                });
            });
            it("should throw an error if token is not present", function(done){
                personaClient.getProfileByGuid("GUID",null,function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid and token are required strings");
                    assert(data===null);
                    done();
                });
            });
            it("should throw an error if token is not a string", function(done){
                personaClient.getProfileByGuid("GUID",{},function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid and token are required strings");
                    assert(data===null);
                    done();
                });
            });
            it("should fail with a status code of 404 for a user not found", function(done){
                personaClient.obtainToken({id: oauthClient, secret: oauthSecret}, function(err, data1) {
                    personaClient.getProfileByGuid('GUID', data1.access_token, function(err, data){
                        assert(err!=null);
                        err.should.be.a.String;
                        err.should.equal("getProfileByGuid failed with status code 404");
                        assert(data===null);
                        done();
                    });
                });
            });
            it("should return a user object if user found", function(done) {
                var expected = {
                    "_id": {
                        "$id": "56a24521f8203aa459000024"
                    },
                    "guid": "fdgNy6QWGmIAl7BRjEsFtA",
                    "gupids": [
                        "google:AItOawmPwlmsEaQiLSJCISvHLO3uT7F4tYKwtUE",
                        "trapdoor:test.tn@talis.com"
                    ],
                    "profile": {
                        "first_name": "TN",
                        "surname": "TestAccount",
                        "email": "test.tn@talis.com"
                    }
                };

                personaClient.obtainToken({id: oauthClient, secret: oauthSecret}, function(error, token) {
                    assert(error == null);
                    personaClient.getProfileByGuid('fdgNy6QWGmIAl7BRjEsFtA', token.access_token, function(error, data) {
                        assert(error == null);
                        assert(data != null);
                        data.should.be.an.Object;
                        data.should.containEql(expected);
                        done();
                    });
                });
            });
        });

        describe("- Update user profile tests", function(){
            it("should throw an error if guid is not set", function(done){
                personaClient.updateProfile(null,{}, "",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid and token are required strings");
                    assert(data===null);
                    done();
                });
            });
            it("should throw an error if guid is not a string", function(done){
                personaClient.updateProfile({},{}, "",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid and token are required strings");
                    assert(data===null);
                    done();
                });
            });
            it("should throw an error if profile is not set", function(done){
                personaClient.updateProfile("GUID",null, "",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("profile is a required object");
                    assert(data===null);
                    done();
                });
            });
            it("should throw an error if profile not an object", function(done){
                personaClient.updateProfile("GUID","PROFILE", "",function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("profile is a required object");
                    assert(data===null);
                    done();
                });
            });
            it("should throw an error if token is not set", function(done){
                personaClient.updateProfile("GUID",{}, null,function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid and token are required strings");
                    assert(data===null);
                    done();
                });
            });
            it("should throw an error if token it not a string", function(done){
                personaClient.updateProfile("GUID",{}, {},function(err,data) {
                    assert(err!=null);
                    err.should.be.a.String;
                    err.should.equal("guid and token are required strings");
                    assert(data===null);
                    done();
                });
            });
            it("should return a user if success", function(done){
                var expected = {
                    "_id": {
                        "$id": "56a24521f8203aa459000024"
                    },
                    "guid": "fdgNy6QWGmIAl7BRjEsFtA",
                    "gupids": [
                        "google:AItOawmPwlmsEaQiLSJCISvHLO3uT7F4tYKwtUE",
                        "trapdoor:test.tn@talis.com"
                    ],
                    "profile": {
                        "first_name": "TN",
                        "surname": "TestAccount",
                        "email": "test.tn@talis.com"
                    }
                };

                personaClient.obtainToken({id: oauthClient, secret: oauthSecret}, function(error, token) {
                    personaClient.updateProfile('fdgNy6QWGmIAl7BRjEsFtA', expected.profile, token.access_token, function(error, data) {
                        assert(error == null);
                        assert(data != null);
                        data.should.be.an.Object;
                        data.should.containEql(expected);
                        done();
                    });
                });
            });
        });
    });
});
