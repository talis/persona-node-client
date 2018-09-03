"use strict";

var should = require("should");
var assert = require("assert");
var persona = require("../index");
var runBeforeEach = require("./utils").beforeEach;
var runAfterEach = require("./utils").afterEach;
var leche = require("leche");
var sinon = require("sinon");
var withData = leche.withData;
var _ = require("lodash");
var _getStubRequest = require("./utils")._getStubRequest;
var _getStubResponse = require("./utils")._getStubResponse;

describe("Persona Client Test Suite - User Scope Tests", function() {

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
            runBeforeEach(this.currentTest.title, "user_scope");
            personaClient = persona.createClient("test-suite",personaClientConfig);
            spy = sinon.spy(personaClient.http, "request");
        });

        afterEach(function() {
            runAfterEach(this.currentTest.title, "user_scope");
            personaClient.http.request.restore();
        });

        describe("- Get user scopes tests", function() {
            _.map(["guid","token"],function(optsKey) {
                var goodOpts = {guid: "some_guid", profile: {}, token: "some_token"};
                it("should throw an error if "+optsKey+" is not present", function(done) {
                    var badOpts = _.clone(goodOpts);
                    badOpts[optsKey] = null;
                    try {
                        personaClient.getScopesForUser(badOpts,function(err,data) {
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
                        personaClient.getScopesForUser(badOpts,function(err,data) {
                            done("callback should not be invoked");
                        });
                    } catch (err) {
                        err.message.should.equal(optsKey+" failed isString validation");
                        done();
                    }
                });
            });

            it("should throw an error if guid is not valid", function(done) {
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                personaClient.obtainToken({id: oauthClient, secret: oauthSecret}, function(err, data1) {
                    personaClient.getScopesForUser({guid:"guid", token:data1.access_token}, function(err, data) {
                        assert(err != null);
                        err.should.be.a.String;
                        err.should.equal("getScopesForUser failed with status code 404");
                        assert(data == null);
                        done();
                    });
                });
            });

            it("should return scopes if guid is valid", function(done) {
                var data = {scope:['fdgNy6QWGmIAl7BRjEsFtk','tdc:app:access','tdc:player:access']};
                var expected = data.scope;

                var personaClient = persona.createClient("test-suite",personaClientConfig);

                personaClient.obtainToken({id: oauthClient, secret: oauthSecret}, function(err, data1) {
                    personaClient.getScopesForUser({guid:'fdgNy6QWGmIAl7BRjEsFtk', token:data1.access_token}, function(err, data) {
                        assert(err == null);
                        assert(data != null);
                        data.should.be.an.instanceOf(Array).and.have.lengthOf(3);
                        data.should.eql(expected);
                        done();
                    });
                });
            });

            it("should return error if token is invalid", function(done) {
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                personaClient.getScopesForUser({guid: 'guid_does_exist', token: "invalid"}, function(err, data) {
                    assert(err != null);
                    err.should.be.a.String;
                    err.should.equal("getScopesForUser failed with status code 401");
                    assert(data == null);
                    done();
                });
            });
        });

        describe("- Add scope to user tests", function(){
            _.map(["guid","token","scope"],function(optsKey) {
                var goodOpts = {guid: "some_guid", token: "some_token", scope: "someScope"};
                it("should throw an error if "+optsKey+" is not present", function(done) {
                    var badOpts = _.clone(goodOpts);
                    badOpts[optsKey] = null;
                    try {
                        personaClient.addScopeToUser(badOpts,function(err,data) {
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
                        personaClient.addScopeToUser(badOpts,function(err,data) {
                            done("callback should not be invoked");
                        });
                    } catch (err) {
                        err.message.should.equal(optsKey+" failed isString validation");
                        done();
                    }
                });
            });

            it("should return no error if add scope successful", function(done) {
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                personaClient.obtainToken({id: oauthClient, secret: oauthSecret}, function(err, data1) {
                    personaClient.addScopeToUser({guid:'fdgNy6QWGmIAl7BRjEsFtk', token:data1.access_token, scope:"test_scope"}, function(err, data){
                        assert(err == null);
                        assert(data == null);
                        done();
                    });
                });
            });

            it("should return error if add scope fails with invalid token", function(done) {
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                personaClient.addScopeToUser({guid:"fdgNy6QWGmIAl7BRjEsFtk", token:"invalid", scope:"test_scope"}, function(err, data){
                    assert(err != null);
                    err.should.be.a.String;
                    err.should.equal("setScopesForUser failed with status code 401");
                    assert(data == null);
                    done();
                });
            });
        });

        describe("- Remove scope from user tests", function(){
            _.map(["guid","token","scope"],function(optsKey) {
                var goodOpts = {guid: "some_guid", token: "some_token", scope: "someScope"};
                it("should throw an error if "+optsKey+" is not present", function(done) {
                    var badOpts = _.clone(goodOpts);
                    badOpts[optsKey] = null;
                    try {
                        personaClient.removeScopeFromUser(badOpts,function(err,data) {
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
                        personaClient.removeScopeFromUser(badOpts,function(err,data) {
                            done("callback should not be invoked");
                        });
                    } catch (err) {
                        err.message.should.equal(optsKey+" failed isString validation");
                        done();
                    }
                });
            });

            it("should return no error if remove scope successful", function(done) {
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                personaClient.obtainToken({id: oauthClient, secret: oauthSecret}, function(err, data1) {
                    personaClient.removeScopeFromUser({guid:'fdgNy6QWGmIAl7BRjEsFtk', token:data1.access_token, scope:"test_scope"}, function(err, data){
                        assert(err == null);
                        assert(data == null);
                        done();
                    });
                });
            });

            it("should return error if remove scope fails with invalid token", function(done) {
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                personaClient.removeScopeFromUser({guid:'fdgNy6QWGmIAl7BRjEsFtk', token:"invalid", scope:"test_scope"}, function(err, data){
                    assert(err != null);
                    err.should.be.a.String;
                    err.should.equal("setScopesForUser failed with status code 401");
                    assert(data == null);
                    done();
                });
            });
        });
    });
});
