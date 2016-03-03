"use strict";

var should = require("should");
var assert = require("assert");
var sinon = require("sinon");
var persona = require("../index");
var _getOAuthToken = require("./utils")._getOAuthToken;
var runBeforeEach = require("./utils").beforeEach;
var runAfterEach = require("./utils").afterEach;

describe("Persona Client Test Suite - Authorization Tests", function() {

    var personaClient;

    beforeEach(function createClientAndStubs() {
        runBeforeEach(this.currentTest.parent.title + " " + this.currentTest.title, "authorization", true);

        personaClient = persona.createClient({
            persona_host:"persona",
            persona_port:80,
            persona_scheme:"http",
            persona_oauth_route:"/oauth/tokens/",
            redis_host:"localhost",
            redis_port:6379,
            redis_db:0,
            enable_debug: false
        });
        sinon.stub(personaClient.redisClient, "get").yields(null, null);
    });

    afterEach(function restoreStubs() {
        runAfterEach(this.currentTest.parent.title + " " + this.currentTest.title, "authorization", true);
        personaClient.redisClient.get.restore();
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
            personaClient.requestAuthorization("guid_does_not_exist","test title","primate","bananas",function(err,data) { // todo: move these creds somewhere else
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
                assert(err===null);
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
            personaClient.deleteAuthorization("guid_does_not_exist", "authorization_client_id","primate", "bananas",function(err) { //todo: move those credentials
                assert(err==null);
                done();
            });
        });

        it("should return 204 if user does exist", function(done) {
            // todo: how do a get a valid guid?
            personaClient.deleteAuthorization("guid", "authorization_client_id","primate", "bananas",function(err) { //todo: move those credentials
                console.log(err);
                assert(err==null);
                done();
            });
        });

    })
});
