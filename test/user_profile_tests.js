"use strict";

var should = require("should");
var assert = require("assert");
var persona = require("../index");
var runBeforeEach = require("./utils").beforeEach;
var runAfterEach = require("./utils").afterEach;

describe("Persona Client Test Suite - User Profile Tests", function() {

    beforeEach(function() {
        runBeforeEach(this.currentTest.title, "user_profile");
    });

    afterEach(function() {
        runAfterEach(this.currentTest.title, "user_profile");
    });

    describe("- Get user profile by guid tests", function() {
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

            personaClient.obtainToken("primate","bananas",function(error, token) {
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

            personaClient.obtainToken("primate","bananas",function(error, token) {
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
