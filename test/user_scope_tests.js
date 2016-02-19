"use strict";

var should = require("should");
var assert = require("assert");
var persona = require("../index");
var runBeforeEach = require("./utils").beforeEach;
var runAfterEach = require("./utils").afterEach;

describe("Persona Client Test Suite - User Scope Tests", function() {

    beforeEach(function() {
        runBeforeEach(this.currentTest.title, "user_scope");
    });

    afterEach(function() {
        runAfterEach(this.currentTest.title, "user_scope");
    });

    describe("- Get user scopes tests", function() {
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

            personaClient.getScopesForUser(null,"token",function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid and token are required strings");
                assert(data == null);
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

            personaClient.getScopesForUser({},"token",function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid and token are required strings");
                assert(data == null);
                done();
            });
        });

        it("should throw an error if token is not present", function(done) {
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

            personaClient.getScopesForUser("guid",null,function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid and token are required strings");
                assert(data == null);
                done();
            });
        });

        it("should throw an error if token is not a string", function(done) {
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

            personaClient.getScopesForUser("guid",{},function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid and token are required strings");
                assert(data == null);
                done();
            });
        });

        it("should throw an error if guid is not valid", function(done) {
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
                personaClient.getScopesForUser("guid",data1.access_token,function(err,data) {
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
                personaClient.getScopesForUser('fdgNy6QWGmIAl7BRjEsFtk', data1.access_token, function(err, data) {
                    assert(err == null);
                    assert(data != null);
                    data.should.be.an.instanceOf(Array).and.have.lengthOf(3);
                    data.should.eql(expected);
                    done();
                });
            });
        });

        it("should return error if token is invalid", function(done) {
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

            personaClient.getScopesForUser('guid_does_exist', "invalid", function(err, data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("getScopesForUser failed with status code 401");
                assert(data == null);
                done();
            });
        });
    });

    describe("- Add scope to user tests", function(){
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

            personaClient.addScopeToUser(null,"token","scope",function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid, token and scope are required strings");
                assert(data == null);
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

            personaClient.addScopeToUser({},"token","scope",function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid, token and scope are required strings");
                assert(data == null);
                done();
            });
        });

        it("should throw an error if token is not present", function(done) {
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

            personaClient.addScopeToUser("guid",null,"scope",function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid, token and scope are required strings");
                assert(data == null);
                done();
            });
        });

        it("should throw an error if token is not a string", function(done) {
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

            personaClient.addScopeToUser("guid",{},"scope",function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid, token and scope are required strings");
                assert(data == null);
                done();
            });
        });

        it("should throw an error if scope is not present", function(done) {
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

            personaClient.addScopeToUser("guid","token",null,function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid, token and scope are required strings");
                assert(data == null);
                done();
            });
        });

        it("should throw an error if scope is not a string", function(done) {
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

            personaClient.addScopeToUser("guid","token",{},function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid, token and scope are required strings");
                assert(data == null);
                done();
            });
        });

        it("should return no error if add scope successful", function(done) {
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
                personaClient.addScopeToUser('fdgNy6QWGmIAl7BRjEsFtk', data1.access_token, "test_scope", function(err, data){
                    assert(err == null);
                    assert(data == null);
                    done();
                });
            });
        });

        it("should return error if add scope fails with invalid token", function(done) {
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

            personaClient.addScopeToUser("fdgNy6QWGmIAl7BRjEsFtk", "invalid", "test_scope", function(err, data){
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("setScopesForUser failed with status code 401");
                assert(data == null);
                done();
            });
        });
    });

    describe("- Remove scope from user tests", function(){
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

            personaClient.removeScopeFromUser(null,"token","scope",function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid, token and scope are required strings");
                assert(data == null);
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

            personaClient.removeScopeFromUser({},"token","scope",function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid, token and scope are required strings");
                assert(data == null);
                done();
            });
        });

        it("should throw an error if token is not present", function(done) {
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

            personaClient.removeScopeFromUser("guid",null,"scope",function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid, token and scope are required strings");
                assert(data == null);
                done();
            });
        });

        it("should throw an error if token is not a string", function(done) {
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

            personaClient.removeScopeFromUser("guid",{},"scope",function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid, token and scope are required strings");
                assert(data == null);
                done();
            });
        });

        it("should throw an error if scope is not present", function(done) {
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

            personaClient.removeScopeFromUser("guid","token",null,function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid, token and scope are required strings");
                assert(data == null);
                done();
            });
        });

        it("should throw an error if scope is not a string", function(done) {
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

            personaClient.removeScopeFromUser("guid","token",{},function(err,data) {
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("guid, token and scope are required strings");
                assert(data == null);
                done();
            });
        });

        it("should return no error if remove scope successful", function(done) {
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
                personaClient.removeScopeFromUser('fdgNy6QWGmIAl7BRjEsFtk', data1.access_token, "test_scope", function(err, data){
                    assert(err == null);
                    assert(data == null);
                    done();
                });
            });
        });

        it("should return error if remove scope fails with invalid token", function(done) {
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

            personaClient.removeScopeFromUser('fdgNy6QWGmIAl7BRjEsFtk', "invalid", "test_scope", function(err, data){
                assert(err != null);
                err.should.be.a.String;
                err.should.equal("setScopesForUser failed with status code 401");
                assert(data == null);
                done();
            });
        });
    });
});
