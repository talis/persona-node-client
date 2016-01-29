'use strict';

var async = require('async');
var should = require('should');
var assert = require('assert');
var persona = require('../index.js');
var cryptojs = require('crypto-js');
var sinon = require('sinon');
var _ = require("lodash");
// This is for mocking out some http responses in some tests
var PassThrough = require('stream').PassThrough;

describe("Persona Client Test Suite - User Scope Tests", function(){
    describe("- Get user scopes tests", function(){
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
            global.http = require('http');
            var requestStub = sinon.stub(http, 'request');

            var data = {scope:['fdgNy6QWGmIAl7BRjEsFtk','tdc:app:access','tdc:player:access']};
            var expected = data.scope;
            var response = new PassThrough();
            response.statusCode = 200;
            response.write(JSON.stringify(data));
            response.end();
            var request = new PassThrough();

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
            requestStub.callsArgWith(1, response).returns(request);

            // stub out the call to get obtainToken by providing a fake redisClient that returns known data
            var now = new Date().getTime() / 1000;
            var reply = {access_token: 'thisisatoken', expires_at: now + 1000};

            sinon.stub(personaClient.redisClient, "get").callsArgWith(1,null,JSON.stringify(reply));

            personaClient.obtainToken("primate","bananas",function(err,data1) {
                personaClient.getScopesForUser('guid_does_exist', data1.access_token, function(err, data){
                    assert(err == null);
                    assert(data != null);

                    data.should.be.an.instanceOf(Array).and.have.lengthOf(3);
                    data.should.eql(expected);

                    http.request.restore();
                    personaClient.redisClient.get.restore();
                    done();
                });
            });
        });

        it("should return error if token is invalid", function(done) {
            global.http = require('http');
            var requestStub = sinon.stub(http, 'request');

            var response = new PassThrough();
            response.statusCode = 401;
            response.end();
            var request = new PassThrough();

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
            requestStub.callsArgWith(1, response).returns(request);

            // stub out the call to get obtainToken by providing a fake redisClient that returns known data
            var now = new Date().getTime() / 1000;
            var reply = {access_token: 'thisisatoken', expires_at: now + 1000};

            sinon.stub(personaClient.redisClient, "get").callsArgWith(1,null,JSON.stringify(reply));

            personaClient.obtainToken("primate","bananas",function(err,data1) {
                personaClient.getScopesForUser('guid_does_exist', data1.access_token, function(err, data){
                    assert(err != null);
                    err.should.be.a.String;
                    err.should.equal("getScopesForUser failed with status code 401");
                    assert(data == null);

                    http.request.restore();
                    personaClient.redisClient.get.restore();
                    done();
                });
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
            global.http = require('http');
            var requestStub = sinon.stub(http, 'request');

            var response = new PassThrough();
            response.statusCode = 204;
            response.end();
            var request = new PassThrough();

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
            requestStub.callsArgWith(1, response).returns(request);

            // stub out the call to get obtainToken by providing a fake redisClient that returns known data
            var now = new Date().getTime() / 1000;
            var reply = {access_token: 'thisisatoken', expires_at: now + 1000};

            sinon.stub(personaClient.redisClient, "get").callsArgWith(1,null,JSON.stringify(reply));

            personaClient.obtainToken("primate","bananas",function(err,data1) {
                personaClient.addScopeToUser('guid_does_exist', data1.access_token, "test_scope", function(err, data){
                    assert(err == null);
                    assert(data == null);

                    http.request.restore();
                    personaClient.redisClient.get.restore();
                    done();
                });
            });
        });

        it("should return error if add scope fails with invalid token", function(done) {
            global.http = require('http');
            var requestStub = sinon.stub(http, 'request');

            var response = new PassThrough();
            response.statusCode = 401;
            response.end();
            var request = new PassThrough();

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
            requestStub.callsArgWith(1, response).returns(request);

            // stub out the call to get obtainToken by providing a fake redisClient that returns known data
            var now = new Date().getTime() / 1000;
            var reply = {access_token: 'thisisatoken', expires_at: now + 1000};

            sinon.stub(personaClient.redisClient, "get").callsArgWith(1,null,JSON.stringify(reply));

            personaClient.obtainToken("primate","bananas",function(err,data1) {
                personaClient.addScopeToUser('guid_does_exist', data1.access_token, "test_scope", function(err, data){
                    assert(err != null);
                    err.should.be.a.String;
                    err.should.equal("setScopesForUser failed with status code 401");
                    assert(data == null);

                    http.request.restore();
                    personaClient.redisClient.get.restore();
                    done();
                });
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
            global.http = require('http');
            var requestStub = sinon.stub(http, 'request');

            var response = new PassThrough();
            response.statusCode = 204;
            response.end();
            var request = new PassThrough();

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
            requestStub.callsArgWith(1, response).returns(request);

            // stub out the call to get obtainToken by providing a fake redisClient that returns known data
            var now = new Date().getTime() / 1000;
            var reply = {access_token: 'thisisatoken', expires_at: now + 1000};

            sinon.stub(personaClient.redisClient, "get").callsArgWith(1,null,JSON.stringify(reply));

            personaClient.obtainToken("primate","bananas",function(err,data1) {
                personaClient.removeScopeFromUser('guid_does_exist', data1.access_token, "test_scope", function(err, data){
                    assert(err == null);
                    assert(data == null);

                    http.request.restore();
                    personaClient.redisClient.get.restore();
                    done();
                });
            });
        });

        it("should return error if remove scope fails with invalid token", function(done) {
            global.http = require('http');
            var requestStub = sinon.stub(http, 'request');

            var response = new PassThrough();
            response.statusCode = 401;
            response.end();
            var request = new PassThrough();

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
            requestStub.callsArgWith(1, response).returns(request);

            // stub out the call to get obtainToken by providing a fake redisClient that returns known data
            var now = new Date().getTime() / 1000;
            var reply = {access_token: 'thisisatoken', expires_at: now + 1000};

            sinon.stub(personaClient.redisClient, "get").callsArgWith(1,null,JSON.stringify(reply));

            personaClient.obtainToken("primate","bananas",function(err,data1) {
                personaClient.removeScopeFromUser('guid_does_exist', data1.access_token, "test_scope", function(err, data){
                    assert(err != null);
                    err.should.be.a.String;
                    err.should.equal("setScopesForUser failed with status code 401");
                    assert(data == null);

                    http.request.restore();
                    personaClient.redisClient.get.restore();
                    done();
                });
            });
        });

    });
});