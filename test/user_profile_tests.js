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

describe("Persona Client Test Suite - User Profile Tests", function(){
    describe("- Get user profile by guid tests", function(){
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
        it("should return a user object if user found", function(done){

            global.http = require('http');
            var requestStub = sinon.stub(http, 'request');

            var expected = {guid:'123',profile: {first_name:'Max', surname:'Payne'}};
            var response = new PassThrough();
            response.statusCode = 200;
            response.write(JSON.stringify(expected));
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
                personaClient.getProfileByGuid('guid_does_exist', data1.access_token, function(err, data){

                    assert(err===null);
                    assert(data!==null);

                    data.should.be.an.Object;
                    data.should.eql(expected);

                    http.request.restore();
                    personaClient.redisClient.get.restore();
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
            global.http = require('http');
            var requestStub = sinon.stub(http, 'request');

            var expected = {guid:'123',profile: {first_name:'Max', surname:'Payne'}};
            var response = new PassThrough();
            response.statusCode = 200;
            response.write(JSON.stringify(expected));
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
                personaClient.updateProfile('guid_does_exist', expected.profile, data1.access_token, function(err, data){
                    assert(err===null);
                    assert(data!==null);

                    data.should.be.an.Object;
                    data.should.eql(expected);

                    http.request.restore();
                    personaClient.redisClient.get.restore();
                    done();
                });
            });
        });
    });
});
