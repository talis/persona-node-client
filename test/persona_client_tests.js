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

describe("Persona Client Test Suite - Constructor & Token Tests", function(){
    describe("- Constructor tests", function(){
        it("should throw error if config.persona_host is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({});
            };
            personaClient.should.throw("You must specify the persona host");
            done();
        });
        it("should throw error if config.persona_port is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({persona_host:"persona"});
            };
            personaClient.should.throw("You must specify the persona port");
            done();
        });
        it("should throw error if config.persona_scheme is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80
                });
            };
            personaClient.should.throw("You must specify the persona scheme");
            done();
        });
        it("should throw error if config.persona_oauth_route is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http"
                });
            };
            personaClient.should.throw("You must specify the persona oauth route");
            done();
        });
        it("should throw error if config.redis_host is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens"
                });
            };
            personaClient.should.throw("You must specify the redis host");
            done();
        });
        it("should throw error if config.redis_port is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens",
                    redis_host:"persona"
                });
            };
            personaClient.should.throw("You must specify the redis port");
            done();
        });
        it("should throw error if config.redis_db is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens",
                    redis_host:"persona",
                    redis_port:6379
                });
            };
            personaClient.should.throw("You must specify the redis db");
            done();
        });
        it("should NOT throw any error if all config params are defined", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80,
                    persona_scheme:"http",
                    persona_oauth_route:"/oauth/tokens",
                    redis_host:"persona",
                    redis_port:6379,
                    redis_db:0
                });
            };
            personaClient.should.not.throw();
            done();
        });
    });

    describe("- Generate token tests", function() {
        var clock;
        beforeEach(function () {
            clock = sinon.useFakeTimers();
        });

        afterEach(function () {
            clock.restore();
        });

        it("should throw error if there is no id",function(done) {
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

            var validateUrl = function(){
                return personaClient.obtainToken(null,"bananas",function(err,data) {});
            };

            validateUrl.should.throw("You must provide an ID to obtain a token");
            done();
        });
        it("should throw error if there is no secret",function(done) {
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

            var validateUrl = function(){
                return personaClient.obtainToken("primate",null,function(err,data) {});
            };

            validateUrl.should.throw("You must provide a secret to obtain a token");
            done();
        });
        it("should return a token, and cache that token",function(done) {
            global.http = require('http');
            var requestStub = sinon.stub(http, 'request');

            var now = new Date().getTime() / 1000;
            var expected = {access_token: 'thisisatoken', expires_in: now + 1800, scope: 'primate', token_type: 'tokentype'};
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

            personaClient._removeTokenFromCache("primate","bananas",function(err) {
                assert(err===null);
                personaClient.obtainToken("primate","bananas",function(err,data1) {
                    assert(err===null);
                    data1.should.have.property("access_token");
                    data1.should.have.property("expires_in");
                    data1.expires_in.should.equal(1800);
                    data1.should.have.property("scope");
                    data1.should.have.property("token_type");
                    clock.tick(3000); //move clock forward by 1s to make sure expires_in is different

                    personaClient.obtainToken("primate","bananas",function(err,data2) {
                        assert(err===null);
                        data2.should.have.property("access_token");
                        data2.should.have.property("expires_in");
                        data2.should.have.property("scope");
                        data2.should.have.property("token_type");

                        data1.access_token.should.equal(data2.access_token);
                        data1.expires_in.should.not.equal(data2.expires_in);

                        http.request.restore();

                        done();
                    });
                });
            });
        });
        it("should not return a token",function(done) {
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

            personaClient.obtainToken("primate","wrong_password",function(err,data) {
                assert(err!=null);
                err.should.be.a.String;
                err.should.equal("Generate token failed with status code 400");
                assert(data===null);
                done();
            });
        });
    });
});
