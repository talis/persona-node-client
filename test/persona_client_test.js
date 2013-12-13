'use strict';

var should = require('should');
var assert = require('assert');
var persona = require('../index.js');

describe("Persona Client Test Suite", function(){

    describe("- Constructor tests", function(){

        it("should throw error if config.persona_host is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({});
            };
            personaClient.should.throw("You must specify the Persona server host");
            done();
        });
        it("should throw error if config.persona_port is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({persona_host:"persona"});
            };
            personaClient.should.throw("You must specify the Persona server port");
            done();
        });
        it("should throw error if config.persona_scheme is not supplied", function(done){
            var personaClient = function(){
                return persona.createClient({
                    persona_host:"persona",
                    persona_port:80
                });
            };
            personaClient.should.throw("You must specify the Persona server scheme (http/https)");
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
            personaClient.should.throw("You must specify the Persona oauth route");
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
            personaClient.should.throw("You must specify the Redis host to use as a cache");
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
            personaClient.should.throw("You must specify the Redis port");
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
            personaClient.should.throw("You must specify the Redis db");
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
});