"use strict";

var should = require("should");
var assert = require("assert");
var persona = require("../index");
var cryptojs = require("crypto-js");
var runBeforeEach = require("./utils").beforeEach;
var runAfterEach = require("./utils").afterEach;
var leche = require("leche");
var withData = leche.withData;

describe("Persona Client Test Suite - Presigned URL Tests", function() {

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
        beforeEach(function() {
            runBeforeEach(this.currentTest.title, "presigned_url");
        });

        afterEach(function() {
            runAfterEach(this.currentTest.title, "presigned_url");
        });

        describe("- Generate and Validate Presigned Url Tests", function() {

            var secret = "canyoukeepasecret";

            it("should throw error if no URL is provided to sign", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var presignUrl = function(){
                    return personaClient.presignUrl(null, secret, null, function(err, result){});
                };

                presignUrl.should.throw("You must provide a URL to sign");
                done();

            });

            it("should throw error if no secret is provided to sign with", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var urlToSign = 'http://192.168.10.62:3000/player?shortcode=google&expires=1395160411633';

                var presignUrl = function(){
                    return personaClient.presignUrl(urlToSign, null, null, function(err, result){});
                };

                presignUrl.should.throw("You must provide a secret with which to sign the url");
                done();

            });

            it("should generate presigned URL", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var urlToSign = 'http://192.168.10.62:3000/player?shortcode=google&expires=1395160411633';
                var expectedHash = cryptojs.HmacSHA256(urlToSign, secret);

                personaClient.presignUrl(urlToSign, secret, null, function(err, result){
                    if(err) return done(err);

                    result.should.equal('http://192.168.10.62:3000/player?shortcode=google&expires=1395160411633&signature='+expectedHash);
                    done();
                });

            });

            it("should generate presigned URL and add default expiry", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var urlToSign = 'http://192.168.10.62:3000/player?shortcode=google';

                personaClient.presignUrl(urlToSign, secret, null, function(err, result){
                    if(err) return done(err);

                    result.should.containEql('&expires=');
                    done();
                });

            });

            it("should generate presigned URL and add passed expiry", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var urlToSign = 'http://192.168.10.62:3000/player?shortcode=google';

                var baseUrl = 'http://192.168.10.62:3000/player?shortcode=google';
                var expiry = new Date().getTime() + 86400;

                var urlWithExp = baseUrl + '&expires=' + expiry;

                var expectedHash = cryptojs.HmacSHA256(urlWithExp, secret);

                var expectedURL = baseUrl + '&expires=' + expiry + '&signature=' + expectedHash;

                personaClient.presignUrl(urlToSign, secret, expiry, function(err, result){
                    if(err) return done(err);

                    result.should.equal(expectedURL);
                    done();
                });

            });

            it("should generate presigned URL that has hash component", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var urlToSign = 'http://192.168.10.62:3000/player?shortcode=google&expires=1395160411633#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
                var expectedHash = cryptojs.HmacSHA256(urlToSign, secret);
                var expectedUrl = 'http://192.168.10.62:3000/player?shortcode=google&expires=1395160411633&signature=' + expectedHash + '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';

                personaClient.presignUrl(urlToSign, secret, null, function(err, result){
                    if(err) return done(err);

                    result.should.equal(expectedUrl);

                    done();
                });

            });

            it("should generate presigned URL that has hash component and add default expiry", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var urlHash = '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
                var urlToSign = 'http://192.168.10.62:3000/player?shortcode=google' + urlHash;

                personaClient.presignUrl(urlToSign, secret, null, function(err, result){
                    if(err) return done(err);

                    result.should.containEql('&expires=');
                    result.should.containEql(urlHash);

                    done();
                });

            });

            it("should generate presigned URL that has hash component and add passed expiry", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var urlHash = '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
                var baseUrl = 'http://192.168.10.62:3000/player?shortcode=google';
                var urlToSign = baseUrl + urlHash;
                var expiry = new Date().getTime() + 86400;

                var urlWithExp = baseUrl + '&expires=' + expiry + urlHash;

                var expectedHash = cryptojs.HmacSHA256(urlWithExp, secret);

                var expectedURL = baseUrl + '&expires=' + expiry + '&signature=' + expectedHash + urlHash;

                personaClient.presignUrl(urlToSign, secret, expiry, function(err, result){
                    if(err) return done(err);

                    result.should.equal(expectedURL);

                    done();
                });

            });

            it("should throw error if no presigned URL is provided to validate", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var validateUrl = function(){
                    return personaClient.isPresignedUrlValid(null, secret);
                };

                validateUrl.should.throw("You must provide a URL to validate");
                done();

            });

            it("should throw error if no secret is provided to validate", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var urlToValidate = 'http://192.168.10.62:3000/player?shortcode=google&expires=1395229157990&signature=ae1ef4f1f2e8a45643e51ab34cc1d08dd627f5bb6e9569b84bcce622040a41fb#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';

                var validateUrl = function(){
                    return personaClient.isPresignedUrlValid(urlToValidate, null);
                };

                validateUrl.should.throw("You must provide a secret with which to validate the url");
                done();

            });

            it("should validate a presigned URL with no querystring or hash parameters", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var baseUrl = 'http://192.168.10.62:3000/player';
                var expiry = new Date().getTime() + 86400;

                var urlWithExp = baseUrl + '?expires=' + expiry;

                var hash = cryptojs.HmacSHA256(urlWithExp, secret);

                var urlToValidate = baseUrl + '?expires=' + expiry + '&signature=' + hash;

                var result = personaClient.isPresignedUrlValid(urlToValidate, secret);

                result.should.equal(true);

                done();
            });

            it("should validate a presigned URL", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var urlHash = '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
                var baseUrl = 'http://192.168.10.62:3000/player?shortcode=google';
                var urlToSign = baseUrl + urlHash;
                var expiry = new Date().getTime() + 86400;

                var urlWithExp = baseUrl + '&expires=' + expiry + urlHash;

                var hash = cryptojs.HmacSHA256(urlWithExp, secret);

                var urlToValidate = baseUrl + '&expires=' + expiry + '&signature=' + hash + urlHash;

                var result = personaClient.isPresignedUrlValid(urlToValidate, secret);

                result.should.equal(true);

                done();
            });

            it("should validate a presigned URL has an expiry", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var urlHash = '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
                var baseUrl = 'http://192.168.10.62:3000/player?shortcode=google';
                var urlToSign = baseUrl + urlHash;
                var hash = cryptojs.HmacSHA256(urlToSign, secret);

                var urlToValidate = baseUrl + '&signature=' + hash + urlHash;

                var result = personaClient.isPresignedUrlValid(urlToValidate, secret);

                result.should.equal(false);

                done();
            });

            it("should validate a presigned URL has expired", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var urlHash = '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
                var baseUrl = 'http://192.168.10.62:3000/player?shortcode=google';
                var urlToSign = baseUrl + urlHash;
                var expiry = Math.floor(new Date().getTime()/1000) - 5;

                var urlWithExp = baseUrl + '&expires=' + expiry + urlHash;

                var hash = cryptojs.HmacSHA256(urlWithExp, secret);

                var urlToValidate = baseUrl + '&expires=' + expiry + '&signature=' + hash + urlHash;

                var result = personaClient.isPresignedUrlValid(urlToValidate, secret);

                result.should.equal(false);

                done();
            });

            it("should validate a presigned URL is invalid", function(done){
                var personaClient = persona.createClient("test-suite",personaClientConfig);

                var urlHash = '#/modules/52d01975d705e4730100000a/resources/5322e5413c53585456000006';
                var baseUrl = 'http://192.168.10.62:3000/player?shortcode=google';
                var urlToSign = baseUrl + urlHash;
                var expiry = new Date().getTime() + 86400;

                var urlWithExp = baseUrl + '&expiry=' + expiry + urlHash + '23'; // add additional data that will cause an invalid hash to be generated

                var hash = cryptojs.HmacSHA256(urlWithExp, secret);

                var urlToValidate = baseUrl + '&expiry=' + expiry + '&signature=' + hash + urlHash;

                var result = personaClient.isPresignedUrlValid(urlToValidate, secret);

                result.should.equal(false);

                done();
            });

        });
    });

});
