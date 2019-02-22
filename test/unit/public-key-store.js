"use strict";

var should = require("should");
var assert = require("assert");
var sinon = require("sinon");
var proxyquire = require('proxyquire');

describe('public-key-store', function() {
    var personaClient;
    
    var testCacheKey = 'key';
    var testPublicKey = 'publickey';
    var testCacheTimeout = 10;
    var testXRequestId = '1234';
    var error = 'Unable to connect to persona';

    beforeEach(function() {
        personaClient = {
            _formatCacheKey: sinon.stub(),
            _removeTokenFromCache: sinon.stub(),
            tokenCache: {
                get: sinon.stub(),
                set: sinon.stub(),
            },
            config: {
                cert_timeout_sec: testCacheTimeout,
            },
            obtainToken: sinon.stub(),
            log: sinon.stub(),
            debug: sinon.stub(),
            error: sinon.stub(),
        };
    });

    describe('set', function() {
        it('correctly sets cache', function() {
            var publicKeyStore = require('../../client/lib/public-key-store');

            publicKeyStore.set(personaClient, testCacheKey, testPublicKey);

            personaClient.log.calledOnce.should.equal(true);

            personaClient.log.calledWith('debug', 'Caching public key for ' + testCacheTimeout + 's').should.equal(true);

            personaClient.tokenCache.set.calledOnce.should.equal(true);

            personaClient.tokenCache.set.calledWith(testCacheKey, testPublicKey, testCacheTimeout).should.equal(true);
        });
    });

    describe('get', function() {
        describe('refresh', function() {
            it('getRemotePublicKey error', function(done) {
                var getRemotePublicKeyStub = sinon.stub();
                var publicKeyStore = proxyquire('../../client/lib/public-key-store', {
                    './remote-public-key': getRemotePublicKeyStub, 
                });
                
                getRemotePublicKeyStub.callsFake((client, cacheKey, xRequestId, callback) => {
                    callback(error);
                });

                publicKeyStore.get(personaClient, testCacheKey, true, testXRequestId, (err) => {
                    getRemotePublicKeyStub.calledOnce.should.equal(true);
                    getRemotePublicKeyStub.calledWith(personaClient, testCacheKey, testXRequestId).should.equal(true);

                    err.should.equal(error); 
                    done();
                }) 
            });

            it('getRemotePublicKey returns publicKey and is saved to cache', function(done) {
                var getRemotePublicKeyStub = sinon.stub();
                var publicKeyStore = proxyquire('../../client/lib/public-key-store', {
                    './remote-public-key': getRemotePublicKeyStub, 
                });
                
                getRemotePublicKeyStub.callsFake((client, cacheKey, xRequestId, callback) => {
                    callback(null, testPublicKey);
                });

                publicKeyStore.get(personaClient, testCacheKey, true, testXRequestId, (err, publicKey) => {
                    getRemotePublicKeyStub.calledOnce.should.equal(true);
                    getRemotePublicKeyStub.calledWith(personaClient, testCacheKey, testXRequestId).should.equal(true);

                    personaClient.log.calledOnce.should.equal(true);

                    personaClient.log.calledWith('debug', 'Caching public key for ' + testCacheTimeout + 's').should.equal(true);

                    personaClient.tokenCache.set.calledOnce.should.equal(true);

                    personaClient.tokenCache.set.calledWith(testCacheKey, testPublicKey, testCacheTimeout).should.equal(true);

                    publicKey.should.equal(testPublicKey);
                    done();
                }) 
            });
        });

        describe('use cache', function() {
            it('found in cache', function(done) {
                var publicKeyStore = require('../../client/lib/public-key-store');
                
                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback(null, testPublicKey);
                });

                publicKeyStore.get(personaClient, testCacheKey, false, testXRequestId, (err, publicKey) => {
                    personaClient.tokenCache.get.calledOnce.should.equal(true);
                    personaClient.tokenCache.get.calledWith(testCacheKey).should.equal(true);

                    personaClient.log.calledOnce.should.equal(true);
                    personaClient.log.calledWith('debug', 'Using public key from cache').should.equal(true);

                    publicKey.should.equal(testPublicKey); 
                    done();
                }) 
            });
            
            it('not found in cache, getRemotePublicKey error', function(done) {
                var getRemotePublicKeyStub = sinon.stub();
                var publicKeyStore = proxyquire('../../client/lib/public-key-store', {
                    './remote-public-key': getRemotePublicKeyStub, 
                });
                
                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback();
                });

                getRemotePublicKeyStub.callsFake((client, cacheKey, xRequestId, callback) => {
                    callback(error);
                });

                publicKeyStore.get(personaClient, testCacheKey, false, testXRequestId, (err) => {
                    getRemotePublicKeyStub.calledOnce.should.equal(true);
                    getRemotePublicKeyStub.calledWith(personaClient, testCacheKey, testXRequestId).should.equal(true);

                    personaClient.tokenCache.get.calledOnce.should.equal(true);
                    personaClient.tokenCache.get.calledWith(testCacheKey).should.equal(true);

                    err.should.equal(error); 
                    done();
                }) 
            });
        
            it('invalid key found in cache, getRemotePublicKey error', function(done) {
                var getRemotePublicKeyStub = sinon.stub();
                var publicKeyStore = proxyquire('../../client/lib/public-key-store', {
                    './remote-public-key': getRemotePublicKeyStub, 
                });
                
                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback(null, {});
                });

                getRemotePublicKeyStub.callsFake((client, cacheKey, xRequestId, callback) => {
                    callback(error);
                });

                publicKeyStore.get(personaClient, testCacheKey, false, testXRequestId, (err) => {
                    getRemotePublicKeyStub.calledOnce.should.equal(true);
                    getRemotePublicKeyStub.calledWith(personaClient, testCacheKey, testXRequestId).should.equal(true);

                    personaClient.tokenCache.get.calledOnce.should.equal(true);
                    personaClient.tokenCache.get.calledWith(testCacheKey).should.equal(true);

                    err.should.equal(error); 
                    done();
                }) 
            });

            it('not found in cache, getRemotePublicKey returns publicKey and is saved to cache', function(done) {
                var getRemotePublicKeyStub = sinon.stub();
                var publicKeyStore = proxyquire('../../client/lib/public-key-store', {
                    './remote-public-key': getRemotePublicKeyStub, 
                });
                
                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback();
                });

                getRemotePublicKeyStub.callsFake((client, cacheKey, xRequestId, callback) => {
                    callback(null, testPublicKey);
                });

                publicKeyStore.get(personaClient, testCacheKey, false, testXRequestId, (erri, publicKey) => {
                    getRemotePublicKeyStub.calledOnce.should.equal(true);
                    getRemotePublicKeyStub.calledWith(personaClient, testCacheKey, testXRequestId).should.equal(true);

                    personaClient.tokenCache.get.calledOnce.should.equal(true);
                    personaClient.tokenCache.get.calledWith(testCacheKey).should.equal(true);
                    
                    personaClient.log.calledOnce.should.equal(true);

                    personaClient.log.calledWith('debug', 'Caching public key for ' + testCacheTimeout + 's').should.equal(true);

                    personaClient.tokenCache.set.calledOnce.should.equal(true);

                    personaClient.tokenCache.set.calledWith(testCacheKey, testPublicKey, testCacheTimeout).should.equal(true);

                    publicKey.should.equal(testPublicKey);
                    done();
                }) 
            });
        
            it('invalid key found in cache, getRemotePublicKey returns publicKey and is saved to cache', function(done) {
                var getRemotePublicKeyStub = sinon.stub();
                var publicKeyStore = proxyquire('../../client/lib/public-key-store', {
                    './remote-public-key': getRemotePublicKeyStub, 
                });
                
                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback(null, {});
                });

                getRemotePublicKeyStub.callsFake((client, cacheKey, xRequestId, callback) => {
                    callback(null, testPublicKey);
                });

                publicKeyStore.get(personaClient, testCacheKey, false, testXRequestId, (err, publicKey) => {
                    getRemotePublicKeyStub.calledOnce.should.equal(true);
                    getRemotePublicKeyStub.calledWith(personaClient, testCacheKey, testXRequestId).should.equal(true);

                    personaClient.tokenCache.get.calledOnce.should.equal(true);
                    personaClient.tokenCache.get.calledWith(testCacheKey).should.equal(true);
                    
                    personaClient.log.calledOnce.should.equal(true);

                    personaClient.log.calledWith('debug', 'Caching public key for ' + testCacheTimeout + 's').should.equal(true);

                    personaClient.tokenCache.set.calledOnce.should.equal(true);

                    personaClient.tokenCache.set.calledWith(testCacheKey, testPublicKey, testCacheTimeout).should.equal(true);

                    publicKey.should.equal(testPublicKey);
                    done();
                }) 
            });

        });
    });

    describe('obtain', function() {
        var testExpiredTimestamp = 1550620790;
        var testUnexpiredTimestamp = 1550620890;
        var testPublicKeyObject = {
            access_token: 'token',
        };

        var testOpts = {
            id: 'idstring',
            secret: 'shhh',
            xRequestId: testXRequestId,
        };

        var testObtainTokenCacheKey = 'obtain_token:'+testOpts.id;

        var testTimestamp = 1550620800000;

        var originalDateNow;

        describe('found in cache', function() {
            beforeEach(function() {
                originalDateNow = Date.now;
                Date.now = () => testTimestamp;
            });

            afterEach(function() {
                Date.now = originalDateNow;
            });

            it('valid object returned', function(done) {
                var publicKeyStore = require('../../client/lib/public-key-store');
               
                testPublicKeyObject.expires_at = testUnexpiredTimestamp;
        
                var testPublicKeyString = JSON.stringify(testPublicKeyObject);

                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback(null, testPublicKeyObject);
                });

                personaClient._formatCacheKey.returns(testObtainTokenCacheKey);

                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback(null, testPublicKeyObject);
                });

                publicKeyStore.obtainToken(personaClient, testOpts, (err, publicKey) => {
                    personaClient.tokenCache.get.calledOnce.should.equal(true);

                    personaClient.tokenCache.get.calledWith(testObtainTokenCacheKey).should.equal(true);

                    personaClient.debug.calledTwice.should.equal(true);

                    personaClient.debug.getCall(0).args[0].should.equal('Found cached token for key ' + testObtainTokenCacheKey + ': ' + testPublicKeyString);
                    
                    personaClient.debug.getCall(1).args[0].should.equal('New expires_in is 90');

                    publicKey.access_token.should.equal(testPublicKeyObject.access_token);
                    publicKey.expires_at.should.equal(testPublicKeyObject.expires_at);
                    publicKey.expires_in.should.equal(90);
                    done(); 
                });
            });
            
            it('valid string returned', function(done) {
                var publicKeyStore = require('../../client/lib/public-key-store');
               
                testPublicKeyObject.expires_at = testUnexpiredTimestamp;
        
                var testPublicKeyString = JSON.stringify(testPublicKeyObject);

                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback(null, testPublicKeyString);
                });

                personaClient._formatCacheKey.returns(testObtainTokenCacheKey);

                publicKeyStore.obtainToken(personaClient, testOpts, (err, publicKey) => {
                    personaClient.tokenCache.get.calledOnce.should.equal(true);

                    personaClient.tokenCache.get.calledWith(testObtainTokenCacheKey).should.equal(true);

                    personaClient.debug.calledTwice.should.equal(true);

                    personaClient.debug.getCall(0).args[0].should.equal('Found cached token for key ' + testObtainTokenCacheKey + ': ' + testPublicKeyString);
                    
                    personaClient.debug.getCall(1).args[0].should.equal('New expires_in is 90');

                    publicKey.access_token.should.equal(testPublicKeyObject.access_token);
                    publicKey.expires_at.should.equal(testPublicKeyObject.expires_at);
                    publicKey.expires_in.should.equal(90);
                    done(); 
                });
            });

            it('no access token removed from cache successfully', function(done) {
                var generateTokenStub = sinon.stub();
                var publicKeyStore = proxyquire('../../client/lib/public-key-store', {
                    './generate-token': generateTokenStub, 
                });
               
                testPublicKeyObject.expires_at = testUnexpiredTimestamp;
        
                var testPublicKeyString = JSON.stringify(testPublicKeyObject);

                personaClient._formatCacheKey.returns(testObtainTokenCacheKey);

                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback(null, {});
                });

                personaClient._removeTokenFromCache.callsFake((id, secret, callback) => {
                    callback();
                });

                generateTokenStub.callsFake((client, cacheKey, xRequestId, id, secret, callback) => {
                    callback(null, testPublicKeyObject);
                });

                publicKeyStore.obtainToken(personaClient, testOpts, (err, publicKey) => {
                    personaClient.tokenCache.get.calledOnce.should.equal(true);

                    personaClient.tokenCache.get.calledWith(testObtainTokenCacheKey).should.equal(true);

                    personaClient.debug.calledOnce.should.equal(true);

                    personaClient.debug.getCall(0).args[0].should.equal('Found cached token for key ' + testObtainTokenCacheKey + ': {}');

                    personaClient._removeTokenFromCache.calledOnce.should.equal(true);

                    personaClient._removeTokenFromCache.calledWith(testOpts.id, testOpts.secret).should.equal(true);

                    generateTokenStub.calledOnce.should.equal(true);

                    generateTokenStub.calledWith(personaClient, testObtainTokenCacheKey, testXRequestId, testOpts.id, testOpts.secret).should.equal(true);

                    publicKey.access_token.should.equal(testPublicKeyObject.access_token);
                    publicKey.expires_at.should.equal(testPublicKeyObject.expires_at);
                    publicKey.expires_in.should.equal(90);
                    done(); 
                });
            });

            it('no access token removed from cache unsuccessfully', function(done) {
                var generateTokenStub = sinon.stub();
                var publicKeyStore = proxyquire('../../client/lib/public-key-store', {
                    './generate-token': generateTokenStub, 
                });
               
                testPublicKeyObject.expires_at = testUnexpiredTimestamp;
        
                var testPublicKeyString = JSON.stringify(testPublicKeyObject);

                personaClient._formatCacheKey.returns(testObtainTokenCacheKey);

                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback(null, {});
                });

                personaClient._removeTokenFromCache.callsFake((id, secret, callback) => {
                    callback(error);
                });

                generateTokenStub.callsFake((client, cacheKey, xRequestId, id, secret, callback) => {
                    callback(null, testPublicKeyObject);
                });

                publicKeyStore.obtainToken(personaClient, testOpts, (err, publicKey) => {
                    personaClient.tokenCache.get.calledOnce.should.equal(true);

                    personaClient.tokenCache.get.calledWith(testObtainTokenCacheKey).should.equal(true);

                    personaClient.debug.calledOnce.should.equal(true);

                    personaClient.debug.getCall(0).args[0].should.equal('Found cached token for key ' + testObtainTokenCacheKey + ': {}');

                    personaClient._removeTokenFromCache.calledOnce.should.equal(true);

                    personaClient._removeTokenFromCache.calledWith(testOpts.id, testOpts.secret).should.equal(true);

                    generateTokenStub.called.should.equal(false);

                    err.should.equal(error);
                    done(); 
                }); 
            });

            it('expired token removed from cache successfully', function(done) {
                var generateTokenStub = sinon.stub();
                var publicKeyStore = proxyquire('../../client/lib/public-key-store', {
                    './generate-token': generateTokenStub, 
                });
               
                testPublicKeyObject.expires_at = testExpiredTimestamp;
        
                var testPublicKeyString = JSON.stringify(testPublicKeyObject);

                personaClient._formatCacheKey.returns(testObtainTokenCacheKey);

                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback(null, testPublicKeyObject);
                });

                personaClient._removeTokenFromCache.callsFake((id, secret, callback) => {
                    callback();
                });

                generateTokenStub.callsFake((client, cacheKey, xRequestId, id, secret, callback) => {
                    callback(null, {
                        access_token: testPublicKeyObject.access_token,
                        expires_at: testUnexpiredTimestamp,
                    });
                });

                publicKeyStore.obtainToken(personaClient, testOpts, (err, publicKey) => {
                    personaClient.tokenCache.get.calledOnce.should.equal(true);

                    personaClient.tokenCache.get.calledWith(testObtainTokenCacheKey).should.equal(true);

                    personaClient.debug.calledTwice.should.equal(true);

                    personaClient.debug.getCall(0).args[0].should.equal('Found cached token for key ' + testObtainTokenCacheKey + ': ' + testPublicKeyString);

                    personaClient.debug.getCall(1).args[0].should.equal('New expires_in is -10');
                    
                    personaClient._removeTokenFromCache.calledOnce.should.equal(true);

                    personaClient._removeTokenFromCache.calledWith(testOpts.id, testOpts.secret).should.equal(true);

                    generateTokenStub.calledOnce.should.equal(true);

                    generateTokenStub.calledWith(personaClient, testObtainTokenCacheKey, testXRequestId, testOpts.id, testOpts.secret).should.equal(true);

                    publicKey.access_token.should.equal(testPublicKeyObject.access_token);
                    publicKey.expires_at.should.equal(testUnexpiredTimestamp);
                    done(); 
                });
            
            });

            it('expired token removed from cache unsuccessfully', function(done) {
                var generateTokenStub = sinon.stub();
                var publicKeyStore = proxyquire('../../client/lib/public-key-store', {
                    './generate-token': generateTokenStub, 
                });
               
                testPublicKeyObject.expires_at = testExpiredTimestamp;
        
                var testPublicKeyString = JSON.stringify(testPublicKeyObject);

                personaClient._formatCacheKey.returns(testObtainTokenCacheKey);

                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback(null, testPublicKeyObject);
                });

                personaClient._removeTokenFromCache.callsFake((id, secret, callback) => {
                    callback(error);
                });

                generateTokenStub.callsFake((client, cacheKey, xRequestId, id, secret, callback) => {
                    callback(null, testPublicKeyObject);
                });

                publicKeyStore.obtainToken(personaClient, testOpts, (err, publicKey) => {
                    personaClient.tokenCache.get.calledOnce.should.equal(true);

                    personaClient.tokenCache.get.calledWith(testObtainTokenCacheKey).should.equal(true);

                    personaClient.debug.calledTwice.should.equal(true);

                    personaClient.debug.getCall(0).args[0].should.equal('Found cached token for key ' + testObtainTokenCacheKey + ': ' + testPublicKeyString);

                    personaClient.debug.getCall(1).args[0].should.equal('New expires_in is -10');
                    
                    personaClient._removeTokenFromCache.calledOnce.should.equal(true);

                    personaClient._removeTokenFromCache.calledWith(testOpts.id, testOpts.secret).should.equal(true);

                    generateTokenStub.called.should.equal(false);

                    err.should.equal(error);
                    done(); 
                });
            });
        });

        describe('not found in cache', function() {
            it('empty response from cache', function(done) {
                var generateTokenStub = sinon.stub();
                var publicKeyStore = proxyquire('../../client/lib/public-key-store', {
                    './generate-token': generateTokenStub, 
                });
               
                testPublicKeyObject.expires_at = testExpiredTimestamp;
        
                var testPublicKeyString = JSON.stringify(testPublicKeyObject);

                personaClient._formatCacheKey.returns(testObtainTokenCacheKey);

                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback(null, null);
                });

                generateTokenStub.callsFake((client, cacheKey, xRequestId, id, secret, callback) => {
                    callback(null, {
                        access_token: testPublicKeyObject.access_token,
                        expires_at: testUnexpiredTimestamp,
                    });
                });

                publicKeyStore.obtainToken(personaClient, testOpts, (err, publicKey) => {
                    personaClient.tokenCache.get.calledOnce.should.equal(true);

                    personaClient.tokenCache.get.calledWith(testObtainTokenCacheKey).should.equal(true);

                    generateTokenStub.calledOnce.should.equal(true);

                    generateTokenStub.calledWith(personaClient, testObtainTokenCacheKey, testXRequestId, testOpts.id, testOpts.secret).should.equal(true);

                    publicKey.access_token.should.equal(testPublicKeyObject.access_token);
                    publicKey.expires_at.should.equal(testUnexpiredTimestamp);
                    done();
                });
            });
            
            // https://github.com/talis/platform/issues/1729
            it('cache error', function(done) {
                var generateTokenStub = sinon.stub();
                var publicKeyStore = proxyquire('../../client/lib/public-key-store', {
                    './generate-token': generateTokenStub, 
                });
               
                testPublicKeyObject.expires_at = testExpiredTimestamp;
        
                var testPublicKeyString = JSON.stringify(testPublicKeyObject);

                personaClient._formatCacheKey.returns(testObtainTokenCacheKey);

                personaClient.tokenCache.get.callsFake((cacheKey, callback) => {
                    callback(error, null);
                });

                generateTokenStub.callsFake((client, cacheKey, xRequestId, id, secret, callback) => {
                    callback(null, {
                        access_token: testPublicKeyObject.access_token,
                        expires_at: testUnexpiredTimestamp,
                    });
                });

                publicKeyStore.obtainToken(personaClient, testOpts, (err, publicKey) => {
                    personaClient.tokenCache.get.calledOnce.should.equal(true);

                    personaClient.tokenCache.get.calledWith(testObtainTokenCacheKey).should.equal(true);

                    generateTokenStub.calledOnce.should.equal(true);

                    generateTokenStub.calledWith(personaClient, testObtainTokenCacheKey, testXRequestId, testOpts.id, testOpts.secret).should.equal(true);

                    publicKey.access_token.should.equal(testPublicKeyObject.access_token);
                    publicKey.expires_at.should.equal(testUnexpiredTimestamp);
                    done();
                });
            });
        });
    });
});
