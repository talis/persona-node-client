"use strict";

var should = require("should");
var assert = require("assert");
var sinon = require("sinon");

var ERROR_TYPES = require('../../client/lib/error-types');

var validateOpts = require('../../client/lib/validate-opts');

describe('validate-opts', function() {
    it('opts should be an object', function(done) {
        try {
            validateOpts(null, null);
            done('Should throw exception when opts is not an object');
        } catch (err) {
            err.message.should.equal('Expecting opts to be an object');
            done();
        }
    });

    describe('mandatoryKeys must be empty, array or object', function() {
        it('can be null', function(done) {
            try {
                validateOpts({}, null);
                done();
            } catch (err) {
                done(err);
            }
        });

        it('can be empty object', function(done) {
            try {
                validateOpts({}, {});
                done();
            } catch (err) {
                done(err);
            }
        });

        it('can be empty array', function(done) {
            try {
                validateOpts({}, []);
                done();
            } catch (err) {
                done(err);
            }
        });

        it('can not be a string', function(done) {
            try {
                validateOpts({}, 'hello');
                done('Should throw exception when mandatoryKeys is a string');
            } catch (err) {
                err.name.should.equal(ERROR_TYPES.INVALID_ARGUMENTS);
                err.message.should.equal('mandatoryKeys must be empty, array or object');
                done();
            }
        });

        it('can not be a integer', function(done) {
            try {
                validateOpts({}, 1);
                done('Should throw exception when mandatoryKeys is a integer');
            } catch (err) {
                err.name.should.equal(ERROR_TYPES.INVALID_ARGUMENTS);
                err.message.should.equal('mandatoryKeys must be empty, array or object');
                done();
            }
        });
    });

    describe('mandatoryKeys is an array', function() {
        it('all keys exist', function(done) {
            try {
                var opts = {
                    key: 'hello',
                    name: 'Dave'
                };

                validateOpts(opts, ['key', 'name']);
                done();
            } catch (err) {
                done(err);
            }
        });

        it('opts contains additional keys', function(done) {
            try {
                var opts = {
                    key: 'hello',
                    name: 'Dave'
                };

                validateOpts(opts, ['key']);
                done();
            } catch (err) {
                done(err);
            }
        });

        it('opts is missing mandatoryKey', function(done) {
            try {
                var opts = {
                    name: 'Dave'
                };

                validateOpts(opts, ['key']);
                done('Should throw exception when mandatoryKey is missing from opts');
            } catch (err) {
                err.name.should.equal(ERROR_TYPES.INVALID_ARGUMENTS);
                err.message.should.equal('key in opts cannot be empty');
                done();
            }
        });

        it('error thrown for first missing key', function(done) {
            try {
                var opts = {
                    name: 'Dave'
                };

                validateOpts(opts, ['key', 'anotherKey']);
                done('Should throw exception when mandatoryKey is missing from opts');
            } catch (err) {
                err.name.should.equal(ERROR_TYPES.INVALID_ARGUMENTS);
                err.message.should.equal('key in opts cannot be empty');
                done();
            }
        });
    });

    describe('mandatoryKeys is an object', function() {
        it('all keys exist', function(done) {
            try {
                var opts = {
                    key: 'hello',
                    name: 'Dave'
                };

                var mandatoryKeys = {
                    key: () => true,
                    name: () => true,
                }

                validateOpts(opts, mandatoryKeys);
                done();
            } catch (err) {
                done(err);
            }
        });

        it('opts contains additional keys', function(done) {
            try {
                var opts = {
                    key: 'hello',
                    name: 'Dave'
                };

                var mandatoryKeys = {
                    key: () => true,
                }

                validateOpts(opts, mandatoryKeys);
                done();
            } catch (err) {
                done(err);
            }
        });

        it('opts is missing mandatoryKey', function(done) {
            try {
                var opts = {
                    name: 'Dave'
                };

                var mandatoryKeys = {
                    key: () => true,
                }

                validateOpts(opts, mandatoryKeys);
                done('Should throw exception when mandatoryKey is missing from opts');
            } catch (err) {
                err.name.should.equal(ERROR_TYPES.INVALID_ARGUMENTS);
                err.message.should.equal('key in opts cannot be empty');
                done();
            }
        });
        
        it('error thrown for first missing key', function(done) {
            try {
                var opts = {
                    name: 'Dave'
                };

                var mandatoryKeys = {
                    key: () => true,
                    anotherKey: () => true,
                }

                validateOpts(opts, mandatoryKeys);
                done('Should throw exception when mandatoryKey is missing from opts');
            } catch (err) {
                err.name.should.equal(ERROR_TYPES.INVALID_ARGUMENTS);
                err.message.should.equal('key in opts cannot be empty');
                done();
            }
        });
    
        it('validation function fails', function(done) {
            try {
                var opts = {
                    key: 'hello',
                    name: 'Dave'
                };

                var mandatoryKeys = {
                    key: () => false,
                }

                validateOpts(opts, mandatoryKeys);
                done('Should throw exception when validation function fails');
            } catch (err) {
                err.name.should.equal(ERROR_TYPES.INVALID_ARGUMENTS);
                done();
            }
        });
    
        it('error thrown for first validation function failure', function(done) {
            try {
                var opts = {
                    key: 'hello',
                    name: 'Dave'
                };

                var mandatoryKeys = {
                    key: () => false,
                    name: () => false,
                }

                validateOpts(opts, mandatoryKeys);
                done('Should throw exception when validation function fails');
            } catch (err) {
                err.name.should.equal(ERROR_TYPES.INVALID_ARGUMENTS);
                done();
            }
        });
    });
});

