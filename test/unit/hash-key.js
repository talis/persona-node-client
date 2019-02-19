"use strict";

var should = require("should");
var assert = require("assert");
var sinon = require("sinon");

var hashKey = require('../../client/lib/hash-key');

describe('hash-key', function() {
    it('correctly hashes key', function() {
        [
            {
                key: 'key',
                hash: 'v6DpRaPd9vWLlfoxg3ke0Q==',
            },
            {
                key: 'data',
                hash: 'U5CAuieM9M9NsuSjJkL/MA=='
            },
            {
                key: 'www.talis.com',
                hash: 'MLXjuG895/5cv8ynX60Yyg=='
            }
        ].forEach(function(test) {
            hashKey(test.key).should.equal(test.hash);     
        });
    });
});

