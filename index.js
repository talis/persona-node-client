"use strict";

var validateScopes = require('./client/lib/validate-scopes');
var ERROR_TYPES = require('./client/lib/error-types');

var PersonaClient = require('./client');

exports.validateScopes = validateScopes;

exports.errorTypes = ERROR_TYPES;

/**
 * The only way to get an instance of the Persona Client is through
 * this method
 * @param appUA
 * @param config
 * @returns {PersonaClient}
 */
exports.createClient = function (appUA, config) {
    return new PersonaClient(appUA, config);
};

