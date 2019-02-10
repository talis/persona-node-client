var ERROR_TYPES = require('./error-types');
var _ = require("lodash");

/**
 * Validate method opts
 * @param opts
 * @param mandatoryKeys null|array|object a simple array of madatory keys, or key/value where value is a function to validate the value of key in opts
 * @throws Error
 */
var validateOpts = function validateOpts(opts, mandatoryKeys) {
    var error = new Error();
    error.name = ERROR_TYPES.INVALID_ARGUMENTS;

    if (!_.isObject(opts)) {
        throw new Error('Expecting opts to be an object');
    }

    if (_.isArray(mandatoryKeys)) {
        mandatoryKeys.forEach(function eachMandatoryKey(mandatoryKey) {
            if (_.isEmpty(opts[mandatoryKey])) {
                error.message = mandatoryKey + ' in opts cannot be empty';
                throw error;
            }
        });
    } else if (_.isObject(mandatoryKeys)) {
        _.keysIn(mandatoryKeys).forEach(function eachMandatoryKey(mandatoryKey) {
            var validationFn = mandatoryKeys[mandatoryKey];
            if (_.isEmpty(opts[mandatoryKey])) {
                error.message = mandatoryKey + ' in opts cannot be empty';
                throw error;
            } else if (!validationFn(opts[mandatoryKey])) {
                error.message = mandatoryKey + ' failed ' + validationFn.name + ' validation';
                throw error;
            }
        });
    } else {
        error.message = 'mandatoryKeys must be empty, array or object';
        throw error;
    }
};

module.exports = validateOpts;
