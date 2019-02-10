/**
 * Split the scope into it's role and namespace components
 *
 * @param {string} scope scope to split up
 * @return {object} scope descriptor (namespace & role)
 */
function chunkScope(scope) {
    var chunks = scope.split('@', 2);
    var result = {};

    if (chunks.length === 2) {
        result.namespace = chunks[0];
        result.role = chunks[1];
    } else {
        result.role = chunks[0];
    }

    return result;
}

/**
 * Check if a scope validates a required scope. The majority of the checks can
 * be considered to be litral string checks. There is a single edgecase where
 * the user has a su@provider scope. This scope will override any other scope if
 * the role either matches or is a subset with a delimiter.
 *
 * i.e su@provider validates su@provider:foo and su@provider
 *
 * @param {string} hscope scope to validate the required scope.
 * @param {string} rscope required scope to validate scope.
 * @return {bool} true if the scope validates the required scope.
 */
function validateScope(hscope, rscope) {
    var requiredScope = chunkScope(rscope);
    var scope = chunkScope(hscope);

    var namespaceMatch = requiredScope.namespace === scope.namespace;
    var roleMatch = requiredScope.role === scope.role;
    var emptyNamespace = requiredScope.namespace == null && scope.namespace == null;

    var roleSubset = requiredScope.role.startsWith(scope.role + ':');
    var suOverride = scope.namespace === 'su' && (roleMatch || roleSubset);

    return suOverride || (emptyNamespace || namespaceMatch) && roleMatch;
}

/**
 * Check if any of the required scopes can be fulfilled by given scopes.
 *
 * @param {array} scopes to check against.
 * @param {array|null} required scopes
 * @return {bool} true if at least one required scope can be validated
 */
function validateScopes(scopes, requiredScopes) {
    if (requiredScopes == null || scopes.indexOf('su') > -1) {
        return true;
    }

    for (var rs in requiredScopes) {
        var requiredScope = requiredScopes[rs];
        for (var sc in scopes) {
            var scope = scopes[sc];
            if (validateScope(scope, requiredScope)) {
                console.log(scope + ' validates ' + requiredScope);
                return true;
            }
        }
    }

    return false;
}

module.exports = validateScopes;
