'use strict';


/**
 * Constructor you must pass in a config object with the following properties set:
 *
 * config.persona_host = "users.talis.com";
 * config.persona_port = 443;
 * config.persona_scheme = "https";
 * config.persona_oauth_route = "/oauth/tokens/";
 * config.redis_host
 * config.redis_port
 * config.redis_db
 *
 * This library stores no default configuration of its own. It relies on the application/service
 * it is embedded in to supply this information.
 *
 * @param config
 * @constructor
 */
var PersonaClient = function(config) {
    this.config = config = config || {};

    //TODO: find a less verbose way of doing this

    if(this.config.persona_host == undefined){
        throw new Error("You must specify the Persona server host");
    }
    if(this.config.persona_port == undefined){
        throw new Error("You must specify the Persona server port");
    }
    if(this.config.persona_scheme == undefined){
        throw new Error("You must specify the Persona server scheme (http/https)");
    }
    if(this.config.persona_oauth_route == undefined){
        throw new Error("You must specify the Persona oauth route");
    }

    if(this.config.redis_host == undefined){
        throw new Error("You must specify the Redis host to use as a cache");
    }
    if(this.config.redis_port == undefined){
        throw new Error("You must specify the Redis port");
    }
    if(this.config.redis_db == undefined){
        throw new Error("You must specify the Redis db");
    }
};

/**
 * The only way to get an instance of the Persona Client is through
 * this method
 * @param config
 * @returns {PersonaClient}
 */
exports.createClient = function(config) {
    return new PersonaClient(config);
};