'use strict';

// log severities
var DEBUG = "debug";
var ERROR = "error";

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

    this.debug("Persona Client Created");
};

PersonaClient.prototype.validateToken = function(req,res,next){
    var token = this.getToken(req),
        _this = this;
    this.debug("Validating token: "+token);

    if (token == null) {
        res.status(401);
        res.json({"error":"no_token","error_description":"No token supplied"});
        throw "OAuth validation failed for "+token;
    }

    redisClient.get("access_token:"+token,function(err,reply) {
        if (reply=="OK") {
            this.debug("Token "+token+" verified by cache");
            next();
        } else {
            var options = {
                hostname: config.oauth.host,
                port: config.oauth.port,
                path: config.oauth.route+token,
                method: 'HEAD'
            };
            http.request(options,function(oauthResp) {
                if (oauthResp.statusCode==204)
                {
                    // put this key in redis with an expire
                    redisClient.multi().set("access_token:"+token,'OK').expire("access_token:"+token,60).exec(function(err,results){ this.debug("cache: "+JSON.stringify(err)+JSON.stringify(results))});
                    this.debug("Verification passed for token "+token+", cached for 60s");
                    next();
                }
                else
                {
                    this.debug("Verification failed for token "+token+" with status code "+oauthResp.statusCode);
                    res.status(401);
                    res.set("Connection","close");
                    res.json({"error":"invalid_token","error_description":"The token is invalid or has expired"});
                }
            }).on("error",function(e) {
                    this.error("OAuth::validateToken problem: "+ e.message);
                    res.status(500);
                    res.set("Connection","close");
                    res.json({"error":"unexpected_error","error_description":e.message});
                }).end();
        }
    });

};

PersonaClient.prototype.generateToken = function(callback){
    // todo: this is really inefficient requesting a new token each time. Cache in redis until expires.
    this.debug("Generating token for use in primitives on behalf of anon client");

    var b64cred = new Buffer(config.oauth.anonClient.id+":"+config.oauth.anonClient.secret).toString('base64');
    var options = {
        hostname: config.oauth.host,
        port: config.oauth.port,
        path: config.oauth.route,
        method: 'POST',
        headers: {
            Authorization: "Basic "+b64cred,
            'Content-Type': "application/json"
        }
    };
    var personaReq = http.request(options,function(personaResp) {
        var str = "";
        personaResp.on('data', function(chunk){
            str += chunk;
        });
        personaResp.on('end', function(){
            // todo impl
            var resp = JSON.parse(str);
            if (resp.access_token) {
                callback(null,resp.access_token);
            } else {
                callback("access_token missing from response", null);
            }
        });
    });
    personaReq.on("clientError",function() {
        callback(err,null);
    });
    personaReq.write(JSON.stringify({grant_type:"client_credentials"}));
    personaReq.end();
};


PersonaClient.prototype.getToken = function (req) {
    if (req.header("Authorization"))
    {
        var result = req.header("Authorization").match(/Bearer\s(\S+)/);
        if (result && result.length>1) return result[1];
    }
    if (req.param('access_token'))
    {
        return req.param('access_token')
    }
    return null;
};

/**
 * Log wrapping functions
 * @param severity ( debug or error )
 * @param message
 * @returns {boolean}
 */
PersonaClient.prototype.log = function(severity, message) {
    if(!this.config.enable_debug) return true;

    if(this.config.logger){
        if(severity == DEBUG){
            this.config.logger.debug(message);
        } else if ( severity == ERROR ){
            this.config.logger.error(message);
        } else {
            console.log(severity +": "+ message);
        }
    } else {
        console.log(severity + ": " + message);
    }
}
PersonaClient.prototype.debug = function(message) {
    this.log(DEBUG, message);
}
PersonaClient.prototype.error = function(message) {
    this.log(ERROR, message);
}


/**
 * The only way to get an instance of the Persona Client is through
 * this method
 * @param config
 * @returns {PersonaClient}
 */
exports.createClient = function(config) {
    return new PersonaClient(config);
};