[![Build Status](https://travis-ci.org/talis/persona-node-client.svg?branch=master)](https://travis-ci.org/talis/persona-node-client)

Node Client for Persona, responsible for retrieving, generating, caching and validating OAuth Tokens.

## Getting Started
Install the module by adding the following line to `packages.json`:

```
    "persona_client": "git://github.com/talis/persona-node-client.git#1.3.0"
```

Create a persona client as follows:

```javascript
var persona = require('persona_client');
var personaClient = persona.createClient({
    persona_host:"localhost",
    persona_port:443,
    persona_scheme:"https",
    persona_oauth_route:"/oauth/tokens",
    enable_debug: true,
    logger: AppLogger
});
```

If using express, we recommend the following middleware:

```javascript
app.use(function(req,res,next){
    req.personaClient = personaClient;
    next();
});
```

## Documentation

### Validating tokens

Here we validate the token supplied using a specific scope (optional)

```javascript
    /**
     * Check if a user is allowed to impersonate another, and logs it
     */
    app.post('/some/route', function(req,res) {
        req.personaClient.validateHTTPBearerToken(req,res, function(){
           // you're good, do stuff
        },"some_scope");
    });
```

If the validation fails, `401` will be returned to the client automatically.


### Pre-signing signing urls

Signing:

```javascript
  personaClient.presignUrl('http://url.to.sign/','mySecret',secsSinceEpocToExpiry,function(err,signedUrl) {
    // do stuff
  }
```

Checking:

```javascript
  var isValid = personaClient.isPresignedUrlValid('http://url.to.sign/?signature=34234545','mySecret');
```

### Client authorizations

Requesting:

```javascript
  personaClient.requestAuthorization('user_guid', 'Required for access to admin', 'client_id', 'client_secret', function(err,authorization) {
    // do stuff
  });
```

Deleting:

```javascript
  personaClient.deleteAuthorization('user_guid', 'Required for access to admin', 'client_id', 'client_secret', function(err) {
    // do stuff
  });
```

### Getting a user profile

Via guid:

```javascript
  personaClient.getProfileByGuid ('user_guid', 'token', function(err, user) {
    // do stuff
    var profile = user.profile;
  });
```

### Updating a user profile

```javascript
  personaClient.updateProfile('user_guid', {first_name:'Max',surname:'Payne'} 'token', function(err, user) {
    // do stuff
    var profile = user.profile;
  });
```

### Caching OAuth tokens

Persona client allows multiple strategies to cache tokens (to avoid repeated
 requests to Persona) via [cache-service](https://npmjs.org/package/cache-service)

 This is configured through the persona client config, e.g.:

 ```javascript
 {
     persona_host:"localhost",
     persona_port:443,
     persona_scheme:"https",
     persona_oauth_route:"/oauth/tokens",
     cache: {
       module: "redis",
       options: {
         redisData: {
           hostname: "localhost",
           port: 6379
         }
       }
     },
     enable_debug: true,
     logger: AppLogger
 ```

`module` corresponds to any cache-service module: e.g. "redis" would require
`cache-service-redis`.  By default, it will use an in-memory cache (`node-cache`).
 
`options` are passed directly to the `cache-service-{module}` constructor, so can be whatever is valid for a given
cache-service module.

## Contributing
In lieu of a formal styleguide, take care to maintain the existing coding style. Add unit tests for any new or changed functionality. Lint and test your code using [Grunt](http://gruntjs.com/).

## Release History

See the [releases page](https://github.com/talis/persona-node-client/releases).

## License
Copyright (c) 2016 Talis Education Limited.
