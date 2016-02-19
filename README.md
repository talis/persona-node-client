[ ![Codeship Status for talis/persona-node-client](https://codeship.com/projects/2e1dc6e0-b950-0133-e3ad-76946c995c7e/status?branch=master)](https://codeship.com/projects/135481)

Node Client for Persona, responsible for retrieving, generating, caching and validating OAuth Tokens.

## Getting Started
Install the module by adding the following line to `packages.json`: 

```
    "persona_client": "git://github.com/talis/persona-node-client.git#1.1.1"
```

Create a persona client as follows:

```javascript
var persona = require('persona_client');
var personaClient = persona.createClient({
    persona_host:"localhost",
    persona_port:443,
    persona_scheme:"https",
    persona_oauth_route:"/oauth/tokens",
    redis_host:"localhost",
    redis_port:6379,
    redis_db:0,
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

## Contributing
In lieu of a formal styleguide, take care to maintain the existing coding style. Add unit tests for any new or changed functionality. Lint and test your code using [Grunt](http://gruntjs.com/).

## Release History

* 1.1.1 - Remove exception that was thrown when the oauth token was invalid. The HTTP status and body is now set as expected.
* 1.1.0 - Added methods for getting and updating a user profile
* 1.0.0 - Breaking change to existing functionality: The method validateToken is now called validateHTTPBearerToken. The validateToken method validates a token against Persona, while the validateHTTPBearerToken method validates a token that originates from a http call (one of the attributes required is a http request object).
* 0.3.0 - added the ability to request/delete client authorizations, and fixed scoping issue on validation.

## License
Copyright (c) 2015 Talis Education Limited.
