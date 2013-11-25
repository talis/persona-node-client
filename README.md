Node Client for Persona, repsonsible for retrieving, generating, caching and validating OAuth Tokens.

## Getting Started
Install the module with: `npm install persona_client`

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

## Documentation
_(Coming soon)_

## Examples
_(Coming soon)_

## Contributing
In lieu of a formal styleguide, take care to maintain the existing coding style. Add unit tests for any new or changed functionality. Lint and test your code using [Grunt](http://gruntjs.com/).

## Release History
_(Nothing yet)_

## License
Copyright (c) 2013 Talis Education Limited. Licensed under the MIT license.
