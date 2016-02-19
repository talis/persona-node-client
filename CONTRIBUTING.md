## First Time Setup

    npm install
    npm test

## Tests

When creating or updating a test, it should be run against a Persona server.

To do this run something like the following:

    RECORD_HTTP_CALLS=true node_modules/.bin/mocha -t 10000 -g "test name" test/suite_name_tests.js

This will create/update a JSON file in the `responses/suite_name` folder. Make sure this file is checked in.

When you are happy with the test, you can remove the `RECORD_HTTP_CALLS=true` part.

Make sure all the tests still pass by running `npm test`.
