"use strict";

var http = require("http");
var querystring = require("querystring");
var fs = require("fs");
var nock = require("nock");
var nonMatchedEvents = [];
var _ = require("lodash");

var _getOAuthToken = function getOAuthToken(scope, callback) {

    var data = {
        'grant_type' : 'client_credentials'
    };
    if(scope){
        data.scope = scope;
    }

    var post_data = querystring.stringify(data);


    var options = {
        host: "persona",
        path: "/oauth/tokens",
        method: "POST",
        auth: "primate:bananas", //todo get rid of this from source control
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': post_data.length
        }
    };

    var req = http.request(options, function(response){
        var str = "";
        response.on('data', function(chunk){
            str += chunk;
        });
        response.on('end', function(){
            //console.log(str);
            var data = JSON.parse(str);
            if (data.error) {
                callback(data.error,null);
            } else if(data.access_token){
                callback(null,data.access_token);
            } else {
                callback("Could not get access token",null);
            }
        });
    });
    //console.log("Posting data "+post_data);
    req.write(post_data);
    //console.log("Sending");
    req.end();
};

var getStubRequest = function(token, scope) {

    var req = {
        header: function(){ return null; },
        param: function(param){
            if(param=="access_token"){
                return token;
            }
            if(param=="scope"){
                return scope;
            }
            return null;
        }
    };

    return req;
};

var getStubResponse = function() {

    var res = {
        _status: null,
        _json: null,
        _props: {},

        _statusWasCalled: false,
        _jsonWasCalled: false,
        _setWasCalled: false,

        status: function(status){
            this._status = status;
            this._statusWasCalled = true;
        },

        json:function(val){
            this._json = val;
            this._jsonWasCalled = true;
        },

        set:function(k, v){
            this._props[k] = v;
            this._setWasCalled = true;
        }
    };

    return res;
};

var guid = function guid() {
    function s4() {
        return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
    }
    return s4() + s4() + s4() + s4() + s4()+ s4() + s4() + s4();
};

var beforeEach = function recordOrReplayHttpCalls(testFriendlyName, responsesFolder) {
    var testName = testFriendlyName.replace(/ /g, "_");
    if(process.env.RECORD_HTTP_CALLS === "true") {
        nock.recorder.rec({
            dont_print: true,
            output_objects: true
        });

        return null;
    }

    nock.emitter.on('no match', function(req) {
        nonMatchedEvents.push(req);
    });

    return nock.load(__dirname + '/responses/' + responsesFolder + '/' + testName + '.json');
};

var getNonMatchedEvents = function() {
    return nonMatchedEvents;
};

var afterEach = function recordAndSaveHttpCallsIfEnabled(testFriendlyName, responsesFolder, requestSpy) {
    if (getNonMatchedEvents().length>0) {
        throw new Error("Unmatched events detected");
    } else {
        // Removes any unused requests so that they don't leak into other tests.
        nock.cleanAll();
        if (process.env.RECORD_HTTP_CALLS === "true") {
            var testName = testFriendlyName.replace(/ /g, "_");
            var fileName = __dirname + "/responses/" + responsesFolder + "/" + testName + ".json";
            var calls = nock.recorder.play();
            fs.writeFileSync(fileName, JSON.stringify(calls, null, 4));
            nock.restore();
        }
    }

    if (requestSpy) {
        for (var i=0;i<requestSpy.callCount;i++) {
            _.map(['X-Request-Id','User-Agent'],function(header) {
                if (!_.has(requestSpy.getCall(i),"args[0].headers['"+header+"']") && !_.isString(requestSpy.getCall(i).args[0].headers[header])) {
                    throw new Error("request was not sent with string value for "+header);
                }
            });
        }
    }
};

exports.guid = guid;
exports.beforeEach = beforeEach;
exports.afterEach = afterEach;
exports._getOAuthToken = _getOAuthToken;
exports._getStubRequest = getStubRequest;
exports._getStubResponse = getStubResponse;
