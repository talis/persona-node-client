var http = require('http'),
    querystring = require('querystring');

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



exports._getOAuthToken   = _getOAuthToken;
exports._getStubRequest  = getStubRequest;
exports._getStubResponse = getStubResponse;