var middleware = require("../cloud9.core/middleware");
var utils = require("connect").utils;

module.exports = function startup(options, imports, register) {
    var realm = "Authorization Required";

    var connect = imports.connect;
    var ide = imports.ide;

    var connectModule = connect.getModule();
    var server = connectModule();

    var useQueryAuth = options.key != undefined && options.key.length >= 1 && options.secret != undefined && options.secret.length >= 1;
    var useBasicAuth = options.username != undefined && options.username.length >= 1 && options.password != undefined && options.password.length >= 1;
    console.log("Using query authorization: " + useQueryAuth);
    console.log("Using basic authorization: " + useBasicAuth);

    server.use(middleware.errorHandler());
    ide.use(function(req, res, next) {
        if (req.session.authorized) return next();
        // attempt query auth
        if (useQueryAuth && req.query.key == options.key && req.query.secret == options.secret) {
            req.session.authorized = true;
            req.remoteUser = options.username;
            return next();
        }

        if (!useBasicAuth) {
            return utils.unauthorized(res, realm);
        }

        // thanks to https://github.com/senchalabs/connect/blob/1.x/lib/middleware/basicAuth.js

        // begin basic auth
        var authorization = req.headers.authorization;

        if (req.remoteUser) return next();
        if (!authorization) return utils.unauthorized(res, realm);

        var parts = authorization.split(' ')
          , scheme = parts[0]
          , credentials = new Buffer(parts[1], 'base64').toString().split(':');

        if ('Basic' != scheme) return utils.badRequest(res);

        if (credentials[0] == options.username && credentials[1] == options.password) return next();
        return utils.unauthorized(res, realm);
    });

    ide.use("/api", server);

    register(null, {
        "ide-routes" : {
            use: function(route, handle) {
                var last = server.stack.pop();
                server.use(route, handle);
                server.stack.push(last);
            }
        }
    });
};