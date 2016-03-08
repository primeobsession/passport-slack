/**
 * Module dependencies.
 */
var util = require('util'),
  url = require('url'),
 OAuth2Strategy = require('passport-oauth').OAuth2Strategy;


/**
 * `Strategy` constructor.
 *
 * The Slack authentication strategy authenticates requests by delegating
 * to Slack using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Slack application's client id
 *   - `clientSecret`  your Slack application's client secret
 *   - `callbackURL`   URL to which Slack will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request, for example:
 *                     'identify', 'channels:read', 'chat:write:user', 'client', or 'admin'
 *                     full set of scopes: https://api.slack.com/docs/oauth-scopes
 *
 * Examples:
 *
 *     passport.use(new SlackStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/slack/callback',
 *         scope: 'identify channels:read chat:write:user client admin'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://slack.com/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://slack.com/api/oauth.access';
  options.scopeSeparator = options.scopeSeparator || ' ';
  this.profileUrl = options.profileUrl || "https://slack.com/api/auth.test?token="; // requires 'users:read' scope
  this.userInfoUrl = options.userInfoUrl || "https://slack.com/api/users.info?user=";
  this._team = options.team;

  OAuth2Strategy.call(this, options, verify);
  this.name = options.name || 'slack';
  
  // warn is not enough scope
  if(!this._skipUserProfile && this._scope.indexOf('users:read') === -1){
    console.warn("Scope 'users:read' is required to retrieve Slack user profile");
  }
}

OAuth2Strategy.prototype._loadUserProfile = function(accessToken, botToken, done) {
  var self = this;

  function loadIt() {
    return self.userProfile(accessToken, botToken, done);
  }
  function skipIt() {
    return done(null);
  }

  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, botToken, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
}


OAuth2Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return this.fail();
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req), callbackURL);
    }
  }

  if (req.query && req.query.code) {
    var code = req.query.code;

    // NOTE: The module oauth (0.9.5), which is a dependency, automatically adds
    //       a 'type=web_server' parameter to the percent-encoded data sent in
    //       the body of the access token request.  This appears to be an
    //       artifact from an earlier draft of OAuth 2.0 (draft 22, as of the
    //       time of this writing).  This parameter is not necessary, but its
    //       presence does not appear to cause any issues.
    this._oauth2.getOAuthAccessToken(code, { grant_type: 'authorization_code', redirect_uri: callbackURL },
      function(err, accessToken, refreshToken, params) {
        if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }
        
        var botToken = null;
        if(params.bot && params.bot.bot_access_token){
          botToken = params.bot.bot_access_token;
        }

        self._loadUserProfile(accessToken, botToken, function(err, profile) {
          if (err) { return self.error(err); };

          function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            self.success(user, info);
          }

          if (self._passReqToCallback) {
            var arity = self._verify.length;
            if (arity == 6) {
              self._verify(req, accessToken, refreshToken, params, profile, verified);
            } else { // arity == 5
              self._verify(req, accessToken, refreshToken, profile, verified);
            }
          } else {
            var arity = self._verify.length;
            if (arity == 5) {
              self._verify(accessToken, refreshToken, params, profile, verified);
            } else { // arity == 4
              self._verify(accessToken, refreshToken, profile, verified);
            }
          }
        });
      }
    );
  } else {
    // NOTE: The module oauth (0.9.5), which is a dependency, automatically adds
    //       a 'type=web_server' parameter to the query portion of the URL.
    //       This appears to be an artifact from an earlier draft of OAuth 2.0
    //       (draft 22, as of the time of this writing).  This parameter is not
    //       necessary, but its presence does not appear to cause any issues.

    var params = this.authorizationParams(options);
    params['response_type'] = 'code';
    params['redirect_uri'] = callbackURL;
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    var state = options.state;
    if (state) { params.state = state; }

    var location = this._oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Slack.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `slack`
 *   - `id`               the user's ID
 *   - `displayName`      the user's username
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, botToken, done) {
  //this._oauth2.useAuthorizationHeaderforGET(true);
  var self = this;

  this.get(this.profileUrl, accessToken, function (err, body, res) {

    if (err) {
      return done(err);
    } else {
      try {
        var json = JSON.parse(body);

        if (!json.ok) {
          done(json.error ? json.error : body);
        } else {
          var profile = {
            provider: 'Slack'
          };
          profile.id = json.user_id;
          profile.displayName = json.user;

          profile._raw = body;
          profile._json = json;

          self.get(self.userInfoUrl + profile.id + "&token=", (botToken) ? botToken : accessToken, function (err, body, res) {

            if (err) {
              return done(err);
            }
            var infoJson = JSON.parse(body);
            if (!infoJson.ok) {
              done(infoJson.error ? infoJson.error : body);
            }else{
              profile._json.info = infoJson;
              done(null, profile);
            }
          });
        }
      } catch(e) {
        done(e);
      }
    }
  });
}

/** The default oauth2 strategy puts the access_token into Authorization: header AND query string
  * which is a violation of the RFC so lets override and not add the header and supply only the token for qs.
  */
Strategy.prototype.get = function(url, access_token, callback) {
  this._oauth2._request("GET", url + access_token, {}, "", "", callback );
};



/**
 * Return extra Slack parameters to be included in the authorization
 * request.
 *
 * @param {Object} options
 * @return {Object}
 */
Strategy.prototype.authorizationParams = function (options) {
  var params = {};
  var team = options.team || this._team;
   if(team){
     params.team = team;
   }
  return params;
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
