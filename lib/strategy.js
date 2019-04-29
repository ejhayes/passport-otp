/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , authenticator = require('otplib').authenticator
  , util = require('util');


/**
 * `Strategy` constructor.
 *
 * The TOTP authentication strategy authenticates requests based on the
 * TOTP value submitted through an HTML-based form.
 *
 * Applications must supply a `setup` callback which accepts `user`, and then
 * calls the `done` callback supplying a `key` used to verify the TOTP value.
 *
 *
 * Options:
 *   - `codeField`:     field name where the TOTP value is found, defaults to _code_
 *   - `authenticator`: otplib.authenticator options
 *
 * Example: uses  
 *
 *     passport.use(new OtpStrategy({
 *         step: 30,
 *         crypto: require('crypto')
 *       },
 *       function (user, done) {
 *         TotpKey.findOne({
 *           userId: user.id
 *         }, function (err, key) {
 *           if (err) {
 *             return done(err);
 *           }
 *           return done(null, key.key, key.period);
 *         });
 *       }));
 *
 * References:
 *  - [TOTP: Time-Based One-Time Password Algorithm](http://tools.ietf.org/html/rfc6238)
 *  - [KeyUriFormat](https://code.google.com/p/google-authenticator/wiki/KeyUriFormat)
 *
 * @param {Object} options
 * @param {Function} setup
 * @api public
 */
function Strategy(options, setup) {
  if (typeof options == 'function') {
    setup = options;
    options = {};
  }

  // passthru options to authenticator, if nothing is specified
  // then at least provide a default crypto library
  if (options.authenticator) {
    authenticator.options;
  }
  else {
    authenticator.options = {
      crypto: require('crypto')
    }
  }
  
  this._codeField = options.codeField || 'code';
  
  passport.Strategy.call(this);
  this._setup = setup;
  this.name = 'otp';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on TOTP values.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  var value = lookup(req.body, this._codeField) || lookup(req.query, this._codeField);
  
  var self = this;
  this._setup(req.user, function(err, key) {
    if (err) { return self.error(err); }
    
    var rv = authenticator.check(value, key);

    if (!rv) { return self.fail(); }
    return self.success(req.user);
  });
  
  
  function lookup(obj, field) {
    if (!obj) { return null; }
    var chain = field.split(']').join('').split('[');
    for (var i = 0, len = chain.length; i < len; i++) {
      var prop = obj[chain[i]];
      if (typeof(prop) === 'undefined') { return null; }
      if (typeof(prop) !== 'object') { return prop; }
      obj = prop;
    }
    return null;
  }
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
