'use strict';

const User = require('./users-model.js');

module.exports = (capability) =>
  (req, res, next) => {

    try {
      let [authType, authString] = req.headers.authorization.split(/\s+/);

      switch (authType.toLowerCase()) {
      case 'basic':
        return _authBasic(authString);
      case 'bearer':
        return _authBearer(authString);
      default:
        return _authError();
      }
    } catch (e) {
      _authError();
    }


    function _authBasic(str) {
      // str: am9objpqb2hubnk=
      let base64Buffer = Buffer.from(str, 'base64'); // <Buffer 01 02 ...>
      let bufferString = base64Buffer.toString();    // john:mysecret
      let [username, password] = bufferString.split(':'); // john='john'; mysecret='mysecret']
      let auth = {username, password}; // { username:'john', password:'mysecret' }

      return User.authenticateBasic(auth)
        .then(user => _authenticate(user))
        .catch(_authError);
    }

    async function _authBearer(authString) {
      try {
        let user = await User.authenticateToken(authString);
        return _authenticate(user);
      } catch(err) {
        _authError(err);
      }
    }

    async function _authenticate(user) {
      if(user) {
        if (!capability || user.can(capability)) {
          req.user = user;
          req.token = user.generateToken();
          next();
        } else {
          console.log('Can\'t', capability, user);
          await _authError();
        }
      }
      else {
        await _authError();
      }
    }
  

    async function _authError(err) {
      next({status: 401, statusMessage: 'Unauthorized', message: 'Invalid User ID/Password'});
    }

  };
