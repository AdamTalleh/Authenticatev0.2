const express = require('express');
const Joi = require('joi');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const db = require('../db/connections');
const users = db.get('users');
users.createIndex('email', { unique: true });

const router = express.Router();

const schema = Joi.object().keys({
  password: Joi.string().regex(/^[a-zA-Z0-9_@%$&-]{8,20}$/).required(),
    email: Joi.string().email({ minDomainAtoms: 2})
});

// const createTokenSendResponse = function(user, res, next) {
// const createTokenSendResponse = (user, res, next) => {
function createTokenSendResponse(user, res, next) {
  const payload = {
    _id: user._id,
    email: user.email
  };

  jwt.sign(payload, process.env.TOKEN_SECRET, {
    expiresIn: '1d'
  }, (err, token) => {
    if (err) {
      respondError422(res, next);
    } else {
      res.json({
        token
      });
    }
  });
}

// any route in here is pre-pended with /auth
router.get('/', (req, res) => {
  res.json({
    message:  'got it !'
  });
});

router.post('/signup', (req, res, next) => {
  const result = Joi.validate(req.body, schema);
  if (result.error === null) {
    users.findOne({
      email: req.body.email
    }).then(user => {
      // if user is undefined, username is not in the db, otherwise, duplicate user detected
      if (user) {
        // there is already a user in the db with this username...
        // respond with an error!
        const error = new Error('this account is already in DB , please choose another one!');
        res.status(409);
        next(error);
      } else {
        // hash the password
        bcrypt.hash(req.body.password.trim(), 12).then(hashedPassword => {
          // insert the user with the hashed password
          const newUser = {
            email: req.body.email,
            password: hashedPassword
          };

          users.insert(newUser).then(insertedUser => {
            createTokenSendResponse(insertedUser, res, next);
          });
        });
      }
    });
  } else {
    res.status(422);
    next(result.error);
  }
});

function respondError422(res, next) {
  res.status(422);
  const error = new Error('Unable to login.');
  next(error);
}

router.post('/login', (req, res, next) => {
  const result = Joi.validate(req.body, schema);
  if (result.error === null) {
    users.findOne({
      email: req.body.email,
    }).then(user => {
      if (user) {
        bcrypt
          .compare(req.body.password, user.password)
          .then((result) => {
            if (result) {
              createTokenSendResponse(user, res, next);
            } else {
              respondError422(res, next);
            }
          });
      } else {
        respondError422(res, next);
      }
    });
  } else {
    respondError422(res, next);
  }
});

module.exports = router;
