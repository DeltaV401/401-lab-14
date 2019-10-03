'use strict';

const express = require('express');
const authRouter = express.Router();

const User = require('./users-model.js');
const auth = require('./middleware.js');
const oauth = require('./oauth/google.js');

authRouter.post('/signup', (req, res, next) => {
  let user = new User(req.body);
  user.save()
    .then( (user) => {
      req.token = user.generateToken();
      req.user = user;
      res.set('token', req.token);
      res.cookie('auth', req.token);
      res.send(req.token);
    })
    .catch(next);
});

authRouter.post('/signin', auth(), (req, res, next) => {
  res.cookie('auth', req.token);
  res.send(req.token);
});

authRouter.get('/oauth', (req,res,next) => {
  oauth.authorize(req)
    .then( token => {
      res.status(200).send(token);
    })
    .catch(next);
});

authRouter.post('/key', auth(), (req,res,next) => {
  let key = req.user.generateKey();
  res.status(200).send(key);
});

authRouter.get('/public-stuff', auth(), (req,res,next) => {
  res.sendStatus(200);
});

authRouter.get('/hidden-stuff', auth('user'), (req,res,next) => {
  res.sendStatus(200);
});

authRouter.get('/something-to-read', auth('read'), (req,res,next) => {
  res.sendStatus(200);
});

authRouter.post('/create-a-thing', auth('create'), (req,res,next) => {
  res.sendStatus(200);
});

authRouter.put('/update', auth('update'), (req,res,next) => {
  res.sendStatus(200);
});

authRouter.patch('/jp', auth('update'), (req,res,next) => {
  res.sendStatus(200);
});

authRouter.delete('/bye-bye', auth('delete'), (req,res,next) => {
  res.sendStatus(200);
});

authRouter.get('/everything', auth('superuser'), (req,res,next) => {
  res.sendStatus(200);
});

module.exports = authRouter;
