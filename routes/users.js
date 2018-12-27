const express = require('express');
const router = express.Router();
const Joi = require('joi');
const passport = require('passport');
const randomstring = require('randomstring');

const mailer = require('../misc/mailer');
const User = require('../models/user');

const userSchema = Joi.object().keys({
  email: Joi.string().email().required(),
  username: Joi.string().required(),
  password: Joi.string().regex(/^[a-zA-Z0-9]{3,10}$/).required(),
  confirmationPassword: Joi.any().valid(Joi.ref('password')).required()
});

const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  req.flash('error', 'You must be registered first !');
  res.redirect('/');
};

const isNotAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    req.flash('error', 'Sorry, but you are already logged in !');
    res.redirect('/');  
  } else {
    return next();
  }
};


router.route('/register')
  .get(isNotAuthenticated, (req, res) => {
    res.render('register');
  })
  .post(async (req, res, next) => {
    try {
      const result = Joi.validate(req.body, userSchema);
      if (result.error) {
        req.flash('error', 'Data is not valid !. Please try again. !');
        res.redirect('/users/register');
        return;
      }

      const user = await User.findOne({ 'email': result.value.email });  
      if (user) {
        req.flash('error', 'Email alredy in use !.');
        res.redirect('/users/register');
        return;
      } 

      const hash = await User.hashPassword(result.value.password);
      
      const secretToken = randomstring.generate();
      result.value.secretToken = secretToken;
      result.value.active = false;

      delete result.value.confirmationPassword;
      result.value.password = hash;
      
      const newUser = await new User(result.value);

      await newUser.save();

      const html = `Hi there !,
      <br />
      Thank you for registering !
      <br />
      <br />
      Please verify your email by typing the following token: 
      <br />
      Token: <strong>${secretToken}</strong>
      <br />
      On the following page:
      <a href="http://localhost:5000/users/verify">http://localhost:5000/users/verify</a>
      <br />
      Have a pleasant day !`;

      await mailer.sendEmail('register@siteauthenticationwithnode.com', newUser.email, 'Register confirmation !', html);

      req.flash('success', 'Please ! Check your email to complete the registration !');
      res.redirect('/users/login');

    } catch (error) {
      next(error);
    }
    
  });

router.route('/verify')
.get(isNotAuthenticated, (req, res) => {
  res.render('verify');
})
.post(async (req, res, next) => {
  try {
    const { secretToken } = req.body;
    const user = await User.findOne({ 'secretToken': secretToken.trim() });  
    if (!user) {
      req.flash('error', 'Invalid Token !');
      res.redirect('/users/verify');
      return;
    } else {
      user.active = true;
      user.secretToken = '';
      await user.save();
      req.flash('success', 'You account is verified successfully !. Now, you may login !.');
      res.redirect('/users/login');
    }  
  } catch (error) {
    next(error);
  }  
});

router.route('/login')
  .get(isNotAuthenticated, (req, res) => {
    res.render('login');
  })
  .post(passport.authenticate('local', {
    successRedirect: '/users/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
  }));

router.route('/logout')
  .get(isAuthenticated, (req, res, next) => {
    req.logout();
    req.flash('success', 'Successfully logged out. Hope to see you soon !.');
    res.redirect('/');
  });

router.route('/dashboard')
  .get(isAuthenticated, (req, res) => {
    res.render('dashboard', {
      username: req.user.username
    });
  });

  module.exports = router;