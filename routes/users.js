const express = require('express');
const router = express.Router();
const Joi = require('joi');

const User = require('../models/user');

const userSchema = Joi.object().keys({
  email: Joi.string().email().required(),
  username: Joi.string().required(),
  password: Joi.string().regex(/^[a-zA-Z0-9]{3,10}$/).required(),
  confirmationPassword: Joi.any().valid(Joi.ref('password')).required()
});

router.route('/register')
  .get((req, res) => {
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
      } else {
        
      }
    } catch (error) {
      next(error);
    }
    
  });

router.route('/login')
  .get((req, res) => {
    res.render('login');
  });

module.exports = router;