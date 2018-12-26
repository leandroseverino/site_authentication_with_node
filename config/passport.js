const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/user');

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser( async (id, done) => {
     try {
        const user = await User.findById(id);
        done(null, user);         
     } catch (error) {
         done(error, null);
     }
});

passport.use('local', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: false
}, async (email, password, done) => {
    try {
        const user = await User.findOne({ 'email': email});
        if (!user) {
            return done(null, false, { message: 'Unknown User'});
        }
        const isValid = await User.comparePasswords(password, user.password);

        if (! isValid) {
            return done(null, false, { message: 'Invalid Password'});            
        } 
        return done(null, user);
    } catch (error) {
        done(error, false, { message: 'Failed to check the User !. Check the database connectivity !'});
    }
}));