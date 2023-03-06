const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const passportJWT = require('passport-jwt');
const GitHubStrategy = require('passport-github2').Strategy;

/* eslint-disable no-unused-vars */
const UserService = require('../../services/UserService');
const JTWStrategy = passportJWT.Strategy;
const ExtractJTW = passportJWT.ExtractJwt;

/**
 * This module sets up and configures passport
 * @param {*} config
 */
module.exports = (config) => {
  passport.use(
    new LocalStrategy(
      {
        passReqToCallback: true,
      },
      async (req, username, password, done) => {
        try {
          const user = await UserService.findByUsername(req.body.username);
          if (!user) {
            req.session.messages.push({
              text: 'Invalid username or password!',
              type: 'danger',
            });
            return done(null, false);
          }
          if (user && !user.verified) {
            req.session.messages.push({
              text: 'Plz verify your email address!',
              type: 'danger',
            });
            return done(null, false);
          }
          const isValid = await user.comparePassword(req.body.password);
          if (!isValid) {
            req.session.messages.push({
              text: 'Invalid username or password!',
              type: 'danger',
            });
            return done(null, false);
          }
          return done(null, user);
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  passport.use(
    new JTWStrategy(
      {
        jwtFromRequest: ExtractJTW.fromAuthHeaderAsBearerToken(),
        secretOrKey: config.JWTSECRET,
      },
      async (jwtPayload, done) => {
        try {
          const user = await UserService.findById(jwtPayload.userId);
          return done(null, user);
        } catch {
          return done(err);
        }
      }
    )
  );

  passport.use(
    new GitHubStrategy(
      {
        clientID: config.GITHUB_CLIENT_ID,
        clientSecret: config.GITHUB_CLIENT_SECRET,
        scope: ['user:email'],
        callbackURL: 'http://localhost:3000/auth/github/callback',
        passReqToCallback: true,
      },
      async (req, accessToken, refreshToken, profile, done) => {
        try {
          console.log('profile', profile);
          return done(null, false);
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  passport.serializeUser(async (user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await UserService.findById(id);
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  });
  return passport;
};
