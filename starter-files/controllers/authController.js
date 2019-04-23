const passport = require('passport');
const crypto = require('crypto');
const mongoose = require('mongoose');
const User = mongoose.model('User');
const promisify = require('es6-promisify');

exports.login = passport.authenticate('local', {
  failureRedirect: '/login',
  failureFlash: 'Failed to login.',
  successRedirect: '/',
  successFlash: 'Successfully logged in.'
});

exports.logout = (req, res) => {
  req.logout();
  req.flash('success', 'You are now logged out! 👋');
  res.redirect('/');
};

exports.isLoggedIn = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  req.flash('error', 'You must be logged in.');
  res.redirect('/login');
};

exports.forgot = async (req, res) => {
  const FORGOT_SUCCESS_COPY =
    'If an account exists with that email address, you will receive an email with a reset password link.';

  // 1. See if user exists
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    req.flash('error', FORGOT_SUCCESS_COPY);
    redirect('/login');
  }

  // 2. Set reset tokens and expiry on their account
  user.resetPasswordToken = crypto.randomBytes(20).toString('hex');
  user.resetPasswordExpires = Date.now() + 3600000; // 1 hour from now
  await user.save();

  // 3. Send them an email with the token
  const resetUrl = `https://${req.headers.host}/account/reset/${
    user.resetPasswordToken
  }`;
  req.flash('success', `${FORGOT_SUCCESS_COPY}${resetUrl}`);

  // 4. Redirect to login page
  res.redirect('/login');
};

exports.reset = async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() }
  });

  if (!user) {
    req.flash('error', 'Password reset is invalid or has expired');
    return res.redirect('/login');
  }

  res.render('reset', { title: 'Reset your password' });
};

exports.confirmedPasswords = (req, res, next) => {
  if (req.body.password === req.body['password-confirm']) {
    next();
    return;
  }
  req.flash('error', 'Passwords do not match');
  res.redirect('back');
};

exports.update = async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() }
  });

  if (!user) {
    req.flash('error', 'Password reset is invalid or has expired');
    return res.redirect('/login');
  }

  // Made available from PassportJS
  const setPassword = promisify(user.setPassword, user);
  await setPassword(req.body.password);

  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  const updatedUser = await user.save();
  // Login user via PassportJS
  await req.login(updatedUser);

  req.flash('Success', 'Your password has been reset and you are logged in.');
  res.redirect('/');
};
