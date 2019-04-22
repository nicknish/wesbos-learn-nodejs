// const mongoose = require('mongoose');
// const User = mongoose.model('User');

exports.loginForm = (req, res) => {
  res.render('login', { title: 'Login' });
};

exports.registerForm = (req, res) => {
  res.render('register', { title: 'Register' });
};

exports.validateRegister = (req, res, next) => {
  req.sanitizeBody('name');
  req.checkBody('name', 'Name cannot be blank.').notEmpty();
  req.checkBody('email', 'Email is invalid.').isEmail();

  // normalizeEmail helps normalize email addresses like so:
  // e.g. wesBos@gmail.com, WESBOS@gmail.com, w.es.bos@gmail.com => wesbos@gmail.com
  req.sanitizeBody('email').normalizeEmail({
    remove_dots: false,
    remove_extension: false,
    gmaiL_remove_subaddress: false
  });

  req.checkBody('password', 'Password cannot be blank.').notEmpty();
  req
    .checkBody('password-confirm', 'Confirmed Password cannot be blank.')
    .notEmpty();
  req
    .checkBody('password-confirm', 'Passwords does not match.')
    .equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    req.flash('error', errors.map(err => err.msg));
    res.render('register', {
      title: 'Register',
      body: req.body,
      flashes: req.flash()
    });
    return;
  }

  next();
};
