const mongoose = require('mongoose');
const promisify = require('es6-promisify');
const User = mongoose.model('User');

exports.loginForm = (req, res) => {
  res.render('login', { title: 'Login' });
};

exports.registerForm = (req, res) => {
  res.render('register', { title: 'Register' });
};

exports.register = async (req, res, next) => {
  const user = new User({ email: req.body.email, name: req.body.name });

  // We use promisify here becuase PassportJS register isn't a promise.
  // promisify allows us to wrap it in a promise so we can use async/await.
  // User.register comes from Passport plugin
  const register = promisify(User.register, User);
  await register(user, req.body.password);
  next();
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

exports.account = (req, res) => {
  res.render('account', { title: 'Edit your account' });
};

exports.updateAccount = async (req, res) => {
  const updates = {
    name: req.body.name,
    email: req.body.email
  };

  const user = await User.findOneAndUpdate(
    { _id: req.user._id },
    { $set: updates },
    { new: true, runValidators: true, context: 'query' }
  );

  req.flash('success', 'Updated the profile!');
  res.redirect('back');
};
