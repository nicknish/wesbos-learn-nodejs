const mongoose = require('mongoose');
const Store = mongoose.model('Store');
const multer = require('multer');
const jimp = require('jimp');
const uuid = require('uuid');

const multerOptions = {
  storage: multer.memoryStorage(),
  fileFilter(req, file, next) {
    // mimetype is the most reliable and safe way to determine whether the file
    // is actually an image. Server-side validation is critical to upload safely.
    const isPhoto = file.mimetype.startsWith('image/');

    if (isPhoto) {
      next(null, true);
    } else {
      next({ message: "That filetype isn't allowed." }, false);
    }
  }
};

exports.upload = multer(multerOptions).single('photo');

exports.resize = async (req, res, next) => {
  // check if there is no new file to resize
  if (!req.file) return next();

  // rename
  const extension = req.file.mimetype.split('/')[1];
  req.body.photo = `${uuid.v4()}.${extension}`;

  // resize
  const photo = await jimp.read(req.file.buffer);
  await photo.resize(800, jimp.AUTO);

  // write to the server
  await photo.write(`./public/uploads/${req.body.photo}`);

  next();
};

exports.homePage = (req, res) => {
  res.render('index');
};

exports.addStore = (req, res) => {
  res.render('editStore', { title: 'Add Store' });
};

exports.editStore = async (req, res) => {
  const store = await Store.findOne({ _id: req.params.id });
  res.render('editStore', { title: `Edit ${store.name}`, store });
};

exports.updateStore = async (req, res) => {
  const store = await Store.findOneAndUpdate({ _id: req.params.id }, req.body, {
    new: true, // return the new store instead of the old one
    runValidators: true // validations only run on create so we have to explicitly run it
  }).exec(); // exec() to run the query

  req.flash(
    'success',
    `Successfully updated <strong>${store.name}</strong>. <a href="/stores/${
      store.slug
    }">View Store</a>`
  );
  res.redirect(`/stores/${store._id}/edit`);
};

exports.createStore = async (req, res) => {
  const store = new Store(req.body);
  await store.save();
  req.flash('success', `Successfully created ${store.name}.`);
  res.redirect('/');
};

exports.getStores = async (req, res) => {
  const stores = await Store.find();
  res.render('stores', { title: 'Stores', stores });
};

exports.getStore = async (req, res) => {
  const store = await Store.findOne({ slug: req.params.slug });
  if (!store) {
    return next();
  }
  res.render('store', { title: store.name, store });
};

exports.getStoresByTag = async (req, res) => {
  const tag = req.params.tag;
  const tagQuery = tag || { $exists: true }; // { $exists } passes back anything with a tag

  const tagsPromise = Store.getTagsList();
  const storesPromise = Store.find({ tags: tagQuery });

  // await for multiple Promises to come back
  const [tags, stores] = await Promise.all([tagsPromise, storesPromise]);

  res.render('tag', { title: 'Tags', tags, tag, stores });
};
