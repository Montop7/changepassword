const express = require('express');
const router = express.Router();
const User = require('../models/user');
const bcrypt = require('bcryptjs');

// Signup route
router.get('/signup', (req, res) => {
  res.render('signup');
});

router.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    req.session.userId = user._id;
    res.redirect('/dashboard');
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Login route
router.get('/login', (req, res) => {
  res.render('login');
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).send('Invalid username or password');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send('Invalid username or password');
    }
    req.session.userId = user._id;
    res.redirect('/dashboard');
  } catch (err) {
    res.status(400).send(err.message);
  }
});

router.get('/changepassword', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.render('changepassword', { message: req.query.message });
});

router.post('/changepassword', async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const userId = req.session.userId;

    if (!userId) {
        return res.redirect('/login');
    }

    if (newPassword !== confirmPassword) {
        return res.render('changepassword', { message: 'New passwords do not match.' });
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.redirect('/login');
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.render('changepassword', { message: 'Current password is incorrect.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();

        res.redirect('/dashboard');
    } catch (err) {
        res.status(500).send(err.message);
    }
});

// Dashboard route
router.get('/dashboard', async (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.redirect('/login');
    }
    res.render('dashboard', { user });
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Logout route
router.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

module.exports = router;
