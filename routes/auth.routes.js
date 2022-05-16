const { Router } = require('express');
const router = new Router();

const User = require('../models/User.model');
const mongoose = require('mongoose'); // <== has to be added

// setup for bcrypt is created after the post route
const bcryptjs = require('bcryptjs');
const saltRounds = 10;

//GET route
router.get('/signup', (req, res) => res.render('auth/signup'));



//POST route
router.post('/signup', (req, res, next) => {
    // we delete this so it doesnt appear in the console
    //console.log('The form data: ', req.body);
    
    //we add this do the bcryptjs works
    const { username, password } = req.body;
    
    if (!username || !password) {
      res.render('auth/signup', { errorMessage: 'All fields are mandatory. Please provide your username and password.' });
      return;
    }

    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res
      .status(500)
      .render('auth/signup', { errorMessage: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' });
    return;
  }

    bcryptjs
      .genSalt(saltRounds)
      .then(salt => bcryptjs.hash(password, salt))
      .then(hashedPassword => {
        return User.create({
            username,
            passwordHash: hashedPassword
          });
        })
        .then(userFromDB => {
           //we delete this so it can redirect to the profile page 
           //console.log('Newly created user is: ', userFromDB);
            res.redirect('/userProfile');
        })
        .catch(error => {
          if (error instanceof mongoose.Error.ValidationError) {
            res.status(500).render('auth/signup', { errorMessage: error.message });
          } else if (error.code === 11000) {
            res.status(500).render('auth/signup', {
               errorMessage: 'Username need to be unique. Username is already used.'
            });
          } else {
            next(error);
          }
        }); 
        //GET log in
      })
      
// ========> LOG IN

// GET log in
router.get('/login', (req, res) => res.render('auth/login'));

//POST log in
router.post('/login', (req, res, next) => {
  console.log('SESSION =====> ', req.session);
  
  const { username, password } = req.body;
 
  if (username === '' || password === '') {
    res.render('auth/login', {
      errorMessage: 'Please enter both, username and password to login.'
    });
    return;
  }
 
  User.findOne({ username })
    .then(user => {
      if (!user) {
        res.render('auth/login', { errorMessage: 'Username is not registered. Try again.' });
        return;
      } else if (bcryptjs.compareSync(password, user.passwordHash)) {
        //res.render('users/user-profile', { user });
        req.session.currentUser = user;
        res.redirect('/userProfile');
      } else {
        res.render('auth/login', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch(error => next(error));
});

//GET route profile
router.get('/userProfile', (req, res) => {
  res.render('users/user-profile', { userInSession: req.session.currentUser });
  });

  //POST log out
   router.post('/logout', (req, res, next) => {
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/');
  });
});
module.exports = router;
