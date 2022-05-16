const { Router } = require('express');
const router = new Router();

const User = require('../models/User.model');

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
    const { username, email, password } = req.body;
 
    bcryptjs
      .genSalt(saltRounds)
      .then(salt => bcryptjs.hash(password, salt))
      .then(hashedPassword => {
        return User.create({
            username,
            email,
            passwordHash: hashedPassword
          });
        })
        .then(userFromDB => {
          console.log('Newly created user is: ', userFromDB);
        })
        .catch(error => next(error));
    });

module.exports = router;
