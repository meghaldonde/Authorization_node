//jshint esversion:6
require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
//const encrypt = require('mongoose-encryption');
//using md5 encryption
//const md5 = require('md5');
//bcrypt hash with salt method
//const bcrypt = require('bcrypt');
//const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocal = require('passport-local');
const passportLocalMongoose = require('passport-local-mongoose');

//Oath google token based authentication
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

FacebookStrategy = require('passport-facebook').Strategy;


const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

//express-session use
app.set('trust proxy', 1) // trust first proxy
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false

}));

app.use(passport.initialize());
app.use(passport.session());

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


//authentication using mongoose-encryption cipher text method
//userSchema.plugin( encrypt, { secret : process.env.SECRET, encryptedFields : ['password']});

const User = mongoose.model("User", userSchema);


// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
//passport.serializeUser(User.serializeUser());
//passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


//OAuth google
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


//OAuth with Facebook
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ facebookId: profile.id }, function(err, user) {
      if (err) { return done(err); }
      done(null, user);
    });
  }
));


//connect to mongodb
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true ,   useCreateIndex: true} );


app.get("/", function(req, res){
  res.render("home");
});


app.get("/login", function(req, res){
  res.render("login");
});

app.get('/secrets', function(req, res){
  // if(req.isAuthenticated()){
  //   res.render('secrets');
  // }else{
  //   res.redirect('/login');
  // }

  User.find({secret: {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    }else{
      if(foundUsers){
        res.render('secrets',{usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render('submit');
  }else{
    res.redirect('/login');
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(e){
          if(e){
            console.log(e);
          }else{
            res.redirect("/secrets");
          }
        });
      }
    }
  });

});


app.get("/register", function(req, res){
  res.render("register");
});

app.post("/register", function(req, res){
//using passport register function
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect('/register');
    }else{
      passport.authenticate('local')(req, res, function(){
        res.redirect('/secrets');
      });
    }
  });


  // bcrypt.hash(req.body.password, saltRounds, function(err,hash){
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //     //password: md5(req.body.password)
  //   });
  //   newUser.save(function(err){
  //
  //     if (!err){
  //
  //       res.render("secrets");
  //
  //     }else{
  //     res.send(err);
  //     }
  //   });
  //});


});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
      if(err){
        console.log(err);
      }
      else{
          passport.authenticate('local')(req, res, function(){
            res.redirect('/secrets');
        });
      }
    }
  );



//   User.findOne({email:req.body.username},
//     function(err, foundUser){
//
//   if (!err){
//     if(foundUser){
//
//       //if(foundUser.password === md5(req.body.password)){
//       bcrypt.compare(req.body.password, foundUser.password, function(err, result){
//         if(result === true){
//           res.render("secrets");
//         }else{
//           res.send("Incorrect  password. ")
//
//         }
//
//       });
//
//     }else{
//       res.send("User not found. ")
//     }
//
//   }else{
//     res.send(err);
//   }
// });
});

app.get("/auth/google",
    passport.authenticate("google",{ scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });


  app.get('/auth/facebook', passport.authenticate('facebook'));

  app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { successRedirect: '/secrets',
                                      failureRedirect: '/login' }));

app.get('/logout', function(req, res){
  //ising passport logout function
  req.logout();
  res.redirect('/');
});

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
