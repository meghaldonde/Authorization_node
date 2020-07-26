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
    password: String
});

userSchema.plugin(passportLocalMongoose);


//authentication using mongoose-encryption cipher text method
//userSchema.plugin( encrypt, { secret : process.env.SECRET, encryptedFields : ['password']});

const User = mongoose.model("User", userSchema);


// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//connect to mongodb
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true ,   useCreateIndex: true} );


app.get("/", function(req, res){
  res.render("home");
});


app.get("/login", function(req, res){
  res.render("login");
});

app.get('/secrets', function(req, res){
  if(req.isAuthenticated()){
    res.render('secrets');
  }else{
    res.redirect('/login');
  }
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

app.get('/logout', function(req, res){
  //ising passport logout function
  req.logout();
  res.redirect('/');
});

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
