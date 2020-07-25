//jshint esversion:6
require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
//const encrypt = require('mongoose-encryption');
const md5 = require('md5');
const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));


const userSchema = new mongoose.Schema({
    email: String,
    password: String
});


//authentication using mongoose-encryption cipher text method
//userSchema.plugin( encrypt, { secret : process.env.SECRET, encryptedFields : ['password']});

const User = mongoose.model("User", userSchema);

//connect to mongodb
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true } );


app.get("/", function(req, res){
  res.render("home");
});


app.get("/login", function(req, res){
  res.render("login");
});


app.get("/register", function(req, res){
  res.render("register");
});

app.post("/register", function(req, res){
  const newUser = new User({
    email: req.body.username,
    password: md5(req.body.password)
  });
  newUser.save(function(err){

  if (!err){

    res.render("secrets");

  }else{
    res.send(err);
  }
});
});

app.post("/login", function(req, res){

  User.findOne({email:req.body.username},
    function(err, foundUser){

  if (!err){
    if(foundUser){

      if(foundUser.password === md5(req.body.password)){
        res.render("secrets");
      }else{
        res.send("Incorrect  password. ")

      }


    }else{
      res.send("User not found. ")
    }

  }else{
    res.send(err);
  }
});
});

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
