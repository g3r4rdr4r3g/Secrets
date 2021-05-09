//jshint esversion:6
require('dotenv').config() //always at top, used in Level 2
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
//Level 1 - Username and password
const mongoose = require("mongoose");
//Level 2 - Database encryption
//const encrypt = require("mongoose-encryption");
//Level 3 - Hashing passwords
//const md5 = require("md5");
//Level 4 - Hashing and salting
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
//Level 5 - Cookies and sessions
const session = require("express-session");
const passport = require("passport");
//requires passport-local package to work
const passportLocalMongoose = require("passport-local-mongoose");
//Level 6 - OAuth 2.0 using Google Login
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

//always below order to be followed - IMPORTANT
app.use(session({
  secret: "Thisisthesecretstringinsteadoftwokeys",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Level 2 Database encryption
//add this BEFORE creating a new mongoose model
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//works only for passport-mongoose-local
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

//works for all
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    //console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

app.get("/auth/google", passport.authenticate('google', {
    scope: ["profile"]
}));

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

//only used from Level 5
app.get("/secrets", function(req, res){

  User.find({"secret": {$ne: null}}, function(err, result){
    if(err)
      console.log(err);
    else{
      if(result){
        res.render("secrets", {resultsWithSecrets: result});
      }
    }
  });

  // //check if user is authenticated (already logged in)
  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // }
  // else{
  //   res.redirect("/login");
  // }
});

//Allowing users to submit Secrets
app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
})

app.get("/logout", function(req, res){
  //passport logout
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res){
  // Level 4 - bcrypt for salting and hashing password
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   //Level 3 -  Store hash in your password DB.
  //   const username = req.body.username;
  //   //const password = md5(req.body.password);
  //   const password = hash;
  //   const newUser = new User ({
  //     username: username,
  //     password: password
  //   });
  //   newUser.save(function(err){
  //     if(err){
  //       console.log(err);
  //     }
  //     else {
  //       res.render("secrets");
  //     }
  //   });
  // });

  //Level 5
  User.register({username: req.body.username}, req.body.password, function(err, result){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/login", function(req, res){
  //Lvel 4 becrypt
  // const username = req.body.username;
  // // Level 3 hash password const password = md5(req.body.password);
  // const password = req.body.password;
  //
  // User.findOne({username: username}, function(err, result){
  //   if(err){
  //     console.log(err);
  //   }
  //   else{
  //     if(result){
  //       // Load hash from your password DB.
  //       bcrypt.compare(password, result.password, function(err, hashResult) {
  //         // result == true
  //         if(hashResult === true)
  //           res.render("secrets");
  //         else {
  //           console.log("Wrong password");
  //         }
  //       });
  //     }
  //     else{
  //       console.log("Username doesnt exist");
  //     }
  //   }
  // });

  //Level 5
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  //passport login
  req.login(user, function(err){
    if(err)
      console.log(err);
    else
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
  });

});

app.post("/submit", function(req, res){
  const secretText = req.body.secret;

  User.findById(req.user.id, function(err, result){
    if(err)
      console.log(err);
    else{
      if(result){
        result.secret = secretText;
        result.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});








app.listen(3000, function () {
  console.log("Server started on port 3000");
});
