//jshint esversion:6
//this imports environment variables to the document
//environment variables can be accessed by use "process.env.<variable name>"
require('dotenv').config();
//this is the package used for hashing data and salting
//const bcrypt = require("bcrypt");
//this just hashes data
//hashes data by calling it's function "md5(<data goes here>)"
const md5 = require("md5");
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//encryptes entries to the database
const encrypt = require("mongoose-encryption");
//these three packages are used for making cookies for authentication
const session = require("express-session");
const passport = require("passport");
const GooggleStrategy = require('passport-google-oauth20').Strategy;

const passportLocalMongoose = require("passport-local-mongoose");

//finds or creates a entry in the database
const findOrCreate = require('mongoose-findorcreate');

//the amount of salting arounds data will go through
//salt is extra numbers to the end of data to make the result hash harder to decipher
const saltRounds = 10;

const app = express();




app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));


//configures the passport package for being used
app.use(session({
    secret: "fjdpsrtunmzranz,yopqiqonz",
    resave: false,
    saveUninitialized: false
}));

//initializes the passport 
app.use(passport.initialize());
//tells express to use passport for sessions
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchemea = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

//sets up a plugin to use passport
//so that passport can hash and salt password inputs for us
userSchemea.plugin(passportLocalMongoose);
//sets the findorcreate package as a plugin for the database
userSchemea.plugin(findOrCreate);

//sets up a mongoose plugin
//the first argument is the purpose of the plugin
//second is a object, with a secret as the string used to dicpher the encryption
//and encryptedFields as an array of fields that should be encrypted
//userSchemea.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchemea);

//creates the strategy
passport.use(User.createStrategy());
//serializes users for sessoins for any strategy they decide to use
passport.serializeUser(User.serializeUser(function(user, done){
    done(null, user.id);
}));
//deseriales for logging out
passport.deserializeUser(User.deserializeUser(function(id, done){
    User,findById(id, function(err, User){
        done(err, User);
    })
}));


//creates a new google strategy for signing in with google
passport.use(new GooggleStrategy({
    //options for our google strategy
    //gives the id
    clientID: process.env.CLIENT_ID,
    //gives the client secret
    clientSecret: process.env.CLIENT_SECRET,
    //callback after authentication
    callbackURL: "http://localhost:3000/auth/google/secrets",
    //uses the google profile info api endpoint to get around google+ deprecation
    //userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
//ges the data we retreieved from their server to our database
    function(accessToken, refreshToken, profile, cb){
        console.log(profile);
        User.findOrCreate({googleID: profile.id }, function(err, user) {
            return cb(err, user);
        })
    }))

app.get("/", (req, res) => {
    res.render("home");
})


//the reason why it's set like this instead of the tranditional callback function that we usually set
//is cause it causes the page to reload forever, while when setting the function this way, it works immediately
app.get("/auth/google", 
passport.authenticate("google", { 
    scope: ["profile"] }));

//after it authenticates with google, redirects to login if it failes, if it succeeds, it redirects to secrets page
app.get("/auth/gooogle/secrets", 
passport.authenticate("google", {failureRedirect: "/login"}),
function(req, res) {
    res.redirect('secrets');
});


app.get("/login", (req, res) => {
    res.render("login");
})
app.get("/register", (req, res) => {
    res.render("register");
})

app.get("/secrets", (req, res) => {
    //finds a datbase entry that has the secret value not null (nothing)
    User.find({"secret": {$ne:null}}, function(err, foundUsers) {
        if(err){
            console.log(err);
        } else {
            if(foundUsers){
                //once it finds the users with secrets, it will redirect the user to the secrets page and display other's secrets
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    })







    // if(req.isAuthenticated()){
    //     res.render("secrets")
    // } else {
    //     res.redirect("/login")
    // }
});


app.get("/submit", (req, res) => {
    if(req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})


app.get("/logout", (req, res) => {
    //deauthenticates users for their session
    req.logout();
    res.redirect("/");
})

app.post("/submit", (req, res) => {
    //gets the secret the user gave 
    const submittedSecret = req.body.secret;
    
    console.log(req.user.id);
    //find the user by their id
    User.findById(req.user.id, function(err, foundUser) {
        if(err){

        } else {
            if(foundUser){
                //sets their secret value in their database entry as the secret they gave
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    //redirects the users to the secrets page so they can view their own secret
                    res.redirect("/secrets")
                });
            }
        }
    })
})



app.post("/register", (req, res) => {

    //registers the user for a new account, local-mongoose is dealing with mongoose while making this
    //first there is a object with the username , this the provided password, then a function for when after the operation is successful
    User.register({username: req.body.username}, req.body.password, (err, user) => {

        //if there is an error, log the error and redirect the user to the register page to retry
        if(err){
            console.log(err);
            res.redirect("/register")
        } else {
            //if the register was successfull, the passport package will authenticate the user locally
            //after they're authenticated and registered, they're redirected to the secrets page
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets")
            })
        }
    });
    
    // 
    //uses the hash function, the first part is the password itself the user gave
    //next is the amount of saltrounds (in our case 10)
    //and a callback function with a potential err variable and the hashing result
    // bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
        //makes a newUser object for preparing it to be saved in the database
        // const newUser = new User({
            // email: req.body.username,
            // password: hash
        // });
        //saves the data in the database
        //after the data is saved, if there were no errors, the user is redirected to the secrets page
        // newUser.save((err) => {
            // if(err) {
                // console.log(err);
            // } else {
                // res.render("secrets");
            // }
        // });
    // })
    // 
// 
   
})


app.post("/login", (req, res) => {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if(err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            })
        }

    })
    // const username = req.body.username;
    // const password = req.body.password
    // tries to find the email the user specified
    //
    // User.findOne({email: username}, (err, foundUser) => {
    //     if(err){
    //         console.log(err);
    //     } else {

    // once the email is found and there was no errors
    //it will hash the given password the user gave and compare it to the hashed password in the database
    // if they're the same, the user is redirected to the secrets page
    //         if(foundUser){
            // the first argument is the password given by the user
            //second is the hashed password in the database
            // and third is a callback function with a err variable and the result that'll be either true of false depending on if the hashes are the same
    //             bcrypt.compare(password, foundUser.password, (err, result) => {
    //                 if(result == true){
    //                     res.render("secrets");
    //                 }
    //             })
                
    //         }
    //     }
    // })
})



app.listen(process.env.PORT, () => {
    console.log("Server has started");
})