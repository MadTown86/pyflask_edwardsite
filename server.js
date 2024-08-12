import express from "express";
import bodyParser from "body-parser";
import { dirname } from "path";
import { fileURLToPath } from "url";
import axios from "axios";
import * as dotenv from "dotenv";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import GoogleStrategy from "passport-google-oauth20";


dotenv.config(); // Load the environment variables

const __dirname = dirname(fileURLToPath(import.meta.url));


const app = express();
const port = 3000;

let date = new Date();
let year = date.getFullYear();
let dbUser = process.env.DB_USER;
let dbPassword = process.env.DB_PASS;
const API_URL = "http://localhost:4000";



app.use(express.static(__dirname + "\\public"));  
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session(
  { secret: process.env.Session_Secret, resave: false, saveUninitialized: true,
    cookie: { secure: false, maxAge: 1000*60*60 }
  }))
app.use(passport.initialize());
app.use(passport.session());


//#region Get Routes

// Route to render the main_page
app.get("/", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("index.ejs", { year: year, username: req.user.email });
  } else {
  try {
    const response = await axios.get(`${API_URL}/`);
    if (response.status === 200) {
      console.log(response.data);
      res.render("index.ejs", { year: year });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
}
}
);

// Route to render /member page
app.get("/member", async (req, res) => {
  try {
    if (req.isAuthenticated()) {
      res.render("member.ejs", { year: year, username: req.user.email });
    } else {
      res.render("login.ejs", { year: year, error_message: "Please Log In" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

// Route to render the train_page
app.get("/train", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("train.ejs", { year: year, username: req.user.email});
  } else {
  try {
    const response = await axios.get(`${API_URL}/`);
    if (response.status === 200) {
      res.render("train.ejs", { year: year });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
  }
}
);

// Route to render the vision_page
app.get("/vision", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("vision.ejs", { year: year, username: req.user.email });
  } else {
  try {
    const response = await axios.get(`${API_URL}/`);
    if (response.status === 200) {
      res.render("vision.ejs", { year: year });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
}
}
);

// Route to render the password-reset request page
app.get("/reset_request", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("reset_request.ejs", { year: year, username: req.user.email });
  } else {
  try {
    const response = await axios.get(`${API_URL}/reset_request`);
    if (response.status === 200) {
      res.render("reset_request.ejs", { year: year});
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
}
}
);

// Route to render the password-reset page from user e-mail
app.get("/password-reset/:token", async (req, res) => {
  console.log("At Least Got Here");
  if (req.isAuthenticated()) {
    res.render("reset.ejs", { year: year, user: req.user.email });
  } else {
    console.log("req.params: ", req.params);
    console.log("req.query: ", req.query.email);
  try {
    let params = {
      token: req.params.token,
      email: req.query.email
    }
    console.log("Params: ", params);
    const response = await axios.get(`${API_URL}/password-reset/`, {params});
    console.log(response.status);
    if (response.status === 200) {
      console.log(req.query.email);
      res.render("reset.ejs", { year: year, user: req.query.email});
      // res.render("reset.ejs", { year: year, username: user, token: token});
    } else if (response.data === "Token Expired") {
      res.status(400).send("Token Expired");
    } else if (response.data === "Token Not Found") {
      res.status(400).send("Token Not Found");
    } else if (response.data === "Internal Server Error") {
      res.status(400).send("Internal Server Error");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
}
}
);

// Route to page to choose a trainer for scheduling
app.get("/trainer", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("trainer.ejs", { year: year, username: req.user.email });
  }
  else {
  try {
    const response = await axios.get(`${API_URL}/trainer`);
    if (response.status === 200) {
      res.render("trainer.ejs", { year: year });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
}
}
);

// Route to render the schedule_page
app.get("/schedule", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const response = await axios.get(`${API_URL}/schedule`, {year: year, username: req.user.email, trainer: req.body.trainer});
      if (response.status === 200) {
        res.render("schedule.ejs", { year: year, username: req.user.email, trainer: req.body.trainer, schedule: response.data.schedule });
      }
      } catch(error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
      }
  } else {
    res.render("login.ejs", { year: year, error_message: "Please Log In" });
}
});

// Route to render the food page
app.get("/food", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("food.ejs", { year: year, username: req.user.email });
  } else {
  try {
    const response = await axios.get(`${API_URL}/`);
    if (response.status === 200) {
      res.render("food.ejs", { year: year });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
}
}
);

// Route to render the login_page
app.get("/login", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("member.ejs", { year: year, username: req.user.email });
  } else {
  try {
    const response = await axios.get(`${API_URL}/login`);
    if (response.status === 200) {
      res.render("login.ejs", { year: year });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
}
}
);

// Route to render the register page
app.get("/register", async (req, res) => {
  try {
    const response = await axios.get(`${API_URL}/`);
    if (response.status === 200) {
      res.render("register.ejs", { year: year });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
}
);
 
// Route to render privacy_policy page
app.get("/privacy_policy", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("privacy_policy.ejs", { year: year, username: req.user.email });
  } else {
  try {
    const response = await axios.get(`${API_URL}/privacy_policy`);
    if (response.status === 200) {
      res.render("privacy_policy.ejs", { year: year });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
}
}
);

// Route to google oauth
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/members", passport.authenticate("google", {
  successRedirect: "/member",
  failureRedirect: "/login"
}));

// Route to render the contact_page
app.get("/contact", async (req, res) => {
  if (req.isAuthenticated()) {
    res.render("contact.ejs", { year: year, username: req.user.email });
  } else {
  try {
    const response = await axios.get(`${API_URL}/contact`);
    console.log("Response from server: ", response.data);
    res.render("contact.ejs", { year: year })
  }
  catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
}
});

//#endregion

//#region Post Routes
 
  // Route to post to contact_page
app.post("/api/contact", async (req, res) => {
  console.log(req.body);
  console.log("From server post: ", req.body.name, req.body.email, req.body.message);
    try {
        const response = await axios.post(`${API_URL}/contact`, req.body);
        console.log("Response from server: ", response.status);
        if (response.status === 200) {
          console.log("Data received successfully");
          res.render("contact.ejs", { year: year, sent: true });
        }
      } 
        catch (error) {
      console.error(error);
      res.status(500).send("Internal Server Error");
    }
  });

// Route to register a user
app.post("/api/register", async (req, res) => {
    try {
        const response = await axios.post(`${API_URL}/register`, req.body);
        console.log("Response from server: ", response.data);
        console.log("response [0]: ", response.data[0]);
        console.log("response data: ", response.data[1][0]);
       if (response.data == "Email already exists") {
          console.log("User already exists");
          res.render("register.ejs", { year: year, error_message: "User already exists" });
        } else if (response.data == "Internal Server Error") {
          console.log("Internal Server Error");
          res.render("register.ejs", { year: year, error_message: "Internal Server Error" });
        } else if (response.data[0] == "User Created Successfully"){
          req.login(response.data[1][0], (err) => {
            console.log(err);
            res.render("member.ejs", {year: year, username: req.user.email});
          });
        }
    } 
        catch (error) {
      console.error(error);
      res.status(500).send("Internal Server Error");
    }
  }
);

// Route to login a user
app.post("/login", passport.authenticate("local", 
  { failureRedirect: "/login", 
    sucessMessage: "You have been logged in",
    successRedirect: "/member",
    failureMessage: "Invalid username or password",
  }));

// Route to logout a user
app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/");
  });
});

//Route to submit reset_request
app.post("/api/reset_request", async (req, res) => {
  console.log(req.body);
  try {
    const response = await axios.post(`${API_URL}/reset_request`, req.body);
    console.log("Response from server: ", response.data);
    if (response.status === 200) {
      res.render("reset_request.ejs", { year: year, message: "Email Sent!" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

//#endregion

//#region Patch Routes

// Route to submit a new password
app.get("/api/reset", async (req, res) => {
  console.log(req);
  console.log(res);

  // try {
  //   const response = await axios.patch(`${API_URL}/reset`, req.body);
  //   console.log("Response from server: ", response.data);
  //   if (response.status === 200) {
  //     res.render("login.ejs", { year: year, message: "Password Reset!" });
  //   }
  // } catch (error) {
  //   console.error(error);
  //   res.status(500).send("Internal Server Error");
  // }
});
//#endregion

//#region Passport Strategies

// Passport login strategy
passport.use('local', new Strategy(async function verify(username, password, cb) {
  console.log("Email: ", username);
  console.log("Password: ", password);
  try {
    const response = await axios.post(`${API_URL}/login`, { username: username, password: password });
    console.log("Response from server: ", response.data);
    const user = response.data;
    
    if (response.status === 200 && response.data) {
      return cb(null, user);
    } else if (response.error) {
      return cb(response.error);
    } else {
      return cb(null, false);
    }
  } catch (error) {
    console.error(error);
    return cb(error);
  }
}
));

// Passport google strategy
passport.use("google", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/members",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
}, async function(accessToken, refreshToken, profile, cb) {
  let email = profile._json.email;
  let familyName = profile.name.familyName;
  let givenName = profile.name.givenName;

  const body = {
    email: email,
    familyName: familyName,
    givenName: givenName
  }
  try {
    const result = await axios.post(`${API_URL}/auth/google`, body);
    console.log(result.data);
    if (result.data[0] === "User registered") {
      return cb(null, result.data);
    } else {
      return cb(null, result.data);
    }
  } catch (error) {
    console.error(error);
    return cb(error);
  }
}));

// Passport serialize and deserialize user
passport.serializeUser((user, cb) => {
    cb(null, user);
  });

// Deserialize user
passport.deserializeUser((obj, cb) => {
  cb(null, obj);
});

//#endregion

// Start listening
app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});