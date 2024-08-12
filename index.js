import express from "express";
import bodyParser from "body-parser";
import { dirname } from "path";
import { fileURLToPath } from "url";
import * as dotenv from "dotenv";
import axios from "axios";
import pg from "pg";


dotenv.config(); // Load the environment variables

const __dirname = dirname(fileURLToPath(import.meta.url));
console.log(__dirname);

const app = express();
const DB_URL = "http://localhost:5000";
const port = 4000;
const saltRounds = 10;

let date = new Date();
let year = date.getFullYear();

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


//#region Basic Routes
// Get main page
app.get("/", (req, res) => {
    res.status(200).send({ year: year });
});

// Get train page
app.get("/train", (req, res) => {
    res.json({ year: year });
});

// Get vision page
app.get("/vision", (req, res) => {
    res.json({ year: year });
});

// Get food page
app.get("/food", (req, res) => {
    res.json({ year: year });
});

// Get schedule page
app.get("/schedule", (req, res) => {
    res.json({ year: year });
});

// Get contact page
app.get("/contact", (req, res) => {
    res.json({ year: year });
});

// Get login page
app.get("/login", (req, res) => {
    res.json({ year: year });
});

// Route to render privacy policy page
app.get("/privacy_policy", (req, res) => {
    res.status(200).send({ year: year });
});


// Route to render reset request page
app.get("/reset_request", (req, res) => {
    res.status(200).send({ year: year });
}
);


// Route to password-reset page with token
app.get("/password-reset/", async (req, res) => {
    console.log(req.query);
    if (!req.body) {
        return res.status(400).send("Incorrect Access Attempted");
    } else {
        const result = await axios.get(`${DB_URL}/password-reset/`, { params: req.query });
        console.log("ResultData: ", result.data);
        if (result.data === "Token Expired") {
            res.status(400).send("Token Expired");
        } else if (result.data === "Token Not Found") {
            res.status(400).send("Token Not Found");
        } else if (result.data === "Not Valid Token") {
            res.status(400).send("Not Valid Token");
        } else if (result.data[0] === "Token found"){
            res.status(200).send({ year: year, user: result.data[1] });
        }
    }
});
//#endregion


//#region POSTS
// Route to contact_page
app.post("/contact", (req, res) => {
    console.log(req.body);
    if (!req.body) {
        return res.status(400).send("No data in request body");
    } else {
        let name = req.body.name;
        let email = req.body.email;
        let message = req.body.message;
        let sent = true;
        console.log(name, email, message);
        const contact_data = {
            name: name,
            email: email,
            message: message
        };

        try {
            const response = axios.post(`${DB_URL}/contact`, contact_data);
            res.status(200).send("Data inserted successfully");
        } 
        catch (error) {
            console.error(error);
            res.status(500).send("Internal Server Error");
        }
    }
    });



// Route to submit user request for password reset
app.post("/reset_request", async (req, res) => {
    console.log(req.body.email_reset_password)
    if (!req.body) {
        return res.status(400).send("Missing data");
    } else {
        try {
            const response = await axios.post(`${DB_URL}/reset_request`, {email: req.body.email_reset_password});
            if (response.data === "Email Not Found") {
                res.status(400).send("Email Not Found");
            } else if (response.data === "Internal Server Error") {
                res.status(400).send("Internal Server Error");
            } else {
                res.status(200).send("Email Sent");
            }
        } catch (error) {
            console.error(error);
            res.status(500).send("Internal Server Error");
        }
    }
});

// Route to render the register_page.
app.post("/register", async (req, res) => {
    if (!req.body) {
        return res.status(400).send("Missing data");
    } else {
        let username = req.body.email_register;
        const email_check = {
            username: username,
        }  
        try {
            const response = await axios.post(`${DB_URL}/register/check`, email_check);
            console.log(response.data);
            if (response.data == "Email already exists") {
                console.log("Email already exists")
                res.send("Email already exists")
            } else if (response.data === "Email is available") {
                let first_name = req.body.fn_register;
                let last_name = req.body.ln_register;
                let email = req.body.email_register;
                let password = req.body.password_register;

                const register_data = {
                    first_name: first_name,
                    last_name: last_name,
                    email: email,
                    password: password,
                };
                try {
                    const api_response = await axios.post(`${DB_URL}/register`, register_data);
                    console.log("This is response data: ", api_response.data);
                    
                    if (api_response.data[0] === "User Created Successfully") {
                        console.log("User Created Successfully")
                        res.send(api_response.data);
                    }
                } 
                catch (error) {
                    console.error("ERROR ", error);
                    res.send("Internal Server Error");
                }
                };
                
        }
        catch (error) {
            console.error(error);
            res.status(500).send("Internal Server Error");
        }
    }
}
);

// Route to login a user
app.post("/login", async (req, res) => {
    console.log(req.body.username);
    console.log(req.body.password);
    if (!req.body) {
        return res.status(400).send("Missing data");
    } else {
        let username = req.body.username;
        let password = req.body.password;
        try {
            const login_response = await axios.post(`${DB_URL}/db/login`, { username: username, password: password });
            if (login_response.status == 200) {
                res.status(200).send(login_response.data);
            } else if (login_response.data === "Wrong Password") {
                res.status(400).send("Wrong Password");
            } else if (login_response.data === "User Not Found") {
                res.status(400).send("Username Not Found");
            } else if (login_response.data === "Internal Server Error") {
                res.status(400).send("Internal Server Error");
            } else {
                res.status(400).send("Unknown Error");
            }
        }
        catch (error) {
            console.error(error);
            res.status(400).send("Internal Server Error");
        }
    }
});

// Route to insert google user into database
app.post("/auth/google", async (req, res) => {
    try {
        const response = await axios.post(`${DB_URL}/auth/google`, req.body);
        if (response.data) {
            res.status(200).send(response.data);
        } else {
            res.status(400).send("Internal Server Error");
        }
    } catch {}
});

//#endregion

//#region PATCH
//Route to update user password
app.patch("/reset", async (req, res) => {
    console.log(req.body.password_reset);
    if (!req.body) {
        return res.status(400).send("Missing data");
    } else {
        let token = req.params.token;
        let password = req.body.password_reset;
        try {
            const response = await axios.patch(`${DB_URL}/password-reset/${token}`, { password: password });
            if (response.data === "Password Updated") {
                res.status(200).send("Password Updated");
            } else if (response.data === "Token Expired") {
                res.status(400).send("Token Expired");
            } else if (response.data === "No Token Found") {
                res.status(400).send("Internal Server Error");
            } else {
                res.status(400).send("Unknown Error");
            }
        } catch (error) {
            console.error(error);
            res.status(400).send("Internal Server Error");
        }
    }
});
//#endregion

// Start listening
app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});
