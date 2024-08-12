import express from "express";
import bodyParser from "body-parser";
import * as mysql2 from "mysql2";
import * as dotenv from "dotenv";
import bycrypt from "bcrypt";
import rndm from "rndm";
import nodemailer from "nodemailer";
import mariadb from "mariadb";


//#region Variable Declaration, Constructors, Functions

dotenv.config(); // Load the environment variables

const app = express();
const port = 5000;
const saltRounds = 10;

let dbUser = process.env.DB_HOSTDBUSER;
let dbPassword = process.env.DB_HOSTDBPASS;
const API_URL = "http://localhost:4000";

// Maria DB Pool testing environment
const pool = mariadb.createPool({
    host: 'donlonenterprise.com',
    user: dbUser,
    password: dbPassword,
    connectionLimit: 5
});

async function asyncByCompare(password, hash) {
    bycrypt.compare(password, hash, (err, result) => {
        if (err) {
            console.error(err);
            return false;
        } else {
            return result;
        }
    });
}

async function asyncDbQuery(query) {
    console.log("Made A Query");
    let conn;
    try {
        const conn = await pool.getConnection();
        const rows = await conn.query(query);
        if (rows) {
            console.log("ROWS IN QUERY ASYNC: ", rows);
            return rows;
        } else {
            return 0;
        }
    } catch (err) {
        throw err;
    } finally {
        if (conn) return conn.end();
    }
}

async function asyncCheckUser(email) {
    console.log("Checking User: ", email);
    let conn;
    try {
        const conn = await pool.getConnection();
        const query = `SELECT * FROM client_data.users WHERE email = ${email};`;
        const rows = await conn.query(query);
        if (rows.length > 0) {
            console.log("CHECK USER ROWS: ", rows);
            return rows;
        } else {
            return 0;
        }
    } catch (err) {
        throw err;
    } finally {
        if (conn) return conn.end();
    }
}

async function asyncPurgeExpiredTokens(user_id) {
    console.log("Purging Tokens: ", user_id);
    let conn;
    try {
        const conn = await pool.getConnection();
        const query = `SELECT * FROM client_data.password_reset_tokens WHERE user_id = ${user_id};`;
        const rows = await conn.query(query);
        if (rows) {
            for (let i = 0; i < rows.length; i++) {
                console.log("ROW ID: ", rows[i].id);
                if (rows[i].expires_at < new Date()) {
                    const delete_query = `DELETE FROM client_data.password_reset_tokens WHERE id = ${rows[i].id};`;
                    const delete_rows = await conn.query(delete_query);
                    if (delete_rows) {
                        console.log("ROW DELETED: ", rows[i].id);
                    } else {
                        console.log("ROW NOT DELETED: ", rows[i].id);
                }
            }
        }
        } else {
            return 0;
        }
    } catch (err) {
        throw err;
    } finally {
        if (conn) return conn.end();
    }
}

// asyncDbQuery("SHOW DATABASES;").catch(err => {
//     console.log(err);
// });

// End Maria DB testing environment

const transporter = nodemailer.createTransport({
    host: "mail.donlonenterprise.com",
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
})

transporter.verify((error, success) => {
    if (error) {
        console.error(error);
    } else {
        console.log(success);
        console.log("Email server is ready to take messages");
    }
}
);

// const pool = mysql2.createPool({
//     host: "198.12.238.129",
//     port: 3306,
//     user: dbUser,
//     password: dbPassword,
//     database: "client_data",
//     waitForConnections: true,
//     connectionLimit: 10,
//     queueLimit: 0
// });

// pool.getConnection((err, connection) => {
//     if (err) {
//         console.error(err);
//     } else {
//         console.log("\n***Connected to database***\n")
//     }
// });

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

//#endregion


//#region GET methods

// Route to check token and release
app.get("/password-reset/", async (req, res) => {
    console.log(req.query);
    console.log("made it here");
    // Check if user exists, return user id
    asyncCheckUser(JSON.stringify(req.query.email)).then((result) => {
        console.log(result);
        if (!result) {
            res.status(400).send("Email not found");
        } else {
            console.log(result[0]);
            const user = result[0];
            // If user exists, then retrieve tokens
            asyncDbQuery(`SELECT * FROM client_data.password_reset_tokens WHERE user_id = ${JSON.stringify(user.id)};`).then((result) => {
                console.log("TOKENS: ", result);
                if (!result) {
                    console.log("No token found");
                    res.status(400).send("No token found");
                } else {
                    let newdate = new Date();
                    let now = newdate.toISOString().slice(0, 19).replace('T', ' ');
                    for (let i = 0; i < result.length; i++) {
                        if (Date.parse(result[i].expires_at) > Date.parse(now)) {
                            if (!asyncByCompare(req.query.token, result[i].token)) {
                                res.status(400).send("Not Valid Token");
                            } else {
                                return res.status(200).send(["Token found", result[i].user_id]);
                            }
                        } else {
                            asyncPurgeExpiredTokens(JSON.stringify(user.id)).then((result) => {
                            if (result) {
                                console.log("Token Purged");
                            } else {
                                console.log("Tokens Empty");
                            }
                            res.status(400).send("Token Expired");
                        });
                    }
                }
            }
                }).catch((err) => {
                    console.error(err);
                    res.status(500).send("Internal Server Error at Token Purge");
                });
            }
            }).catch((err) => {
                console.error(err);
                res.status(500).send("Error in retrieving token");
        })
    });

//#endregion


//#region POST methods

// Route to post to db
app.post("/contact", async (req, res) => {
try {
    if (!req.body) {
        return res.status(400).send("No data received");
    } else {
        
        pool.getConnection((err, connection) => {
            if (err) {
                console.error(err);
            } else {
                console.log("\n***Connected to database***\n")
                const query = `INSERT INTO clients (full_name, email, message) VALUES (${JSON.stringify(req.body.name)}, ${JSON.stringify(req.body.email)}, ${JSON.stringify(req.body.message)})`;
                console.log(query);
                connection.query(query, function (err, results, fields) {
                    if (err) {
                        console.error(err);
                        res.status(500).send("Internal Server Error");
                    } else {
                        const mailOptions = {
                            from: process.env.EMAIL_USER,
                            to: req.body.email,
                            subject: req.body.name + " :: Client Message",
                            text: req.body.message
                        };
                        transporter.sendMail(mailOptions, (err, info) => {
                            if (err) {
                                console.error(err);
                                res.status(500).send("Internal Server Error");
                            } else {
                                console.log("Email sent: " + info.response);
                                res.status(200).send("Data inserted successfully");
                                console.log("Data inserted successfully");
                            }
                        });
                        
                    }
                });
            }
        });
    }

} catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
}
});

// Route to check availability of username
app.post("/register/check", async (req, res) => {
    console.log("This is req-body in API: ", req.body);
    console.log("Register Check");
    try {
        if (!req.body) {
            return res.status(400).send("No data received");
        } else {
            asyncCheckUser(JSON.stringify(req.body.username)).then((result) => {
                if (result.length > 0) {
                    console.log("Email already exists");
                    res.status(200).send("Email already exists");
                } else {
                    console.log("Email is available");
                    res.status(200).send("Email is available");
                }
            }).catch((err) => {
                console.error(err);
                res.status(500).send("Internal Server Error");
            });
        }
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});

// Route to register user to db and hash password
app.post("/register", async (req, res) => {
    try {
        if (!req.body) {
            return res.status(400).send("No data received");
        } else {
            console.log(req.body);
            let first_name = req.body.first_name;
            let last_name = req.body.last_name;
            let email = req.body.email;
            let password = req.body.password;
            bycrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.error(err);
                    res.status(500).send("Internal Server Error");
                } else {
                        const query = `INSERT INTO client_data.users (first_name, last_name, email, password) VALUES (${JSON.stringify(first_name)}, ${JSON.stringify(last_name)}, ${JSON.stringify(email)}, ${JSON.stringify(hash)})`;
                        console.log(query);
                        asyncDbQuery(query).then((result) => {
                            console.log("Data inserted successfully");
                            const user = email;
                            res.status(200).send(["User Created Successfully", user]);
                        }).catch((err) => {
                            console.error(err);
                            res.status(500).send("Internal Server Error");
                        });
                }
            });
        }
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});

// Route to register user with Google O Auth
app.post("/auth/google", async (req, res) => {
console.log(req.body);
try {
    pool.getConnection((err, connection) => {
        if (err) {
            console.log(err);
            res.status(500).send("Internal Server Error");
        } else {
            // Check if user already exists
            const email_check_query = `SELECT * FROM client_data.users WHERE email = ${JSON.stringify(req.body.email)}`;
            connection.query(email_check_query, async (err, results, fields) => {
                if (err) {
                    console.error(err);
                    res.status(500).send("Internal Server Error");
                } else {
                    if (results.length > 0) {
                        console.log("User already exists");
                        res.status(200).send(["User already exists", req.body]);
                    } else {
                        const register_data = {
                            first_name: req.body.givenName,
                            last_name: req.body.familyName,
                            email: req.body.email,
                            password: "google"
                        };
                        const register_query = `INSERT INTO client_data.users (first_name, last_name, email, password) VALUES (${JSON.stringify(req.body.givenName)}, ${JSON.stringify(req.body.familyName)}, ${JSON.stringify(req.body.email)}, ${JSON.stringify("google")})`;
                        connection.query(register_query, async (err, results, fields) => {
                            if (err) {
                                console.error(err);
                                res.status(500).send("Internal Server Error");
                            } else {
                                const user_query = `SELECT * FROM client_data.users WHERE email = ${JSON.stringify(req.body.email)}`;
                                connection.query(user_query, async (err, results, fields) => {
                                    if (err) {
                                        console.error(err);
                                        res.status(500).send("Internal Server Error");
                                    } else {
                                        res.status(200).send(["User registered", results[0]]);
                                    }
                                });
                            }
                        });
                    }
                }
            });
        }
    });
} catch (error) {

}

});
         
// Route to login user
app.post("/db/login", async (req, res) => {
    console.log(req.body);
    let email = req.body.username;
    let password = req.body.password;
    console.log("\n***Connected to database***\n");
    const query = `SELECT * FROM client_data.users WHERE email = ${JSON.stringify(email)}`;
    asyncDbQuery(query).then((result) => {
    if (result.length > 0) {
        const user = result[0];
        bycrypt.compare(password, user.password, (err, result) => {
            if (err) {
                res.status(400).send("Internal Server Error");
            } else {
                if (result) {
                    console.log("User authenticated");
                    res.status(200).send(user);
                } else {
                    res.send("Wrong Password");
                }
            }
        });
    } else {
        res.send("User not found");
    }
    }
    ).catch((err) => {
        console.error(err);
        res.status(500).send("Internal Server Error");
    });
});


// Route to request for password reset token
app.post("/reset_request", async (req, res) => {
    const now = new Date();
    const mysqlFormattedDate = now.toISOString().slice(0, 19).replace('T', ' ');
    const oneHourLater = new Date(now.getTime() + 60 * 60 * 1000);
    const oneHourFormattedDate = oneHourLater.toISOString().slice(0, 19).replace('T', ' ');

    console.log('JavaScript date:', now);
    console.log('MySQL formatted date:', mysqlFormattedDate);

    asyncCheckUser(JSON.stringify(req.body.email)).then((result) => {
        console.log(result);
            if (result.length > 0) {
                console.log("Email exists");
            } else {
                console.log("Email does not exist");
            }
        if (!result) {
            res.status(400).send("Email not found");
        } else {
            console.log(result[0]);
            const user = result[0];
            var token = rndm(16);
            console.log("Token: ", token);
            bycrypt.hash(token, saltRounds, (err, hash) => {
                if (err) {
                    console.error(err);
                    res.status(500).send("Internal Server Error");
                } else {
                    const update_query = `INSERT INTO client_data.password_reset_tokens ( user_id, token, created_at, expires_at ) VALUES (${JSON.stringify(user.id)}, ${JSON.stringify(hash)}, ${JSON.stringify(mysqlFormattedDate)}, ${JSON.stringify(oneHourFormattedDate)});`;
                    asyncDbQuery(update_query).then((result) => {
                        if (result) {
                            console.log("TRUE");
                        } else {
                            console.log("FALSE");
                        }
                        if (result) {
                            let linkString = "http://localhost:3000/password-reset/" + `${token}` + `?email=${req.body.email}`;
                            const mailOptions = {
                            from: process.env.EMAIL_USER,
                            to: req.body.email,
                            subject: "Password Reset Request",
                            html: `<p>Click the link below to reset your password</p><a href=${linkString}>Reset Password</a>`
                            };
                        transporter.sendMail(mailOptions, (err, info) => {
                            if (err) {
                                console.error(err);
                                res.status(500).send("Internal Server Error");
                            } else {
                                console.log("Email sent: " + info.response);
                                console.log("Data inserted successfully");
                                res.status(200).send("Email sent");
                            }
                        });
                        } else {
                            res.status(500).send("Internal Server Error");
                        }
                        
                    }).catch((err) => {
                        console.error(err);
                        res.status(500).send("Internal Server Error");
                    });
                }
            });
        }
    }
    ).catch((err) => {
        console.error(err);
        res.status(500).send("Internal Server Error");
    });
});
//#endregion

// Start listening
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
}
);