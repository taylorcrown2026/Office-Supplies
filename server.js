const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const path = require("path");

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MUST use secure session store for SOC 2 (Redis, Memcached, etc.)
app.use(session({
    secret: "CHANGE_ME_TO_ENV_SECRET",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false, 
        maxAge: 1000 * 60 * 60 
    }
}));

// Serve HTML files
app.use(express.static(__dirname));

// Login endpoint
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    // TODO: Replace with SOC 2 compliant authentication
    if (username === "admin" && password === "admin123") {
        req.session.user = { username, role: "admin" };
        return res.redirect("admin.html");
    }

    // Normal user
    req.session.user = { username, role: "user" };
    res.redirect("user.html");
});

// Mock data (replace with DB)
let requests = [];

// Submit request
app.post("/request", (req, res) => {
    requests.push({
        id: Date.now().toString(),
        user: req.session.user.username,
        department: req.body.department,
        item: req.body.item,
        date: req.body.date
    });

    res.sendStatus(200);
});

// Admin fetch requests
app.get("/requests", (req, res) => {
    res.json(requests);
});

// Admin complete request
app.put("/requests/:id", (req, res) => {
    requests = requests.filter(r => r.id !== req.params.id);
    res.sendStatus(200);
});

// Create user
app.post("/createUser", (req, res) => {
    // TODO: Add hashing, RBAC, audit logs for SOC 2
    console.log("New user created: ", req.body);
    res.sendStatus(200);
});

app.listen(3000, () => console.log("Server running on port 3000"));