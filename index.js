require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const Joi = require("joi");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));

const client = new MongoClient(
  `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`
);
client.connect();
const db = client.db(process.env.MONGODB_DATABASE);
const userCollection = db.collection("users");

app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  saveUninitialized: false,
  cookie: { maxAge: 60 * 60 * 1000 }, 
  store: MongoStore.create({
    mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`
  })
}));

app.use(express.static("public"));
app.set("view engine", "ejs");

app.use((req, res, next) => {
  res.locals.currentPath = req.path || "/";
  next();
});

app.get("/", (req, res) => {
    if (req.session.authenticated) {
        res.render("index", { name: req.session.name });
    } else {
        res.render("index",{ name: null });
    }
});
 
app.get("/signup", (req, res) => {
    res.render("signup");
});
 
app.post("/signupSubmit", async (req, res) => {
    const { name, email, password } = req.body;
 
    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });
 
    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error) {
        const msg = validationResult.error.details[0].message;
        return res.render("error", { msg ,link: "signup" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user_type = 'user'; // Default user type
 
    await userCollection.insertOne({ name, email, password: hashedPassword, user_type });
 
    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
 
    res.redirect("/members");
});

app.get("/login", (req, res) => {
   res.render("login");
});
 
app.post("/loginSubmit", async (req, res) => {
    const { email, password } = req.body;
 
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });
 
    const validationResult = schema.validate({ email, password });
    if (validationResult.error) {
        return res.render("error", { msg: "Invalid email/password combination.", link: "login" });
    }
 
    const user = await userCollection.findOne({ email });
    if (!user) {
        return res.render("error", { msg: "Invalid email/password combination.", link: "login" });
    }
 
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
        return res.render("error", { msg: "Invalid email/password combination.", link: "login" });
    }
 
    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;
    req.session.user_type = user.user_type;
 
    res.redirect("/members");
});
 
app.get("/members", (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect("/");
    }

    const images = ["image1.gif", "image2.webp", "image3.gif"];
    res.render("members", { name: req.session.name, images });
});
 
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.render("logout");
});
 
app.get("/admin", async (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect("/login");
    }

    if (req.session.user_type !== "admin") {
        return res.status(403).render("error", { 
            msg: "You are not authorized to view this page.", 
            link: "/" 
        });
    }

    const users = await userCollection.find().toArray();
    res.render("users", { users });
});
app.get("/promote/:id", async (req, res) => {
    if (!req.session.authenticated || req.session.user_type !== "admin") {
        return res.status(403).render("error", {    
            msg: "You are not authorized to perform this action.",
            link: "/admin"
        });
    }

    const id = req.params.id;
    const user = await userCollection.findOne({ _id: new ObjectId(id) });
    if (!user) {
        return res.status(404).render("error", { 
            msg: "User not found.", 
            link: "/admin" 
        });
    }
    await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { user_type: "admin" } });
    res.redirect("/admin");
});

app.get("/demote/:id", async (req, res) => {
    if (!req.session.authenticated || req.session.user_type !== "admin") {
        return res.status(403).render("error", {    
            msg: "You are not authorized to perform this action.",
            link: "/admin"
        });
    }   

    const id = req.params.id;
    const user = await userCollection.findOne({ _id: new ObjectId(id) });
    if (!user) {
        return res.status(404).render("error", { 
            msg: "User not found.", 
            link: "/admin" 
        });
    }
    await userCollection.updateOne({ _id: new ObjectId(id)}, { $set: { user_type: "user" } });
    res.redirect("/admin");
});

app.use((req, res) => {
    res.status(404).render("404");
});
 

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});