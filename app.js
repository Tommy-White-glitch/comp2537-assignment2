require('dotenv').config();

const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo').default;
const Joi = require('joi');
const bcrypt = require('bcrypt');

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// MongoDB
mongoose.connect(`mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`)
.then(() => console.log("MongoDB connected"))
.catch(err => console.log(err));

// Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});
const User = mongoose.model("User", userSchema);

// Session
app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
    mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`,
    crypto: {
        secret: process.env.MONGODB_SESSION_SECRET
    }
    }),
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60,
        httpOnly: true
    }
}));

// Home Page
app.get('/', (req, res) => {
    if (!req.session.user) {
        res.send(`
            <button onclick="location.href='/signup'">Sign Up</button><br>
            <button onclick="location.href='/login'">Log In</button>
        `);
    } else {
        res.send(`
            <p>Hello, ${req.session.user.name}!</p>
            <button onclick="location.href='/members'">Members Area</button><br>
            <button onclick="location.href='/logout'">Logout</button>
        `);
    }
});

// Sign Up Page
app.get('/signup', (req, res) => {
    res.send(`
        <form method="POST" action="/signup">
            <input name="name" placeholder="name" required /><br>
            <input name="email" placeholder="email" required /><br>
            <input  type="password" name="password" placeholder="password" required /><br>
            <button type="submit">Sign Up</button>
        </form>
    `);
});

app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name) return res.send("Please provide a name <a href='/signup'>Try again</a>");
    if (!email) return res.send("Please provide an email <a href='/signup'>Try again</a>");
    if (!password) return res.send("Please provide a password <a href='/signup'>Try again</a>");

    const schema = Joi.object({
        name: Joi.string().alphanum().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });

    const { error } = schema.validate(req.body);
    if (error) return res.send("Invalid input <a href='/signup'>Try again</a>");

    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return res.send("Email already exists <a href='/signup'>Try again</a>");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({ name, email, password: hashedPassword });

    req.session.user = { name };
    res.redirect('/members');
});

// Log In Page
app.get('/login', (req, res) => {
    res.send(`
        <form method="POST" action="/login">
            <input name="email" placeholder="email" required /><br>
            <input type="password" name="password" placeholder="password" required /><br>
            <button type="submit">Login</button>
        </form>
    `);
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email) {
        return res.send("Please provide an email <a href='/login'>Try again</a>");
    }

    if (!password) {
        return res.send("Please provide a password <a href='/login'>Try again</a>");
    }

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });

    const { error } = schema.validate(req.body);
    if (error) {
        return res.send("Invalid input format <a href='/login'>Try again</a>");
    }

    const user = await User.findOne({ email });

    if (!user) {
        return res.send("Email not found <a href='/login'>Try again</a>");
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
        return res.send("Incorrect password <a href='/login'>Try again</a>");
    }

    // Success
    req.session.user = { name: user.name };
    res.redirect('/members');
});

// Members Page
app.get('/members', (req, res) => {
    if (!req.session.user) return res.redirect('/');

    const images = ['garfield.jpg', 'odie.jpg', 'snoopy.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <h1>Hello, ${req.session.user.name}!</h1>
        <img src="/${randomImage}" width="300"/>
        <br><button onclick="location.href='/logout'">Logout</button>

    `);
});

// Log Out
app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// 404
app.use((req, res) => {
    res.status(404).send("<p>Page not found - 404</p>");
});

// Server
app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});