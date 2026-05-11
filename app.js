require('dotenv').config();

const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo').default;
const Joi = require('joi');
const bcrypt = require('bcrypt');

const app = express();

app.set('view engine', 'ejs');

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
    password: String,
    user_type: {
        type: String,
        default: "user"
    }
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

function isValidSession(req) {
    return req.session.user;
}

function sessionValidation(req, res, next) {

    if (isValidSession(req)) {
        next();
    } else {
        res.redirect('/login');
    }
}

function adminAuthorization(req, res, next) {

    if (req.session.user.user_type === "admin") {
        next();
    } else {

        res.status(403);

        res.render("error", {
            message: "You are not authorized."
        });
    }
}

// Home Page
app.get('/', (req, res) => {

    res.render("index", {
        user: req.session.user
    });
});

// Sign Up Page
app.get('/signup', (req, res) => {
    res.render("signup");
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

    await User.create({
        name,
        email,
        password: hashedPassword,
        user_type: "user"
    });

    req.session.user = {
        name,
        email,
        user_type: "user"
    };
    
    res.redirect('/members');
});

// Log In Page
app.get('/login', (req, res) => {
    res.render("login");
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
    req.session.user = {
        name: user.name,
        email: user.email,
        user_type: user.user_type
    };
    res.redirect('/members');
});

// Members Page
app.get('/members', sessionValidation, (req, res) => {

    const images = ['/garfield.jpg',
                    '/odie.jpg', 
                    '/snoopy.jpg'
                   ];

    res.render('members', {
        user: req.session.user,
        images
    });
});

app.get('/admin',
    sessionValidation,
    adminAuthorization,
    async (req, res) => {

        const users = await User.find({});

        res.render('admin', {
            users
        });
});

app.get('/promote/:email',
    sessionValidation,
    adminAuthorization,
    async (req, res) => {

        await User.updateOne(
            { email: req.params.email },
            { $set: { user_type: 'admin' } }
        );

        res.redirect('/admin');
});

app.get('/demote/:email',
    sessionValidation,
    adminAuthorization,
    async (req, res) => {

        await User.updateOne(
            { email: req.params.email },
            { $set: { user_type: 'user' } }
        );

        res.redirect('/admin');
});

// Log Out
app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// 404
app.use((req, res) => {

    res.status(404);

    res.render('404');
});

// Server
const port = process.env.PORT || 3000;

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});