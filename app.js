const express = require('express');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const passport = require('passport');
const session = require('express-session');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const Post = require('./models/Post');
const User = require('./models/User');
// const User = require(User);
// const userSchema = require('./database/userSchema');

dotenv.config();

mongoose.connect('mongodb://localhost:27017/bookstore', { useNewUrlParser: true, useUnifiedTopology: true });

const app = express();
app.use(express.json());

const MONGO_URL = process.env.MONGO_URL;
const PORT = process.env.PORT;

app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


app.post('/register', async (req, res) => {
    const { error } = userSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const { name, email, password } = req.body;

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({ name, email, password: hashedPassword });

    user.save((err, savedUser) => {
        if (err) return res.status(500).json({ message: 'Something went wrong', error: err });

        const { password, ...userWithoutPassword } = savedUser.toObject();

        res.status(200).json({
            message: 'Registered successfully',
            data: {
                ...userWithoutPassword,
                updatedAt: savedUser.updatedAt,
                createdAt: savedUser.createdAt
            }
        });
    });
});

app.post('/login', async (req, res) => {
    const { error } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: 'Bad Request', error });

    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Unauthorized' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ message: 'Unauthorized' });

    const accessToken = jwt.sign({ id: user._id }, 'secret');

    const { password: userPassword, ...userWithoutPassword } = user.toObject();

    res.status(200).json({
        message: 'Login successful',
        data: {
            accessToken,
            user: {
                ...userWithoutPassword,
                updatedAt: user.updatedAt,
                createdAt: user.createdAt
            }
        }
    });
});

app.post('/posts', async (req, res) => {
    const { error } = postSchema.validate(req.body);
    if (error) return res.status(400).json({ message: 'Bad Request', error });

    const token = req.headers.authorization.split(' ')[1];
    const { id } = jwt.verify(token, 'secret');

    const user = await User.findById(id);
    if (!user) return res.status(401).json({ message: 'Unauthorized' });

    const { title, body } = req.body;

    const post = new Post({ title, body, user: user._id });

    post.save((err, savedPost) => {
        if (err) return res.status(500).json({ message: 'Something went wrong', error: err });

        const { user: userId, ...postWithoutUserId } = savedPost.toObject();

        res.status(200).json({
            message: 'Post created',
            data: {
                ...postWithoutUserId,
                user: {
                    id: userId,
                    name: user.name,
                    email: user.email,
                    updatedAt: user.updatedAt,
                    createdAt: user.createdAt
                },
                updatedAt: savedPost.updatedAt,
                createdAt: savedPost.createdAt
            }

        });
    });
});

app.patch('/posts/:postId', async (req, res) => {
    const { error } = patchPostSchema.validate(req.body);
    if (error) return res.status(400).json({ message: 'Bad Request', error });

    const token = req.headers.authorization.split(' ')[1];
    const { id } = jwt.verify(token, 'secret');

    const post = await Post.findById(req.params.postId);
    if (!post) return res.status(404).json({ message: 'Post not found' });

    if (post.user.toString() !== id) return res.status(401).json({ message: 'Unauthorized' });

    const { title, body } = req.body;

    if (title) post.title = title;
    if (body) post.body = body;

    post.save((err, updatedPost) => {
        if (err) return res.status(500).json({ message: 'Something went wrong', error: err });

        const { user: userId, ...postWithoutUserId } = updatedPost.toObject();

        res.status(200).json({
            message: 'Post updated successfully',
            data: {
                ...postWithoutUserId,
                user: {
                    id: userId,
                    name: user.name,
                    email: user.email,
                    updatedAt: user.updatedAt,
                    createdAt: user.createdAt
                },
                updatedAt: updatedPost.updatedAt,
                createdAt: updatedPost.createdAt
            }
        });
    });
});

app.put('/post/:id', (req, res) => {
    Post.findOneAndUpdate({ _id: req.params.id, author: req.user._id }, { content: req.body.content }, err => {
        if (err) return res.status(500).send(err);
        res.status(200).send('Post updated');
    });
});

app.delete('/post/:id', (req, res) => {
    Post.findOneAndDelete({ _id: req.params.id, author: req.user._id }, err => {
        if (err) return res.status(500).send(err);
        res.status(200).send('Post deleted');
    });
});

app.get('/posts', async (req, res) => {
    const { error } = getPostsSchema.validate(req.query);
    if (error) return res.status(400).json({ message: 'Bad Request', error });

    const token = req.headers.authorization.split(' ')[1];
    jwt.verify(token, 'secret');

    const { limit = 10, page = 1, order = 'desc', orderBy = 'createdAt' } = req.query;

    const posts = await Post.find()
        .sort({ [orderBy]: order })
        .limit(limit)
        .skip((page - 1) * limit)
        .populate('user', '-password');

    res.status(200).json({
        message: 'All posts',
        data: posts.map(post => post.toObject())
    });
});

app.get('/posts/:postId', async (req, res) => {
    const token = req.headers.authorization.split(' ')[1];
    jwt.verify(token, 'secret');

    const post = await Post.findById(req.params.postId).populate('user', '-password');
    if (!post) return res.status(404).json({ message: 'Post not found' });

    res.status(200).json({
        message: 'Post',
        data: post.toObject()
    });
});

mongoose.connect(MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Connected to MongoDB');
        app.listen(PORT, () =>
            console.log(`Server started on port ${PORT}`));
    });
