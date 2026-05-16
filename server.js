const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- Database Models ---

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    hasSubscription: { type: Boolean, default: false },
    expiryDate: { type: Date, default: null }
});

const KeySchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    days: { type: Number, required: true },
    used: { type: Boolean, default: false },
    usedBy: { type: String, default: null }
});

const User = mongoose.model('User', UserSchema);
const Key = mongoose.model('Key', KeySchema);

// --- API Routes ---

// Registration
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const newUser = new User({ username, email, password });
        await newUser.save();
        res.status(201).json({ message: 'Success' });
    } catch (err) {
        res.status(400).json({ error: 'Username or Email already exists' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { loginId, password } = req.body;
    const user = await User.findOne({ 
        $or: [{ username: loginId }, { email: loginId }],
        password: password
    });
    if (user) {
        res.json(user);
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Activate Key
app.post('/api/activate-key', async (req, res) => {
    const { username, keycode } = req.body;
    const key = await Key.findOne({ code: keycode, used: false });
    
    if (!key) return res.status(404).json({ error: 'Invalid or used key' });

    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    key.used = true;
    key.usedBy = username;
    await key.save();

    user.hasSubscription = true;
    const now = user.expiryDate && user.expiryDate > new Date() ? new Date(user.expiryDate) : new Date();
    now.setDate(now.getDate() + key.days);
    user.expiryDate = now;
    await user.save();

    res.json(user);
});

// Check Subscription (API for Mod)
app.get('/api/check-sub/:username', async (req, res) => {
    const user = await User.findOne({ username: req.params.username });
    if (user && user.hasSubscription && user.expiryDate > new Date()) {
        res.json({ active: true, expiry: user.expiryDate });
    } else {
        res.json({ active: false });
    }
});

// Admin: Generate Key
app.post('/api/admin/gen-key', async (req, res) => {
    const { adminUser, days } = req.body;
    const admin = await User.findOne({ username: adminUser, role: 'admin' });
    if (!admin) return res.status(403).json({ error: 'Unauthorized' });

    const code = 'ABYSS-' + Math.random().toString(36).substr(2, 9).toUpperCase();
    const newKey = new Key({ code, days });
    await newKey.save();
    res.json(newKey);
});

// Admin: Get All Keys
app.get('/api/admin/keys/:adminUser', async (req, res) => {
    const admin = await User.findOne({ username: req.params.adminUser, role: 'admin' });
    if (!admin) return res.status(403).json({ error: 'Unauthorized' });
    const keys = await Key.find().sort({ _id: -1 });
    res.json(keys);
});

// --- Server Start ---

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/abyss';

mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.log(err));

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
