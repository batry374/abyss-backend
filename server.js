const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const app = express();

// Security-заголовки
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
// Разрешаем запросы только с твоего фронтенда
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());

// --- Rate Limiting ---

// Лимит на логин: 5 попыток за 15 минут с одного IP
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Слишком много попыток входа. Попробуйте через 15 минут.' }
});

// Лимит на регистрацию: 3 попытки за 30 минут с одного IP
const registerLimiter = rateLimit({
    windowMs: 30 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Слишком много попыток регистрации. Попробуйте позже.' }
});

// Общий лимит API: 60 запросов в минуту с одного IP
const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Слишком много запросов. Попробуйте позже.' }
});

// Применяем общий лимит ко всем /api маршрутам
app.use('/api', apiLimiter);

// --- Database Models ---

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    hasSubscription: { type: Boolean, default: false },
    expiryDate: { type: Date, default: null },
    hwid: { type: String, default: null }
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
app.post('/api/register', registerLimiter, async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).json({ error: 'Missing fields' });
        
        const newUser = new User({ username, email, password });
        await newUser.save();
        res.status(201).json({ message: 'Success' });
    } catch (err) {
        console.error('Reg error:', err);
        res.status(400).json({ error: 'Username or Email already exists' });
    }
});

// Login
app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { loginId, password, hwid } = req.body;
        
        // Валидация входных данных
        if (!loginId || !password) {
            return res.status(400).json({ error: 'Заполните все поля' });
        }
        
        console.log('Login attempt:', loginId, 'with HWID:', hwid);
        
        const user = await User.findOne({ 
            $or: [{ username: loginId }, { email: loginId }],
            password: password
        });
        
        if (user) {
            if (hwid) {
                if (!user.hwid) {
                    user.hwid = hwid;
                    await user.save();
                } else if (user.hwid !== hwid) {
                    console.log('HWID Mismatch for user:', user.username);
                    return res.status(401).json({ error: 'HWID не совпадает с привязанным к этому аккаунту!' });
                }
            }
            console.log('Login success:', user.username);
            
            // Удаляем пароль из ответа для безопасности
            const userResponse = user.toObject();
            delete userResponse.password;
            
            res.json(userResponse);
        } else {
            res.status(401).json({ error: 'Неверные данные для входа' });
        }
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// Activate Key
app.post('/api/activate-key', async (req, res) => {
    try {
        const { username, keycode } = req.body;
        
        // Валидация входных данных
        if (!username || !keycode) {
            return res.status(400).json({ error: 'Заполните все поля' });
        }
        
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

        // Удаляем пароль из ответа
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.json(userResponse);
    } catch (err) {
        console.error('Key error:', err);
        res.status(500).json({ error: 'Activation failed' });
    }
});

// Check Subscription (API for Mod)
app.get('/api/check-sub/:username', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (user && user.hasSubscription && user.expiryDate > new Date()) {
            res.json({ active: true, expiry: user.expiryDate });
        } else {
            res.json({ active: false });
        }
    } catch (err) {
        res.json({ active: false, error: 'Check failed' });
    }
});

// Admin: Generate Key
app.post('/api/admin/gen-key', async (req, res) => {
    try {
        const { adminUser, adminPassword, days } = req.body;
        
        if (typeof adminUser !== 'string' || !adminUser || !adminPassword) {
            return res.status(400).json({ error: 'Invalid request' });
        }
        
        // Проверяем что пользователь существует, имеет роль admin И пароль совпадает
        const admin = await User.findOne({ username: adminUser, role: 'admin' });
        if (!admin) return res.status(403).json({ error: 'Unauthorized' });
        
        // Проверяем пароль
        if (admin.password !== adminPassword) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const code = 'ABYSS-' + Math.random().toString(36).substr(2, 9).toUpperCase();
        const newKey = new Key({ code, days: parseInt(days) });
        await newKey.save();
        res.json(newKey);
    } catch (err) {
        res.status(500).json({ error: 'Generation failed' });
    }
});

// Admin: Get All Keys
app.get('/api/admin/keys/:adminUser', async (req, res) => {
    try {
        const adminUser = req.params.adminUser;
        const adminPassword = req.headers['x-admin-password'];
        
        if (typeof adminUser !== 'string' || !adminUser || !adminPassword) {
            return res.status(400).json({ error: 'Invalid request' });
        }
        
        const admin = await User.findOne({ username: adminUser, role: 'admin' });
        if (!admin) return res.status(403).json({ error: 'Unauthorized' });
        
        // Проверяем пароль через заголовок
        if (admin.password !== adminPassword) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        const keys = await Key.find().sort({ _id: -1 });
        res.json(keys);
    } catch (err) {
        res.status(500).json({ error: 'Fetch failed' });
    }
});

// Secure Client Download
app.get('/api/download/:username/:password', async (req, res) => {
    try {
        const { username, password } = req.params;
        
        // Валидация входных данных
        if (!username || !password) {
            return res.status(400).send('Неверные параметры запроса');
        }
        
        const user = await User.findOne({ username, password });
        
        // Проверка подписки перед скачиванием
        if (!user) {
            return res.status(403).send('Неверные данные для входа');
        }
        
        if (!user.hasSubscription) {
            return res.status(403).send('У вас нет активной подписки для скачивания клиента.');
        }
        
        if (!user.expiryDate || user.expiryDate <= new Date()) {
            return res.status(403).send('Ваша подписка истекла. Активируйте новый ключ.');
        }
        
        const filePath = path.join(__dirname, 'AbyssClient.jar');
        if (fs.existsSync(filePath)) {
            res.download(filePath);
        } else {
            res.status(404).send('Файл клиента пока не загружен на сервер.');
        }
    } catch (err) {
        console.error('Download error:', err);
        res.status(500).send('Ошибка сервера при скачивании');
    }
});

// --- Server Start ---

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Connection Error:', err));

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
