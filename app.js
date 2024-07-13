const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const util = require('util');
const axios = require('axios');

const app = express();

// 数据库配置
const DB_PATH = 'database.db';
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the database.');
});

// 创建表
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        uuid TEXT,
        user_level INTEGER DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        uuid TEXT UNIQUE,
        type TEXT CHECK(type IN ('oaifree', 'fuclaude')),
        level TEXT CHECK(level IN ('normal', 'vip')),
        key TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS invite_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE,
        usage_count INTEGER DEFAULT -1,
        level TEXT CHECK(level IN ('normal', 'vip'))
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS proxy_addresses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT UNIQUE CHECK(type IN ('oaifree', 'fuclaude')),
        address TEXT
    )`);
});

// 将数据库查询转换为 Promise
const dbGet = util.promisify(db.get.bind(db));
const dbRun = util.promisify(db.run.bind(db));
const dbAll = util.promisify(db.all.bind(db));

// 中间件设置
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'your-session-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// 密码哈希函数
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    try {
      const hash = crypto.createHash('sha256');
      hash.update(password);
      resolve(hash.digest('hex'));
    } catch (error) {
      reject(error);
    }
  });
}

// 生成随机会话 ID
const generateSessionId = () => {
    const randomBytes = crypto.randomBytes(20).toString('base64');
    return randomBytes.replace(/[+/=]/g, match => ({ '+': '-', '/': '_', '=': '' }[match]));
};

// 设置登录会话
const setLoginSession = (req, userId, userLevel, providerId, loginUrl) => {
    const sessionId = generateSessionId();
    req.session.claude_session = sessionId;
    req.session.userId = userId;
    req.session.userLevel = userLevel;
    req.session.providerId = providerId;
    req.session.loginUrl = loginUrl;
};

// 检查登录状态
const isLoggedIn = (req) => {
    return req.session.claude_session !== undefined && req.session.claude_session !== '' && req.session.userId !== undefined;
};

// 检查是否为管理员
const isAdmin = (req) => {
    return req.session.userLevel >= 4;
};

// 清除登录会话
const clearLoginSession = (req) => {
    req.session.destroy();
};

// 检查是否是首次访问
const checkFirstVisit = async () => {
    const result = await dbGet('SELECT COUNT(*) as count FROM users');
    return result.count === 0;
};

// 生成8位邀请码
function generateInviteCode() {
    return Math.random().toString(36).substring(2, 10).toUpperCase();
}

// 处理注册请求
const handleRegister = async (req, res) => {
    const { username, password, invite_code } = req.body;
    const isFirstVisit = await checkFirstVisit();

    try {
        // 检查用户名是否已存在
        const existingUser = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
        if (existingUser) {
            return res.status(400).render('register', { 
                errorMessage: "Username already exists. Please choose a different username.", 
                isFirstVisit 
            });
        }

        let userLevel = 1; // 默认用户级别
        let inviteCodeInfo;

        if (!isFirstVisit) {
            inviteCodeInfo = await dbGet('SELECT * FROM invite_codes WHERE code = ?', [invite_code]);
            if (!inviteCodeInfo || inviteCodeInfo.usage_count === 0) {
                return res.status(400).render('register', { 
                    errorMessage: "Invalid invite code", 
                    isFirstVisit: false 
                });
            }
            userLevel = inviteCodeInfo.level === 'vip' ? 2 : 1;
        } else {
            userLevel = 4; // 首次访问，设置为管理员
        }

        const hashedPassword = await hashPassword(password);
        const uuid = uuidv4();

        await dbRun(`INSERT INTO users (username, password, uuid, user_level) VALUES (?, ?, ?, ?)`,
            [username, hashedPassword, uuid, userLevel]);

        if (!isFirstVisit && inviteCodeInfo && inviteCodeInfo.usage_count > 0) {
            await dbRun('UPDATE invite_codes SET usage_count = usage_count - 1 WHERE code = ?', [invite_code]);
        }

        res.redirect('/login');
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).render('register', { 
            errorMessage: "An error occurred during registration. Please try again.", 
            isFirstVisit 
        });
    }
};

// 获取代理地址
const getProxyAddress = async (type) => {
    try {
        const proxyAddress = await dbGet('SELECT address FROM proxy_addresses WHERE type = ?', [type]);
        return proxyAddress ? proxyAddress.address : null;
    } catch (error) {
        console.error('Error fetching proxy address:', error);
        return null;
    }
};

// 处理登录请求
const handleLogin = async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await dbGet(`SELECT * FROM users WHERE username = ?`, [username]);
        
        if (!user) {
            return res.status(400).json({ success: false, errorMessage: "User not found" });
        }

        const hashedPassword = await hashPassword(password);
        if (hashedPassword !== user.password) {
            return res.status(400).json({ success: false, errorMessage: "Invalid password" });
        }

        setLoginSession(req, user.id, user.user_level);
        return res.json({ success: true, message: "Login successful" });

    } catch (error) {
        console.error("Database error:", error);
        return res.status(500).json({ success: false, errorMessage: "Database error" });
    }
};

// 处理provider选择请求
const handleProviderSelection = async (req, res) => {
    const { providerId } = req.body;

    if (!isLoggedIn(req)) {
        return res.status(401).json({ success: false, errorMessage: "Not logged in" });
    }

    try {
        const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [req.session.userId]);
        const provider = await dbGet('SELECT * FROM channels WHERE id = ?', [providerId]);
        
        if (!provider) {
            return res.status(400).json({ success: false, errorMessage: "Invalid provider selected" });
        }
        if (provider.level === 'vip' && user.user_level < 2) {
            return res.status(403).json({ success: false, errorMessage: "You do not have access to this provider" });
        }

        if (provider.type === 'fuclaude') {
            const proxyAddress = await getProxyAddress('fuclaude');
            if (!proxyAddress) {
                return res.status(500).json({ success: false, errorMessage: "Proxy address not found" });
            }

            const requestBody = {
                session_key: provider.key,
            };

            if (user.user_level < 3) {
                requestBody.unique_name = user.uuid;
            }

            try {
                const response = await axios.post(`${proxyAddress}/manage-api/auth/oauth_token`, requestBody, {
                    headers: { 'Content-Type': 'application/json' }
                });

                const { login_url } = response.data;
                req.session.providerId = providerId;
                req.session.loginUrl = `${proxyAddress}${login_url}`;
                return res.json({ success: true, message: "Provider selected", redirectUrl: req.session.loginUrl });
            } catch (error) {
                console.error('Error fetching login URL:', error);
                return res.status(500).json({ success: false, errorMessage: "Error fetching login URL" });
            }
        } else if (provider.type === 'oaifree') {
            // TODO: Implement oaifree login logic
            return res.status(501).json({ success: false, errorMessage: "oaifree login not implemented yet" });
        } else {
            return res.status(400).json({ success: false, errorMessage: "Invalid provider type" });
        }

    } catch (error) {
        console.error("Database error:", error);
        return res.status(500).json({ success: false, errorMessage: "Database error" });
    }
};

// 路由
app.get('/', async (req, res) => {
    if (!isLoggedIn(req)) {
        return res.redirect('/login');
    }
    
    try {
        const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [req.session.userId]);
        let providers;
        if (user.user_level >= 2) {
            providers = await dbAll('SELECT id, name, type, level FROM channels');
        } else {
            providers = await dbAll('SELECT id, name, type, level FROM channels WHERE level = "normal"');
        }
        res.render('provider_selection', { providers });
    } catch (error) {
        console.error("Database error:", error);
        res.status(500).send('Error loading providers');
    }
});

app.post('/', handleProviderSelection);

app.get('/login', async (req, res) => {
    if (isLoggedIn(req)) {
        return res.redirect('/');
    }
    const isFirstVisit = await checkFirstVisit();
    if (isFirstVisit) {
        return res.redirect('/register');
    }
    res.render('login', { errorMessage: null });
});

app.post('/login', handleLogin);

app.get('/register', async (req, res) => {
    const isFirstVisit = await checkFirstVisit();
    res.render('register', { errorMessage: null, isFirstVisit });
});

app.post('/register', handleRegister);

app.get('/logout', (req, res) => {
    clearLoginSession(req);
    res.redirect('/login');
});

app.get('/admin', async (req, res) => {
    if (!isLoggedIn(req) || !isAdmin(req)) {
        return res.redirect('/login');
    }
    try {
        const users = await dbAll('SELECT * FROM users');
        const channels = await dbAll('SELECT * FROM channels');
        const inviteCodes = await dbAll('SELECT * FROM invite_codes');
        const proxyAddresses = await dbAll('SELECT * FROM proxy_addresses');
        res.render('admin', { users, channels, inviteCodes, proxyAddresses });
    } catch (error) {
        console.error('Error fetching admin data:', error);
        res.status(500).send('Error loading admin page');
    }
});

// 捕获所有其他路由并重定向到根路由
app.get('*', (req, res) => {
    res.redirect('/');
});

// 管理员功能路由
app.post('/admin/user/update', async (req, res) => {
    if (!isLoggedIn(req) || !isAdmin(req)) {
        return res.status(403).send('Unauthorized');
    }
    const { userId, userLevel } = req.body;
    try {
        const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
        if (user.user_level === 4) {
            return res.status(400).send('Cannot modify initial user level');
        }
        await dbRun('UPDATE users SET user_level = ? WHERE id = ?', [userLevel, userId]);
        res.redirect('/admin');
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).send('Error updating user');
    }
});

app.post('/admin/user/delete', async (req, res) => {
    if (!isLoggedIn(req) || !isAdmin(req)) {
        return res.status(403).send('Unauthorized');
    }
    const { userId } = req.body;
    try {
        const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
        if (user.user_level === 4) {
            return res.status(400).send('Cannot delete initial user');
        }
        await dbRun('DELETE FROM users WHERE id = ?', [userId]);
        res.redirect('/admin');
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).send('Error deleting user');
    }
});

app.post('/admin/provider/add', async (req, res) => {
    if (!isLoggedIn(req) || !isAdmin(req)) {
        return res.status(403).send('Unauthorized');
    }
    const { name, type, level, key } = req.body;
    const uuid = uuidv4();
    try {
        await dbRun('INSERT INTO channels (name, uuid, type, level, key) VALUES (?, ?, ?, ?, ?)',
            [name, uuid, type, level, key]);
        res.redirect('/admin');
    } catch (error) {
        console.error('Error adding provider:', error);
        res.status(500).send('Error adding provider');
    }
});

app.post('/admin/provider/update', async (req, res) => {
    if (!isLoggedIn(req) || !isAdmin(req)) {
        return res.status(403).send('Unauthorized');
    }
    const { providerId, name, type, level, key } = req.body;
    try {
        await dbRun('UPDATE channels SET name = ?, type = ?, level = ?, key = ? WHERE id = ?',
            [name, type, level, key, providerId]);
        res.redirect('/admin');
    } catch (error) {
        console.error('Error updating provider:', error);
        res.status(500).send('Error updating provider');
    }
});

app.post('/admin/provider/delete', async (req, res) => {
    if (!isLoggedIn(req) || !isAdmin(req)) {
        return res.status(403).send('Unauthorized');
    }
    const { providerId } = req.body;
    try {
        await dbRun('DELETE FROM channels WHERE id = ?', [providerId]);
        res.redirect('/admin');
    } catch (error) {
        console.error('Error deleting provider:', error);
        res.status(500).send('Error deleting provider');
    }
});

app.post('/admin/invite/generate', async (req, res) => {
    if (!isLoggedIn(req) || !isAdmin(req)) {
        return res.status(403).send('Unauthorized');
    }
    const { usageCount, level } = req.body;
    const code = generateInviteCode();
    try {
        await dbRun('INSERT INTO invite_codes (code, usage_count, level) VALUES (?, ?, ?)',
            [code, usageCount, level]);
        res.redirect('/admin');
    } catch (error) {
        console.error('Error generating invite code:', error);
        res.status(500).send('Error generating invite code');
    }
});

app.post('/admin/invite/delete', async (req, res) => {
    if (!isLoggedIn(req) || !isAdmin(req)) {
        return res.status(403).send('Unauthorized');
    }
    const { codeId } = req.body;
    try {
        await dbRun('DELETE FROM invite_codes WHERE id = ?', [codeId]);
        res.redirect('/admin');
    } catch (error) {
        console.error('Error deleting invite code:', error);
        res.status(500).send('Error deleting invite code');
    }
});

app.post('/admin/proxy/update', async (req, res) => {
    if (!isLoggedIn(req) || !isAdmin(req)) {
        return res.status(403).send('Unauthorized');
    }
    const { type, address } = req.body;
    try {
        await dbRun('INSERT OR REPLACE INTO proxy_addresses (type, address) VALUES (?, ?)',
            [type, address]);
        res.redirect('/admin');
    } catch (error) {
        console.error('Error updating proxy address:', error);
        res.status(500).send('Error updating proxy address');
    }
});


// 错误处理中间件
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// 启动服务器
const PORT = process.argv[2] || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});