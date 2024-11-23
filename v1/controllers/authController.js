const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('../db');
const { getCurrentSecret } = require('../secretManager');

const ACCESS_TOKEN_EXPIRATION = '2h';
const REFRESH_TOKEN_EXPIRATION = '7d';

exports.login = async (req, res) => {
    const { email, password } = req.body;
    try {
        const [user] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) return res.status(401).json({ error: 'Email veya şifre hatalı!' });
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Email veya şifre hatalı!' });
        const secretKey = getCurrentSecret();
        const accessToken = jwt.sign({ id: user.id, email: user.email }, secretKey, { expiresIn: ACCESS_TOKEN_EXPIRATION });
        const refreshToken = jwt.sign({ id: user.id, email: user.email }, secretKey, { expiresIn: REFRESH_TOKEN_EXPIRATION });
        await db.query('UPDATE users SET refresh_token = ? WHERE id = ?', [refreshToken, user.id]);
        res.cookie('auth_token', accessToken, { httpOnly: true, secure: true });
        res.cookie('refresh_token', refreshToken, { httpOnly: true, secure: true });
        res.status(200).json({ message: 'Başarıyla giriş yapıldı!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
};

exports.refreshToken = async (req, res) => {
    const refreshToken = req.cookies.refresh_token;
    if (!refreshToken) return res.status(403).json({ error: 'Refresh token sağlanmadı!' });
    try {
        const [user] = await db.query('SELECT * FROM users WHERE refresh_token = ?', [refreshToken]);
        if (!user) return res.status(403).json({ error: 'Geçersiz refresh token!' });
        jwt.verify(refreshToken, getCurrentSecret(), (err, decoded) => {
            if (err) return res.status(403).json({ error: 'Geçersiz veya süresi dolmuş refresh token!' });
            const newAccessToken = jwt.sign({ id: decoded.id, email: decoded.email }, getCurrentSecret(), { expiresIn: ACCESS_TOKEN_EXPIRATION });
            res.cookie('auth_token', newAccessToken, { httpOnly: true, secure: true });
            res.status(200).json({ message: 'Yeni access token oluşturuldu!' });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
};

exports.logout = async (req, res) => {
    const userId = req.user?.id;
    try {
        if (userId) await db.query('UPDATE users SET refresh_token = NULL WHERE id = ?', [userId]);
        res.clearCookie('auth_token');
        res.clearCookie('refresh_token');
        res.status(200).json({ message: 'Başarıyla çıkış yapıldı!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
};