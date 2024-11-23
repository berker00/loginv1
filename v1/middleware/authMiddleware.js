const jwt = require('jsonwebtoken');
const { getCurrentSecret } = require('../secretManager');

exports.verifyToken = (req, res, next) => {
    const token = req.cookies.auth_token;
    if (!token) return res.status(401).json({ error: 'Token eksik!' });
    jwt.verify(token, getCurrentSecret(), (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Geçersiz token!' });
        req.user = decoded;
        next();
    });
};