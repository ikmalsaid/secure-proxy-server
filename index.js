const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'my_very_secure_secret_key'; // In production, store in env variable

app.use(express.json());

const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));

// ---- Middleware: Logger ----
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ---- Middleware: Rate Limit (per IP) ----
const proxyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: 'Too many requests, try again later.',
});
app.use('/proxy', proxyLimiter);

// ---- Helper: Auth Middleware ----
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// ---- Route: Login (fake credentials) ----
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;

  // Fake validation: accept anything
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }

  // In real world: check against DB, hash password, etc.
  const token = jwt.sign({ userId: username }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// ---- Route: POST /proxy (protected + validated + forwarded) ----
app.post('/proxy', authenticate, async (req, res) => {
  // Validate input
  const schema = Joi.object({
    title: Joi.string().min(1).max(100).required(),
    body: Joi.string().required(),
    userId: Joi.number().integer().required(),
  });

  const { error, value } = schema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  try {
    // Forward to a real/fake API
    const response = await axios.post('https://jsonplaceholder.typicode.com/posts', value);
    res.status(response.status).json(response.data);
  } catch (err) {
    console.error('Proxy error:', err.message);
    res.status(502).json({ error: 'Failed to forward request' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
