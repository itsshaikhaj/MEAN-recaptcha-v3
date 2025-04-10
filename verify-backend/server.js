const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
const PORT = 3000;

// Dummy in-memory users
const users = [];

app.use(cors());
app.use(bodyParser.json());

// Secrets
const SECRET_KEY = 'your_secret_key_here';  // JWT Secret
const RECAPTCHA_SECRET = 'your reCAPTCHA Secret Key (server key)';  // <<<<< your reCAPTCHA Secret Key (server key)

// Helper function to verify reCAPTCHA
async function verifyRecaptcha(token) {
  const url = `https://www.google.com/recaptcha/api/siteverify`;
  const params = new URLSearchParams();
  params.append('secret', RECAPTCHA_SECRET);
  params.append('response', token);

  const response = await axios.post(url, params, { family: 4 });
  return response.data.success;
}

// Signup API
app.post('/api/signup', async (req, res) => {
  const { name, email, password, recaptchaToken } = req.body;

  if (!name || !email || !password || !recaptchaToken) {
    return res.status(400).json({ message: 'Please fill all fields including recaptcha' });
  }

  // Verify Recaptcha
  const isHuman = await verifyRecaptcha(recaptchaToken);
  if (!isHuman) {
    return res.status(400).json({ message: 'Recaptcha verification failed' });
  }

  // Check existing user
  const existingUser = users.find(user => user.email === email);
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }

  // Save user
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ name, email, password: hashedPassword });
  console.log('Users:', users);

  res.json({ message: 'Signup successful' });
});

// Login API
app.post('/api/login', async (req, res) => {
  const { email, password, recaptchaToken } = req.body;

  if (!email || !password || !recaptchaToken) {
    return res.status(400).json({ message: 'Please fill all fields including recaptcha' });
  }

  // Verify Recaptcha
  const isHuman = await verifyRecaptcha(recaptchaToken);
  if (!isHuman) {
    return res.status(400).json({ message: 'Recaptcha verification failed' });
  }

  const user = users.find(user => user.email === email);
  if (!user) {
    return res.status(400).json({ message: 'Invalid email or password' });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Invalid email or password' });
  }

  const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });

  res.json({ message: 'Login successful', token });
});

// Protected route
app.get('/api/home', (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) return res.status(401).json({ message: 'Unauthorized' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    res.json({ message: `Welcome ${decoded.email}` });
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
