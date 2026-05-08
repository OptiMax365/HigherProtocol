// server.js - QuoteCards Pro Production Backend
const express = require('express');
const Stripe = require('stripe');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

require('dotenv').config();

// ===== ENVIRONMENT VALIDATION =====
const requiredEnvVars = [
  'STRIPE_SECRET_KEY',
  'STRIPE_PUBLISHABLE_KEY',
  'STRIPE_WEBHOOK_SECRET',
  'STRIPE_PAYMENT_LINK_MONTHLY',
  'STRIPE_PAYMENT_LINK_YEARLY',
  'JWT_SECRET',
  'ADMIN_EMAIL',
  'DATABASE_URL',
  'CORS_ORIGIN'
];

const missingVars = requiredEnvVars.filter(key => !process.env[key]);
if (missingVars.length > 0) {
  console.error('❌ Missing env vars:', missingVars.join(', '));
  process.exit(1);
}

// ===== APP INITIALIZATION =====
const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;
const CORS_ORIGIN = process.env.CORS_ORIGIN;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// PostgreSQL pool configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Email transporter setup
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ===== DATABASE INITIALIZATION =====
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        email VARCHAR(255) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        is_pro BOOLEAN DEFAULT FALSE,
        plan VARCHAR(50),
        stripe_customer_id VARCHAR(255),
        stripe_subscription_id VARCHAR(255),
        paid_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        last_active TIMESTAMP DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) REFERENCES users(email),
        amount INTEGER NOT NULL,
        plan VARCHAR(50) NOT NULL,
        status VARCHAR(50) NOT NULL,
        session_id VARCHAR(255) UNIQUE,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS downloads (
        id SERIAL PRIMARY KEY,
        user_email VARCHAR(255) REFERENCES users(email),
        image_url TEXT NOT NULL,
        quote TEXT,
        author TEXT,
        settings JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        token VARCHAR(255) UNIQUE NOT NULL,
        requested_at TIMESTAMP DEFAULT NOW(),
        used BOOLEAN DEFAULT FALSE,
        ip_address VARCHAR(45)
      );
      
      CREATE TABLE IF NOT EXISTS user_activity (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) REFERENCES users(email),
        page VARCHAR(255),
        user_agent TEXT,
        timestamp TIMESTAMP DEFAULT NOW(),
        ip_address VARCHAR(45)
      );
      
      CREATE INDEX IF NOT EXISTS idx_payments_email ON payments(email);
      CREATE INDEX IF NOT EXISTS idx_users_is_pro ON users(is_pro);
      CREATE INDEX IF NOT EXISTS idx_activity_email ON user_activity(email);
      CREATE INDEX IF NOT EXISTS idx_resets_email ON password_resets(email);
    `);
    
    console.log('✅ Database initialized');
    
    // Create admin user if not exists
    const adminCheck = await pool.query('SELECT email FROM users WHERE email = $1', [ADMIN_EMAIL]);
    if (adminCheck.rows.length === 0) {
      const adminHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
      await pool.query(
        `INSERT INTO users (email, name, password_hash, is_pro) VALUES ($1, $2, $3, $4)`,
        [ADMIN_EMAIL, 'Admin', adminHash, true]
      );
      console.log(`✅ Admin user created: ${ADMIN_EMAIL}`);
    } else {
      console.log(`✅ Admin user already exists: ${ADMIN_EMAIL}`);
    }
    
  } catch (err) {
    console.error('❌ DB init failed:', err);
    process.exit(1);
  }
}

// ===== MIDDLEWARE =====
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://js.stripe.com'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://api.stripe.com', CORS_ORIGIN],
      frameSrc: ["'self'", 'https://buy.stripe.com']
    }
  }
}));

app.use(cors({
  origin: CORS_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));

app.use(morgan('short'));
app.use(express.json({ limit: '10mb' }));

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' }
});

// Authentication middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Admin middleware
const adminMiddleware = (req, res, next) => {
  if (req.user.email !== ADMIN_EMAIL) {
    console.warn(`⚠️ Admin access denied: ${req.user.email}`);
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Helper: Get client IP
const getIP = (req) => req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

// ===== PUBLIC ENDPOINTS =====
app.get('/api/config', (req, res) => {
  res.json({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY });
});

app.get('/health', (req, res) =>
  res.json({ status: 'ok', timestamp: new Date().toISOString() })
);

// ===== AUTH ENDPOINTS =====

// SIGNUP - Fixed with proper error handling
app.post('/api/signup', authLimiter, async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    if (!email?.includes('@') || !password || password.length < 6 || !name) {
      return res.status(400).json({ error: 'Valid name, email, and 6+ char password required' });
    }
    
    const existing = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (email, name, password_hash) 
       VALUES ($1, $2, $3) 
       RETURNING email, name, is_pro as "isPro", plan, created_at`,
      [email, name, passwordHash]
    );
    
    const user = result.rows[0];
    const token = jwt.sign({ email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    
    console.log(`✅ New user: ${email}`);
    res.status(201).json({ token, user });
    
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Signup failed: ' + (err.message || 'Server error') });
  }
});

// LOGIN
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email?.includes('@') || !password) {
      return res.status(400).json({ error: 'Valid email and password required' });
    }
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    
    if (!valid) {
      console.warn(`Failed login: ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    await pool.query('UPDATE users SET last_active = NOW() WHERE email = $1', [email]);
    
    const token = jwt.sign({ email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      token,
      user: {
        email: user.email,
        name: user.name,
        isPro: user.is_pro,
        plan: user.plan
      }
    });
    
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// GET CURRENT USER
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT email, name, is_pro as "isPro", plan FROM users WHERE email = $1',
      [req.user.email]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(result.rows[0]);
    
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// ===== PASSWORD RESET =====
app.post('/api/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email?.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    
    const token = crypto.randomBytes(32).toString('hex');
    const ip = getIP(req);
    
    await pool.query(
      `INSERT INTO password_resets (email, token, ip_address) VALUES ($1, $2, $3)`,
      [email, token, ip]
    );
    
    if (process.env.SMTP_USER) {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: ADMIN_EMAIL,
        subject: '🔐 Password Reset Request - QuoteCards Pro',
        html: `
          <h3>Password Reset Request</h3>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>IP:</strong> ${ip}</p>
          <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
          <p>Log into admin dashboard to send recovery email.</p>
        `
      });
    }
    
    console.log(`🔐 Reset requested: ${email} from ${ip}`);
    res.json({ success: true, message: 'Reset request recorded. Admin notified.' });
    
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// ADMIN: Send Recovery Email
app.post('/api/admin/send-recovery', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { email, adminEmail } = req.body;
    
    if (!email?.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    
    const user = await pool.query('SELECT name FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetLink = `${CORS_ORIGIN}/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`;
    
    await pool.query(
      `INSERT INTO password_resets (email, token, used) VALUES ($1, $2, true)`,
      [email, resetToken]
    );
    
    if (process.env.SMTP_USER) {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: '🔐 Reset Your QuoteCards Pro Password',
        html: `
          <h3>Reset Your Password</h3>
          <p>Hi ${user.rows[0].name},</p>
          <p>Click the link below to reset your password:</p>
          <p><a href="${resetLink}" style="background:#6e3bfa;color:#fff;padding:10px 20px;text-decoration:none;border-radius:6px">Reset Password</a></p>
          <p>This link expires in 1 hour.</p>
          <p>Requested by admin: ${adminEmail}</p>
        `
      });
    }
    
    await pool.query(
      'UPDATE password_resets SET used = true WHERE email = $1 ORDER BY requested_at DESC LIMIT 1',
      [email]
    );
    
    console.log(`✅ Recovery email sent to ${email}`);
    res.json({ success: true, message: 'Recovery email sent' });
    
  } catch (err) {
    console.error('Send recovery error:', err);
    res.status(500).json({ error: 'Failed to send recovery email' });
  }
});

// ===== ACTIVITY TRACKING =====
app.post('/api/activity', authMiddleware, async (req, res) => {
  try {
    const { page, userAgent, timestamp } = req.body;
    
    await pool.query(
      `INSERT INTO user_activity (email, page, user_agent, timestamp, ip_address)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.email, page, userAgent, timestamp || new Date().toISOString(), getIP(req)]
    );
    
    await pool.query('UPDATE users SET last_active = NOW() WHERE email = $1', [req.user.email]);
    res.json({ success: true });
    
  } catch (err) {
    console.error('Activity tracking error:', err);
    res.status(500).json({ error: 'Failed to track activity' });
  }
});

// ===== DOWNLOADS =====
app.post('/api/downloads', authMiddleware, async (req, res) => {
  try {
    const { imageUrl, quote, author, settings } = req.body;
    
    if (!imageUrl) {
      return res.status(400).json({ error: 'Image URL required' });
    }
    
    await pool.query(
      `INSERT INTO downloads (user_email, image_url, quote, author, settings)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.email, imageUrl, quote, author, settings || {}]
    );
    
    res.json({ success: true });
    
  } catch (err) {
    console.error('Save download error:', err);
    res.status(500).json({ error: 'Failed to save download' });
  }
});

app.get('/api/downloads', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, image_url as "imageUrl", quote, author, settings, created_at
       FROM downloads WHERE user_email = $1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.email]
    );
    
    res.json({ downloads: result.rows });
    
  } catch (err) {
    console.error('Fetch downloads error:', err);
    res.status(500).json({ error: 'Failed to fetch downloads' });
  }
});

// ===== PAYMENTS =====
app.post('/api/verify-payment', authMiddleware, async (req, res) => {
  try {
    const { sessionId } = req.body;
    
    if (!sessionId) {
      return res.status(400).json({ error: 'Session ID required' });
    }
    
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    
    if (session.client_reference_id !== req.user.email) {
      return res.status(400).json({ error: 'Session mismatch' });
    }
    
    if (session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment not completed' });
    }
    
    const plan = session.metadata?.plan || 'monthly';
    
    await pool.query(
      `UPDATE users SET is_pro = TRUE, plan = $1, stripe_subscription_id = $2, paid_at = NOW() WHERE email = $3`,
      [plan, session.subscription, req.user.email]
    );
    
    await pool.query(
      `INSERT INTO payments (email, amount, plan, status, session_id)
       VALUES ($1, $2, $3, 'paid', $4) ON CONFLICT (session_id) DO NOTHING`,
      [req.user.email, session.amount_total ? session.amount_total / 100 : 0, plan, session.id]
    );
    
    console.log(`✅ Payment verified: ${req.user.email}`);
    res.json({ success: true });
    
  } catch (err) {
    console.error('Payment verify error:', err);
    res.status(500).json({ error: 'Failed to verify payment' });
  }
});

// ===== ADMIN ENDPOINTS =====
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [usersRes, proRes, revenueRes] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT COUNT(*) FROM users WHERE is_pro = TRUE'),
      pool.query("SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'paid'")
    ]);
    
    const totalUsers = parseInt(usersRes.rows[0].count);
    const proUsers = parseInt(proRes.rows[0].count);
    const revenue = parseFloat(revenueRes.rows[0].total);
    
    res.json({
      totalUsers,
      proUsers,
      revenue,
      conversionRate: totalUsers > 0 ? Math.round((proUsers / totalUsers) * 100) : 0
    });
    
  } catch (err) {
    console.error('Admin stats error:', err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT email, name, is_pro as "isPro", plan, created_at as "createdAt", last_active as "lastActive"
      FROM users ORDER BY created_at DESC
    `);
    
    res.json({ users: result.rows });
    
  } catch (err) {
    console.error('Admin users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/admin/payments', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT email, amount, plan, status, session_id as "sessionId", created_at as "date"
      FROM payments ORDER BY created_at DESC LIMIT 100
    `);
    
    res.json({ payments: result.rows });
    
  } catch (err) {
    console.error('Admin payments error:', err);
    res.status(500).json({ error: 'Failed to fetch payments' });
  }
});

app.get('/api/admin/reset-requests', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT email, requested_at, ip_address
      FROM password_resets
      WHERE used = false AND requested_at > NOW() - INTERVAL '24 hours'
      ORDER BY requested_at DESC
    `);
    
    res.json({ requests: result.rows });
    
  } catch (err) {
    console.error('Reset requests error:', err);
    res.status(500).json({ error: 'Failed to fetch reset requests' });
  }
});

// ===== STRIPE WEBHOOK =====
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  
  if (!sig) {
    return res.status(400).send('Missing signature');
  }
  
  try {
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const email = session.client_reference_id || session.metadata?.userId;
        
        if (!email) break;
        
        await pool.query(
          `UPDATE users SET is_pro = TRUE, plan = $1, stripe_customer_id = $2, stripe_subscription_id = $3, paid_at = NOW() WHERE email = $4`,
          [session.metadata?.plan || 'monthly', session.customer, session.subscription, email]
        );
        
        await pool.query(
          `INSERT INTO payments (email, amount, plan, status, session_id)
           VALUES ($1, $2, $3, 'paid', $4) ON CONFLICT (session_id) DO NOTHING`,
          [email, session.amount_total ? session.amount_total / 100 : 0, session.metadata?.plan || 'monthly', session.id]
        );
        
        console.log(`✅ User ${email} upgraded via webhook`);
        break;
      }
      
      case 'customer.subscription.deleted':
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        const user = await pool.query('SELECT email FROM users WHERE stripe_subscription_id = $1', [sub.id]);
        
        if (user.rows.length > 0) {
          const email = user.rows[0].email;
          
          if (sub.status === 'canceled' || event.type === 'customer.subscription.deleted') {
            await pool.query('UPDATE users SET is_pro = FALSE, plan = NULL WHERE email = $1', [email]);
            console.log(`❌ User ${email} downgraded`);
          }
        }
        break;
      }
    }
    
    res.json({ received: true });
    
  } catch (err) {
    console.error('Webhook error:', err.message);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

// ===== ERROR HANDLING =====
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) =>
  res.status(404).json({ error: 'Endpoint not found' })
);

// ===== REAL-TIME PRESENCE =====
app.post('/api/ping', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE users SET last_active = NOW() WHERE email = $1', [req.user.email]);
    res.json({ success: true });
  } catch (err) {
    console.error('Ping error:', err);
    res.status(500).json({ error: 'Failed to update activity' });
  }
});

// ===== SERVER STARTUP =====
async function startServer() {
  try {
    await initDB();
    await pool.query('SELECT NOW()');
    console.log('✅ DB connected');
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🔗 Webhook: ${CORS_ORIGIN}/api/webhook`);
    });
    
  } catch (err) {
    console.error('❌ Startup failed:', err);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🔄 Shutting down...');
  await pool.end();
  process.exit(0);
});

startServer();
