// server.js - QuoteCards Pro Production Backend
// Fixed: Signup endpoint, Pro recognition, CORS, UI flicker prevention, Performance

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

// === ENVIRONMENT VALIDATION ===
const requiredEnvVars = [
  'STRIPE_SECRET_KEY', 'STRIPE_PUBLISHABLE_KEY', 'STRIPE_WEBHOOK_SECRET',
  'STRIPE_PAYMENT_LINK_MONTHLY', 'STRIPE_PAYMENT_LINK_YEARLY',
  'JWT_SECRET', 'ADMIN_EMAIL', 'DATABASE_URL', 'CORS_ORIGIN'
];
const missingVars = requiredEnvVars.filter(key => !process.env[key]);
if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars.join(', '));
  process.exit(1);
}

// === APP INITIALIZATION ===
const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 10000;
const CORS_ORIGIN = process.env.CORS_ORIGIN;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// === DATABASE CONNECTION ===
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20, // Connection pool size
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

// === EMAIL TRANSPORTER ===
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// === DATABASE INITIALIZATION ===
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
      CREATE INDEX IF NOT EXISTS idx_users_last_active ON users(last_active);
    `);
    console.log('✅ Database tables initialized');

    // Create admin user if not exists
    const adminCheck = await pool.query('SELECT email FROM users WHERE email = $1', [ADMIN_EMAIL]);
    if (adminCheck.rows.length === 0) {
      const adminHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
      await pool.query(
        `INSERT INTO users (email, name, password_hash, is_pro, plan) VALUES ($1, $2, $3, $4, $5)`,
        [ADMIN_EMAIL, 'Admin', adminHash, true, 'admin']
      );
      console.log(`✅ Admin user created: ${ADMIN_EMAIL}`);
    }
  } catch (err) {
    console.error('❌ Database initialization failed:', err);
    process.exit(1);
  }
}

// === MIDDLEWARE ===

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://js.stripe.com', 'https://*.render.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https:', 'blob:'],
      connectSrc: ["'self'", 'https://api.stripe.com', CORS_ORIGIN, 'https://*.render.com', 'https://higherprotocola3.onrender.com'],
      frameSrc: ["'self'", 'https://buy.stripe.com', 'https://*.stripe.com']
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false
}));

// CORS - Allow multiple origins for development/testing
const allowedOrigins = [
  CORS_ORIGIN,
  'https://optimax365.github.io',
  'http://localhost:10000',
  'http://127.0.0.1:10000',
  'https://higherprotocola3.onrender.com'
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`⚠️ CORS blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Logging
app.use(morgan('combined'));

// Body parsing with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} from ${req.ip}`);
  next();
});

// === RATE LIMITING ===
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // Limit each IP to 60 requests per minute
  message: { error: 'Rate limit exceeded' }
});

// === AUTH MIDDLEWARE ===
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required - missing token' });
  }
  
  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    console.warn('Token verification failed:', err.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (!req.user || req.user.email !== ADMIN_EMAIL) {
    console.warn(`⚠️ Admin access denied for: ${req.user?.email || 'unknown'}`);
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Helper: Get client IP
const getIP = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
         req.headers['x-real-ip'] || 
         req.socket.remoteAddress;
};

// === PUBLIC ENDPOINTS ===

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Public config (safe to expose)
app.get('/api/config', (req, res) => {
  res.json({ 
    publishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
    corsOrigin: CORS_ORIGIN,
    version: '1.0.0'
  });
});

// === AUTH ENDPOINTS ===

// 🔹 SIGNUP - FIXED: Proper endpoint registration & error handling
app.post('/api/signup', authLimiter, async (req, res) => {
  console.log('📝 Signup attempt:', req.body?.email);
  
  try {
    const { email, password, name } = req.body;
    
    // Validation
    if (!email?.includes('@')) {
      return res.status(400).json({ error: 'Valid email address required' });
    }
    if (!name || name.trim().length < 2) {
      return res.status(400).json({ error: 'Full name required (min 2 characters)' });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Check if user exists
    const existing = await pool.query('SELECT email FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered. Try signing in instead.' });
    }
    
    // Hash password and create user
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (email, name, password_hash, is_pro, plan) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING email, name, is_pro as "isPro", plan, created_at`,
      [email.toLowerCase().trim(), name.trim(), passwordHash, false, null]
    );
    
    const user = result.rows[0];
    
    // Generate JWT token
    const token = jwt.sign(
      { email: user.email, name: user.name }, 
      JWT_SECRET, 
      { expiresIn: '7d', issuer: 'quotecards-pro' }
    );
    
    console.log(`✅ New user registered: ${user.email}`);
    
    // Return user data with boolean isPro
    res.json({ 
      token, 
      user: { 
        email: user.email, 
        name: user.name, 
        isPro: !!user.isPro, // Ensure boolean
        plan: user.plan,
        createdAt: user.created_at
      } 
    });
    
  } catch (err) {
    console.error('❌ Signup error:', err);
    res.status(500).json({ 
      error: 'Signup failed. Please try again.',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// 🔹 LOGIN
app.post('/api/login', authLimiter, async (req, res) => {
  console.log('🔐 Login attempt:', req.body?.email);
  
  try {
    const { email, password } = req.body;
    
    if (!email?.includes('@') || !password) {
      return res.status(400).json({ error: 'Valid email and password required' });
    }
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    
    if (result.rows.length === 0) {
      console.warn(`Failed login: User not found - ${email}`);
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    
    if (!valid) {
      console.warn(`Failed login: Invalid password for ${email}`);
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Update last active
    await pool.query('UPDATE users SET last_active = NOW() WHERE email = $1', [email]);
    
    // Generate token
    const token = jwt.sign(
      { email: user.email, name: user.name }, 
      JWT_SECRET, 
      { expiresIn: '7d', issuer: 'quotecards-pro' }
    );
    
    console.log(`✅ Login successful: ${user.email}`);
    
    res.json({
      token,
      user: { 
        email: user.email, 
        name: user.name, 
        isPro: !!user.is_pro, // Ensure boolean for frontend
        plan: user.plan,
        lastActive: user.last_active
      }
    });
    
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// 🔹 GET CURRENT USER - FIXED: Returns boolean isPro
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT email, name, is_pro as "isPro", plan, created_at as "createdAt", last_active as "lastActive" 
       FROM users WHERE email = $1`,
      [req.user.email]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    
    // Ensure isPro is boolean for consistent frontend handling
    res.json({ 
      email: user.email, 
      name: user.name, 
      isPro: !!user.isPro,
      plan: user.plan,
      createdAt: user.createdAt,
      lastActive: user.lastActive
    });
    
  } catch (err) {
    console.error('❌ Profile fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

// 🔹 LOGOUT (client-side token removal, but we can invalidate if needed)
app.post('/api/logout', authMiddleware, (req, res) => {
  // In production, you might add token to a blacklist here
  console.log(`👋 User logged out: ${req.user.email}`);
  res.json({ success: true, message: 'Logged out successfully' });
});

// === PASSWORD RESET ===

app.post('/api/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email?.includes('@')) {
      return res.status(400).json({ error: 'Valid email address required' });
    }
    
    const token = crypto.randomBytes(32).toString('hex');
    const ip = getIP(req);
    
    // Store reset request
    await pool.query(
      `INSERT INTO password_resets (email, token, ip_address) VALUES ($1, $2, $3)`,
      [email.toLowerCase(), token, ip]
    );
    
    // Notify admin (since we don't send directly from backend)
    if (process.env.SMTP_USER) {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: ADMIN_EMAIL,
        subject: '🔐 Password Reset Request - QuoteCards Pro',
        html: `
          <h3>Password Reset Request</h3>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>IP Address:</strong> ${ip}</p>
          <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
          <p>Please log into the admin dashboard to send the recovery email.</p>
        `
      }).catch(err => console.warn('Email notification failed:', err.message));
    }
    
    console.log(`🔐 Reset requested: ${email} from ${ip}`);
    res.json({ success: true, message: 'Reset request recorded. Admin has been notified.' });
    
  } catch (err) {
    console.error('❌ Forgot password error:', err);
    res.status(500).json({ error: 'Failed to process reset request' });
  }
});

// Admin: Send recovery email
app.post('/api/admin/send-recovery', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email?.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    
    const user = await pool.query('SELECT name, email FROM users WHERE email = $1', [email.toLowerCase()]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetLink = `${CORS_ORIGIN}/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`;
    
    await pool.query(
      `INSERT INTO password_resets (email, token, used) VALUES ($1, $2, true)`,
      [email.toLowerCase(), resetToken]
    );
    
    if (process.env.SMTP_USER) {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: '🔐 Reset Your QuoteCards Pro Password',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h3 style="color: #6e3bfa;">Reset Your Password</h3>
            <p>Hi ${user.rows[0].name},</p>
            <p>Click the button below to reset your password:</p>
            <p style="text-align: center; margin: 30px 0;">
              <a href="${resetLink}" style="background: linear-gradient(135deg, #6e3bfa, #4287ff); color: white; padding: 12px 30px; text-decoration: none; border-radius: 8px; font-weight: 600; display: inline-block;">
                Reset Password
              </a>
            </p>
            <p style="color: #666; font-size: 14px;">This link expires in 1 hour for security.</p>
            <p style="color: #666; font-size: 12px; margin-top: 20px;">
              If you didn't request this, please ignore this email or contact support.
            </p>
          </div>
        `
      });
    }
    
    console.log(`✅ Recovery email sent to ${email}`);
    res.json({ success: true, message: 'Recovery email sent successfully' });
    
  } catch (err) {
    console.error('❌ Send recovery error:', err);
    res.status(500).json({ error: 'Failed to send recovery email' });
  }
});

// === ACTIVITY TRACKING ===

app.post('/api/activity', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { page, userAgent, timestamp } = req.body;
    
    await pool.query(
      `INSERT INTO user_activity (email, page, user_agent, timestamp, ip_address)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.email, page || 'unknown', userAgent || '', timestamp || new Date().toISOString(), getIP(req)]
    );
    
    // Update last active
    await pool.query('UPDATE users SET last_active = NOW() WHERE email = $1', [req.user.email]);
    
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Activity tracking error:', err);
    res.status(500).json({ error: 'Failed to track activity' });
  }
});

// Real-time presence ping (prevents UI flicker by keeping session fresh)
app.post('/api/ping', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE users SET last_active = NOW() WHERE email = $1', [req.user.email]);
    res.json({ success: true, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('❌ Ping error:', err);
    res.status(500).json({ error: 'Failed to update activity' });
  }
});

// === DOWNLOADS ===

app.post('/api/downloads', authMiddleware, async (req, res) => {
  try {
    const { imageUrl, quote, author, settings } = req.body;
    
    if (!imageUrl) {
      return res.status(400).json({ error: 'Image URL is required' });
    }
    
    await pool.query(
      `INSERT INTO downloads (user_email, image_url, quote, author, settings)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.email, imageUrl, quote || '', author || '', settings || {}]
    );
    
    res.json({ success: true, message: 'Download saved' });
  } catch (err) {
    console.error('❌ Save download error:', err);
    res.status(500).json({ error: 'Failed to save download' });
  }
});

app.get('/api/downloads', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, image_url as "imageUrl", quote, author, settings, created_at as "createdAt"
       FROM downloads WHERE user_email = $1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.email]
    );
    
    res.json({ downloads: result.rows });
  } catch (err) {
    console.error('❌ Fetch downloads error:', err);
    res.status(500).json({ error: 'Failed to fetch downloads' });
  }
});

// Delete a download
app.delete('/api/downloads/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(
      `DELETE FROM downloads WHERE id = $1 AND user_email = $2 RETURNING id`,
      [id, req.user.email]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Download not found or access denied' });
    }
    
    res.json({ success: true, message: 'Download deleted' });
  } catch (err) {
    console.error('❌ Delete download error:', err);
    res.status(500).json({ error: 'Failed to delete download' });
  }
});

// === PAYMENTS ===

app.post('/api/verify-payment', authMiddleware, async (req, res) => {
  try {
    const { sessionId } = req.body;
    
    if (!sessionId) {
      return res.status(400).json({ error: 'Stripe session ID required' });
    }
    
    // Verify session with Stripe
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    
    // Validate session belongs to this user
    if (session.client_reference_id !== req.user.email && session.metadata?.userId !== req.user.email) {
      console.warn(`Session mismatch: ${session.client_reference_id} vs ${req.user.email}`);
      return res.status(400).json({ error: 'Payment session does not match user' });
    }
    
    // Check payment status
    if (session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment not yet completed' });
    }
    
    const plan = session.metadata?.plan || 'monthly';
    
    // Upgrade user to Pro
    await pool.query(
      `UPDATE users SET is_pro = TRUE, plan = $1, stripe_subscription_id = $2, paid_at = NOW() WHERE email = $3`,
      [plan, session.subscription || session.id, req.user.email]
    );
    
    // Record payment
    await pool.query(
      `INSERT INTO payments (email, amount, plan, status, session_id)
       VALUES ($1, $2, $3, 'paid', $4) ON CONFLICT (session_id) DO NOTHING`,
      [req.user.email, session.amount_total ? session.amount_total / 100 : 0, plan, session.id]
    );
    
    console.log(`✅ Payment verified & user upgraded: ${req.user.email}`);
    res.json({ success: true, message: 'Pro membership activated!' });
    
  } catch (err) {
    console.error('❌ Payment verification error:', err);
    res.status(500).json({ 
      error: 'Failed to verify payment',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// === ADMIN ENDPOINTS ===

app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [usersRes, proRes, revenueRes, newUsersRes] = await Promise.all([
      pool.query('SELECT COUNT(*) as count FROM users'),
      pool.query('SELECT COUNT(*) as count FROM users WHERE is_pro = TRUE'),
      pool.query("SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'paid'"),
      pool.query("SELECT COUNT(*) as count FROM users WHERE created_at >= NOW() - INTERVAL '30 days'")
    ]);
    
    const totalUsers = parseInt(usersRes.rows[0].count);
    const proUsers = parseInt(proRes.rows[0].count);
    const revenue = parseFloat(revenueRes.rows[0].total);
    const newUsers = parseInt(newUsersRes.rows[0].count);
    
    res.json({
      totalUsers,
      proUsers,
      revenue,
      conversionRate: totalUsers > 0 ? Math.round((proUsers / totalUsers) * 100) : 0,
      newUsersLast30Days: newUsers,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('❌ Admin stats error:', err);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { search, status, limit = 100, offset = 0 } = req.query;
    
    let query = `
      SELECT email, name, is_pro as "isPro", plan, created_at as "createdAt", last_active as "lastActive"
      FROM users WHERE 1=1
    `;
    const params = [];
    let paramIndex = 1;
    
    if (search) {
      query += ` AND (email ILIKE $${paramIndex} OR name ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex++;
    }
    
    if (status === 'pro') {
      query += ` AND is_pro = TRUE`;
    } else if (status === 'free') {
      query += ` AND is_pro = FALSE`;
    }
    
    query += ` ORDER BY created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(parseInt(limit), parseInt(offset));
    
    const result = await pool.query(query, params);
    const total = await pool.query('SELECT COUNT(*) FROM users');
    
    res.json({ 
      users: result.rows.map(u => ({ ...u, isPro: !!u.isPro })),
      total: parseInt(total.rows[0].count),
      page: Math.floor(offset / limit) + 1
    });
  } catch (err) {
    console.error('❌ Admin users error:', err);
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
    console.error('❌ Admin payments error:', err);
    res.status(500).json({ error: 'Failed to fetch payments' });
  }
});

app.get('/api/admin/reset-requests', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT email, requested_at, ip_address, used
      FROM password_resets
      WHERE requested_at > NOW() - INTERVAL '24 hours'
      ORDER BY requested_at DESC
    `);
    
    res.json({ requests: result.rows });
  } catch (err) {
    console.error('❌ Reset requests error:', err);
    res.status(500).json({ error: 'Failed to fetch reset requests' });
  }
});

// Admin: Manually upgrade/downgrade user
app.post('/api/admin/users/:email/plan', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { email } = req.params;
    const { isPro, plan } = req.body;
    
    if (typeof isPro !== 'boolean') {
      return res.status(400).json({ error: 'isPro must be a boolean' });
    }
    
    await pool.query(
      `UPDATE users SET is_pro = $1, plan = $2, paid_at = CASE WHEN $1 = TRUE THEN COALESCE(paid_at, NOW()) ELSE NULL END WHERE email = $3`,
      [isPro, plan || null, email.toLowerCase()]
    );
    
    console.log(`👤 Admin updated ${email}: isPro=${isPro}, plan=${plan}`);
    res.json({ success: true, message: `User ${isPro ? 'upgraded to Pro' : 'downgraded to Free'}` });
    
  } catch (err) {
    console.error('❌ Admin plan update error:', err);
    res.status(500).json({ error: 'Failed to update user plan' });
  }
});

// === STRIPE WEBHOOK ===

app.post('/api/webhook', 
  express.raw({ type: 'application/json' }), 
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    
    if (!sig) {
      console.warn('Webhook: Missing Stripe signature');
      return res.status(400).send('Missing signature header');
    }
    
    try {
      const event = stripe.webhooks.constructEvent(
        req.body, 
        sig, 
        process.env.STRIPE_WEBHOOK_SECRET
      );
      
      console.log(`🎯 Webhook received: ${event.type}`);
      
      switch (event.type) {
        case 'checkout.session.completed': {
          const session = event.data.object;
          const email = session.client_reference_id || session.metadata?.userId || session.customer_email;
          
          if (!email) {
            console.warn('Webhook: No email found in session');
            break;
          }
          
          const plan = session.metadata?.plan || 'monthly';
          
          // Upgrade user
          await pool.query(
            `UPDATE users SET is_pro = TRUE, plan = $1, stripe_customer_id = $2, stripe_subscription_id = $3, paid_at = NOW() WHERE email = $4`,
            [plan, session.customer, session.subscription, email.toLowerCase()]
          );
          
          // Record payment
          await pool.query(
            `INSERT INTO payments (email, amount, plan, status, session_id)
             VALUES ($1, $2, $3, 'paid', $4) ON CONFLICT (session_id) DO NOTHING`,
            [email.toLowerCase(), session.amount_total ? session.amount_total / 100 : 0, plan, session.id]
          );
          
          console.log(`✅ Webhook: User ${email} upgraded to Pro (${plan})`);
          break;
        }
        
        case 'customer.subscription.updated':
        case 'customer.subscription.deleted': {
          const sub = event.data.object;
          
          // Find user by subscription ID
          const user = await pool.query(
            'SELECT email FROM users WHERE stripe_subscription_id = $1', 
            [sub.id]
          );
          
          if (user.rows.length > 0) {
            const email = user.rows[0].email;
            
            if (sub.status === 'canceled' || event.type === 'customer.subscription.deleted') {
              // Downgrade user
              await pool.query(
                'UPDATE users SET is_pro = FALSE, plan = NULL WHERE email = $1', 
                [email]
              );
              console.log(`❌ Webhook: User ${email} subscription canceled - downgraded to Free`);
            }
          }
          break;
        }
        
        case 'invoice.payment_failed': {
          const invoice = event.data.object;
          const email = invoice.customer_email;
          
          if (email) {
            console.warn(`⚠️ Webhook: Payment failed for ${email}`);
            // Could send notification email here
          }
          break;
        }
      }
      
      res.json({ received: true });
      
    } catch (err) {
      console.error('❌ Webhook error:', err.message);
      res.status(400).send(`Webhook Error: ${err.message}`);
    }
  }
);

// === ERROR HANDLING ===

// 404 handler - MUST be after all routes
app.use((req, res) => {
  console.warn(`404: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ 
    error: 'Endpoint not found', 
    path: req.originalUrl,
    method: req.method,
    available: ['GET /health', 'POST /api/signup', 'POST /api/login', 'GET /api/me', '...']
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('💥 Unhandled error:', err);
  
  // Don't leak error details in production
  const isDev = process.env.NODE_ENV === 'development';
  
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(isDev && { stack: err.stack, details: err })
  });
});

// === GRACEFUL SHUTDOWN ===
process.on('SIGTERM', async () => {
  console.log('🔄 SIGTERM received, shutting down gracefully...');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('🔄 SIGINT received, shutting down gracefully...');
  await pool.end();
  process.exit(0);
});

// === START SERVER ===
async function startServer() {
  try {
    await initDB();
    
    // Test DB connection
    await pool.query('SELECT NOW()');
    console.log('✅ Database connected successfully');
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`\n🚀 QuoteCards Pro Server Running`);
      console.log(`📍 Port: ${PORT}`);
      console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔗 API Base: https://higherprotocola3.onrender.com`);
      console.log(`🎨 Frontend: ${CORS_ORIGIN}`);
      console.log(`👤 Admin: ${ADMIN_EMAIL}`);
      console.log(`🪝 Webhook: /api/webhook\n`);
    });
    
  } catch (err) {
    console.error('❌ Server startup failed:', err);
    process.exit(1);
  }
}

// Start the server
startServer();

// Export for testing
module.exports = { app, pool };
