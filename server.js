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
require('dotenv').config();

// Validate environment variables on startup
const requiredEnvVars = [
  'STRIPE_SECRET_KEY',
  'STRIPE_PUBLISHABLE_KEY', 
  'STRIPE_WEBHOOK_SECRET',
  'STRIPE_PAYMENT_LINK_MONTHLY',
  'STRIPE_PAYMENT_LINK_YEARLY',
  'JWT_SECRET',
  'ADMIN_EMAIL',
  'ADMIN_PASSWORD',
  'DATABASE_URL',
  'CORS_ORIGIN'
];

const missingVars = requiredEnvVars.filter(key => !process.env[key]);
if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars.join(', '));
  process.exit(1);
}

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;
const CORS_ORIGIN = process.env.CORS_ORIGIN;

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database schema
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
      
      CREATE INDEX IF NOT EXISTS idx_payments_email ON payments(email);
      CREATE INDEX IF NOT EXISTS idx_users_is_pro ON users(is_pro);
    `);
    console.log('✅ Database schema initialized');
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
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://js.stripe.com'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://api.stripe.com'],
      frameSrc: ["'self'", 'https://buy.stripe.com']
    }
  }
}));

// CORS configuration
app.use(cors({
  origin: CORS_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Request logging
app.use(morgan(process.env.LOG_LEVEL === 'debug' ? 'combined' : 'short'));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public', { 
  maxAge: '1y',
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
  }
}));

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

// === AUTH MIDDLEWARE ===
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.email !== process.env.ADMIN_EMAIL) {
    console.warn(`⚠️ Unauthorized admin access attempt by: ${req.user.email}`);
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// === PUBLIC ENDPOINTS ===

app.get('/api/config', (req, res) => {
  res.json({ 
    publishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
    paymentLinks: {
      monthly: process.env.STRIPE_PAYMENT_LINK_MONTHLY,
      yearly: process.env.STRIPE_PAYMENT_LINK_YEARLY
    }
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// === AUTH ENDPOINTS ===

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email?.includes('@') || !password) {
      return res.status(400).json({ error: 'Valid email and password required' });
    }
    
    // Find or create user
    let user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (user.rows.length === 0) {
      // Auto-register with hashed password
      const passwordHash = await bcrypt.hash(password, 12);
      const newUser = await pool.query(
        `INSERT INTO users (email, name, password_hash) 
         VALUES ($1, $2, $3) RETURNING *`,
        [email, email.split('@')[0], passwordHash]
      );
      user = newUser;
    } else {
      // Verify password for existing user
      const valid = await bcrypt.compare(password, user.rows[0].password_hash);
      if (!valid) {
        console.warn(`Failed login attempt for: ${email}`);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Update last active
      await pool.query('UPDATE users SET last_active = NOW() WHERE email = $1', [email]);
    }
    
    const userData = user.rows[0];
    const token = jwt.sign(
      { email: userData.email, name: userData.name }, 
      JWT_SECRET, 
      { expiresIn: '7d', issuer: 'quotecards-pro' }
    );
    
    res.json({
      token,
      user: {
        email: userData.email,
        name: userData.name,
        isPro: userData.is_pro,
        plan: userData.plan
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Authentication service unavailable' });
  }
});

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
    console.error('Profile fetch error:', err);
    res.status(500).json({ error: 'Failed to retrieve profile' });
  }
});

// === PAYMENT ENDPOINTS ===

// Verify payment after Stripe redirect (called by frontend)
app.post('/api/verify-payment', authMiddleware, async (req, res) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) return res.status(400).json({ error: 'Session ID required' });
    
    // Retrieve session from Stripe
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    
    // Validate session belongs to this user
    if (session.client_reference_id !== req.user.email) {
      return res.status(400).json({ error: 'Session mismatch' });
    }
    
    if (session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment not completed' });
    }
    
    // Upgrade user in database
    const plan = session.metadata?.plan || 'monthly';
    await pool.query(
      `UPDATE users 
       SET is_pro = TRUE, plan = $1, stripe_subscription_id = $2, paid_at = NOW()
       WHERE email = $3`,
      [plan, session.subscription, req.user.email]
    );
    
    // Record payment
    await pool.query(
      `INSERT INTO payments (email, amount, plan, status, session_id)
       VALUES ($1, $2, $3, 'paid', $4)`,
      [
        req.user.email,
        session.amount_total ? session.amount_total / 100 : 0,
        plan,
        session.id
      ]
    );
    
    console.log(`✅ Payment verified for ${req.user.email}: ${plan} plan`);
    res.json({ success: true });
    
  } catch (err) {
    console.error('Payment verification error:', err);
    res.status(500).json({ error: 'Failed to verify payment' });
  }
});

// Create billing portal session for subscription management
app.post('/api/create-portal-session', authMiddleware, async (req, res) => {
  try {
    const user = await pool.query(
      'SELECT stripe_customer_id FROM users WHERE email = $1',
      [req.user.email]
    );
    
    if (user.rows.length === 0 || !user.rows[0].stripe_customer_id) {
      return res.status(400).json({ error: 'No active subscription found' });
    }
    
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: user.rows[0].stripe_customer_id,
      return_url: `${CORS_ORIGIN}`
    });
    
    res.json({ url: portalSession.url });
  } catch (err) {
    console.error('Portal session error:', err);
    res.status(500).json({ error: 'Failed to create billing portal' });
  }
});

// === ADMIN ENDPOINTS ===

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
    res.status(500).json({ error: 'Failed to retrieve stats' });
  }
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT email, name, is_pro as "isPro", plan, 
             created_at as "createdAt", last_active as "lastActive"
      FROM users 
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Admin users fetch error:', err);
    res.status(500).json({ error: 'Failed to retrieve users' });
  }
});

app.get('/api/admin/payments', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT email, amount, plan, status, session_id as "sessionId", created_at as "date"
      FROM payments 
      ORDER BY created_at DESC 
      LIMIT 100
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Admin payments fetch error:', err);
    res.status(500).json({ error: 'Failed to retrieve payments' });
  }
});

// === STRIPE WEBHOOK (Critical for subscription lifecycle) ===
// Must use raw body for signature verification
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  
  if (!sig) {
    console.error('❌ Webhook missing Stripe signature');
    return res.status(400).send('Missing signature');
  }
  
  try {
    const event = stripe.webhooks.constructEvent(
      req.body, 
      sig, 
      process.env.STRIPE_WEBHOOK_SECRET
    );
    
    console.log(`🔔 Webhook received: ${event.type}`);
    
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const email = session.client_reference_id || session.metadata?.userId;
        
        if (!email) {
          console.warn('⚠️ Checkout session missing user identifier');
          break;
        }
        
        // Update user to Pro
        await pool.query(
          `UPDATE users 
           SET is_pro = TRUE, 
               plan = $1, 
               stripe_customer_id = $2,
               stripe_subscription_id = $3,
               paid_at = NOW()
           WHERE email = $4`,
          [
            session.metadata?.plan || 'monthly',
            session.customer,
            session.subscription,
            email
          ]
        );
        
        // Record payment
        await pool.query(
          `INSERT INTO payments (email, amount, plan, status, session_id)
           VALUES ($1, $2, $3, 'paid', $4)
           ON CONFLICT (session_id) DO NOTHING`,
          [
            email,
            session.amount_total ? session.amount_total / 100 : 0,
            session.metadata?.plan || 'monthly',
            session.id
          ]
        );
        
        console.log(`✅ User ${email} upgraded to Pro via webhook`);
        break;
      }
      
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const status = subscription.status;
        
        // Find user by subscription ID
        const user = await pool.query(
          'SELECT email FROM users WHERE stripe_subscription_id = $1',
          [subscription.id]
        );
        
        if (user.rows.length > 0) {
          const email = user.rows[0].email;
          
          if (status === 'canceled' || status === 'unpaid' || event.type === 'customer.subscription.deleted') {
            // Downgrade user
            await pool.query(
              'UPDATE users SET is_pro = FALSE, plan = NULL WHERE email = $1',
              [email]
            );
            console.log(`❌ User ${email} subscription ${status} - downgraded to Free`);
          } else {
            // Update plan details
            const planName = subscription.items.data[0]?.price?.nickname || 'monthly';
            await pool.query(
              'UPDATE users SET plan = $1 WHERE email = $2',
              [planName, email]
            );
            console.log(`🔄 User ${email} subscription updated: ${status}`);
          }
        }
        break;
      }
      
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        const user = await pool.query(
          'SELECT email FROM users WHERE stripe_customer_id = $1',
          [invoice.customer]
        );
        
        if (user.rows.length > 0) {
          console.log(`⚠️ Payment failed for ${user.rows[0].email} - invoice: ${invoice.id}`);
          // Optional: Send email notification to user here
        }
        break;
      }
      
      // Handle other events as needed
      default:
        console.log(`ℹ️ Unhandled webhook event: ${event.type}`);
    }
    
    res.json({ received: true });
    
  } catch (err) {
    console.error('❌ Webhook signature verification or processing failed:', err.message);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

// === ERROR HANDLING ===
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// === START SERVER ===
async function startServer() {
  try {
    await initDB();
    
    // Test database connection
    await pool.query('SELECT NOW()');
    console.log('✅ Database connection verified');
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 QuoteCards Pro running in PRODUCTION mode`);
      console.log(`📡 Server: http://localhost:${PORT}`);
      console.log(`🔗 Webhook: ${process.env.CORS_ORIGIN}/api/webhook`);
      console.log(`🛡️  Environment: ${process.env.NODE_ENV}`);
      console.log(`🔐 CORS Origin: ${CORS_ORIGIN}`);
    });
    
  } catch (err) {
    console.error('❌ Failed to start server:', err);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🔄 Received SIGTERM, shutting down gracefully');
  await pool.end();
  process.exit(0);
});

startServer();
