require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const Stripe = require('stripe');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const FREE_REPORT_LIMIT = 5;

if (!JWT_SECRET) {
  console.error('Missing JWT_SECRET in environment. Set it before starting the server.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false },
});

const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

app.post('/api/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(500).send('Stripe not configured');
  }
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers['stripe-signature'],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const garageId = session.client_reference_id;
        await pool.query(
          `UPDATE garages SET stripe_customer_id = $1, stripe_subscription_id = $2, subscription_status = 'active' WHERE id = $3`,
          [session.customer, session.subscription, garageId]
        );
        break;
      }
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const status = sub.status === 'active' || sub.status === 'trialing' ? 'active' : sub.status;
        await pool.query(
          `UPDATE garages SET subscription_status = $1 WHERE stripe_customer_id = $2`,
          [status, sub.customer]
        );
        break;
      }
    }
    res.json({ received: true });
  } catch (err) {
    console.error('Webhook handling error:', err);
    res.status(500).send('Webhook handler error');
  }
});

app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function signToken(garage) {
  return jwt.sign({ garageId: garage.id }, JWT_SECRET, { expiresIn: '30d' });
}

async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not logged in.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT * FROM garages WHERE id = $1', [payload.garageId]);
    if (!rows[0]) return res.status(401).json({ error: 'Account no longer exists.' });
    req.garage = rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Session expired, please log in again.' });
  }
}

function publicGarage(g) {
  return {
    id: g.id,
    name: g.name,
    email: g.email,
    subscriptionStatus: g.subscription_status,
    freeReportsUsed: g.free_reports_used,
    freeReportLimit: FREE_REPORT_LIMIT,
  };
}

app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are all required.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  try {
    const existing = await pool.query('SELECT id FROM garages WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length) return res.status(409).json({ error: 'An account with that email already exists.' });

    const passwordHash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO garages (name, email, password_hash) VALUES ($1, $2, $3) RETURNING *`,
      [name, email.toLowerCase(), passwordHash]
    );
    const garage = rows[0];
    res.json({ token: signToken(garage), garage: publicGarage(garage) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not create account.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  try {
    const { rows } = await pool.query('SELECT * FROM garages WHERE email = $1', [email.toLowerCase()]);
    const garage = rows[0];
    if (!garage || !(await bcrypt.compare(password, garage.password_hash))) {
      return res.status(401).json({ error: 'Incorrect email or password.' });
    }
    res.json({ token: signToken(garage), garage: publicGarage(garage) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not log in.' });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ garage: publicGarage(req.garage) });
});

app.get('/api/inspections', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, share_token, vehicle_reg, customer_name, created_at
     FROM inspections WHERE garage_id = $1 ORDER BY created_at DESC LIMIT 100`,
    [req.garage.id]
  );
  res.json({ inspections: rows });
});

app.post('/api/inspections', requireAuth, async (req, res) => {
  const { vehicleReg, customerName, data } = req.body || {};
  if (!data) return res.status(400).json({ error: 'Missing inspection data.' });

  const canUseFreeTier = req.garage.free_reports_used < FREE_REPORT_LIMIT;
  const isSubscribed = req.garage.subscription_status === 'active';
  if (!canUseFreeTier && !isSubscribed) {
    return res.status(402).json({
      error: `You've used your ${FREE_REPORT_LIMIT} free reports. Subscribe to keep generating them.`,
      requiresSubscription: true,
    });
  }

  const shareToken = uuidv4();
  try {
    const { rows } = await pool.query(
      `INSERT INTO inspections (garage_id, share_token, vehicle_reg, customer_name, data)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, share_token, created_at`,
      [req.garage.id, shareToken, vehicleReg || null, customerName || null, JSON.stringify(data)]
    );

    if (!isSubscribed) {
      await pool.query('UPDATE garages SET free_reports_used = free_reports_used + 1 WHERE id = $1', [req.garage.id]);
    }

    res.json({ inspection: rows[0], shareUrl: `/report.html?token=${shareToken}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not save inspection.' });
  }
});

app.get('/api/public/inspections/:token', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT i.vehicle_reg, i.customer_name, i.data, i.created_at, g.name AS garage_name
     FROM inspections i JOIN garages g ON g.id = i.garage_id
     WHERE i.share_token = $1`,
    [req.params.token]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Report not found.' });
  res.json({ report: rows[0] });
});

app.post('/api/billing/create-checkout-session', requireAuth, async (req, res) => {
  if (!stripe || !process.env.STRIPE_PRICE_ID) {
    return res.status(500).json({ error: 'Billing is not configured yet.' });
  }
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: req.garage.stripe_customer_id ? undefined : req.garage.email,
      customer: req.garage.stripe_customer_id || undefined,
      client_reference_id: String(req.garage.id),
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${process.env.APP_URL}/app.html?subscribed=1`,
      cancel_url: `${process.env.APP_URL}/app.html?subscribed=0`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not start checkout.' });
  }
});

app.post('/api/billing/create-portal-session', requireAuth, async (req, res) => {
  if (!stripe || !req.garage.stripe_customer_id) {
    return res.status(400).json({ error: 'No billing account found yet.' });
  }
  try {
    const session = await stripe.billingPortal.sessions.create({
      customer: req.garage.stripe_customer_id,
      return_url: `${process.env.APP_URL}/app.html`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not open billing portal.' });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Garage health check server running on port ${PORT}`));
