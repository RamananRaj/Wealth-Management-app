require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const stripe     = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { createClient } = require('@supabase/supabase-js');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto     = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Supabase (service-role key = full DB access, used only server-side)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-to-a-long-random-string';

// ── Email (Resend API — works on Render free tier) ────────────────
const APP_NAME = 'Propertiq';
const APP_URL  = process.env.APP_URL || 'https://ramananraj.github.io/Wealth-Management-app';

async function sendEmail({ to, subject, html }) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) { console.warn('⚠️  RESEND_API_KEY not set — email skipped'); return; }

  // Use verified domain sender if available, otherwise Resend's default
  const from = process.env.EMAIL_FROM
    ? `"${APP_NAME}" <${process.env.EMAIL_FROM}>`
    : `"${APP_NAME}" <onboarding@resend.dev>`;

  const res = await fetch('https://api.resend.com/emails', {
    method:  'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify({ from, to, subject, html }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Resend API error');
  return data;
}

console.log(process.env.RESEND_API_KEY ? '✅  Resend email ready' : '⚠️  RESEND_API_KEY not set');

async function sendWelcomeEmail(user) {
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#1a1a1a;">
      <div style="background:#1E3A5F;padding:28px 32px;border-radius:8px 8px 0 0;">
        <h1 style="color:#fff;margin:0;font-size:22px;">${APP_NAME}</h1>
      </div>
      <div style="background:#fff;padding:32px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px;">
        <h2 style="margin-top:0;">Welcome, ${user.first_name}!</h2>
        <p>Your ${APP_NAME} account is ready. You can now track your property portfolio, monitor income and expenses, and stay on top of your investments — all in one place.</p>
        <a href="${APP_URL}" style="display:inline-block;margin:16px 0;padding:12px 24px;background:#1E3A5F;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;">Open ${APP_NAME}</a>
        <p style="color:#6b7280;font-size:13px;margin-top:24px;">If you didn't create this account, you can safely ignore this email.</p>
      </div>
    </div>`;
  await sendEmail({ to: user.email, subject: `Welcome to ${APP_NAME}`, html })
    .catch(err => console.error('Welcome email failed:', err.message));
}

async function sendPasswordResetEmail(email, token) {
  const resetUrl = `${APP_URL}?reset=${token}`;
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#1a1a1a;">
      <div style="background:#1E3A5F;padding:28px 32px;border-radius:8px 8px 0 0;">
        <h1 style="color:#fff;margin:0;font-size:22px;">${APP_NAME}</h1>
      </div>
      <div style="background:#fff;padding:32px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px;">
        <h2 style="margin-top:0;">Reset your password</h2>
        <p>We received a request to reset the password for your ${APP_NAME} account.</p>
        <a href="${resetUrl}" style="display:inline-block;margin:16px 0;padding:12px 24px;background:#1E3A5F;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;">Reset Password</a>
        <p style="color:#6b7280;font-size:13px;">This link expires in <strong>1 hour</strong>. If you didn't request a password reset, you can safely ignore this email — your password won't change.</p>
        <p style="color:#9ca3af;font-size:12px;margin-top:24px;word-break:break-all;">Or copy this link: ${resetUrl}</p>
      </div>
    </div>`;
  await sendEmail({ to: email, subject: `Reset your ${APP_NAME} password`, html })
    .catch(err => console.error('Reset email failed:', err.message));
}

// ── Stripe Price IDs
const PLAN_PRICES = {
  investor:  process.env.STRIPE_PRICE_INVESTOR,
  portfolio: process.env.STRIPE_PRICE_PORTFOLIO,
};

// ─────────────────────────────────────────────────────────────────
// Auth middleware
// ─────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

// ─────────────────────────────────────────────────────────────────
// WEBHOOK — must be before express.json() so body stays raw
// ─────────────────────────────────────────────────────────────────
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('⚠️  Webhook error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const { userId, plan } = session.metadata || {};
      if (userId && plan) {
        await supabase.from('users').update({
          plan,
          stripe_customer_id:     session.customer,
          stripe_subscription_id: session.subscription,
          updated_at: new Date().toISOString(),
        }).eq('id', userId);
        // Sync to CRM
        await syncCrmCustomer(userId, {
          stripeCustomerId:    session.customer,
          stripeSubscriptionId: session.subscription,
          stripePlan:          plan,
          stripeStatus:        'active',
          subscribedAt:        new Date().toISOString(),
        });
        console.log(`✅  Plan upgraded: user ${userId} → ${plan}`);
      }
      break;
    }
    case 'customer.subscription.created':
    case 'customer.subscription.updated': {
      const sub = event.data.object;
      const priceId = sub.items.data[0]?.price?.id;
      const newPlan = Object.entries(PLAN_PRICES).find(([, pid]) => pid === priceId)?.[0];
      const { data: users } = await supabase.from('users').select('id').eq('stripe_customer_id', sub.customer);
      if (users?.length) {
        if (newPlan) {
          await supabase.from('users').update({ plan: newPlan, updated_at: new Date().toISOString() }).eq('id', users[0].id);
        }
        await syncCrmCustomer(users[0].id, {
          stripeSubscriptionId: sub.id,
          stripeStatus:        sub.status,
          stripePlan:          newPlan,
          nextBillingAt:       sub.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : null,
          trialEndsAt:         sub.trial_end ? new Date(sub.trial_end * 1000).toISOString() : null,
          cancelledAt:         sub.canceled_at ? new Date(sub.canceled_at * 1000).toISOString() : null,
        });
      }
      break;
    }
    case 'customer.subscription.deleted': {
      const sub = event.data.object;
      const { data: users } = await supabase.from('users').select('id').eq('stripe_customer_id', sub.customer);
      if (users?.length) {
        await supabase.from('users').update({ plan: 'free', updated_at: new Date().toISOString() }).eq('id', users[0].id);
        await syncCrmCustomer(users[0].id, {
          stripeStatus: 'cancelled',
          stripePlan:   'free',
          cancelledAt:  new Date().toISOString(),
        });
      }
      break;
    }
    case 'invoice.payment_succeeded': {
      const inv = event.data.object;
      const { data: users } = await supabase.from('users').select('id').eq('stripe_customer_id', inv.customer);
      if (users?.length) {
        // Get payment method details
        let cardBrand = null, cardLast4 = null, cardExpMonth = null, cardExpYear = null;
        try {
          const pmId = inv.payment_intent ? (await stripe.paymentIntents.retrieve(inv.payment_intent)).payment_method : null;
          if (pmId) {
            const pm = await stripe.paymentMethods.retrieve(pmId);
            cardBrand    = pm.card?.brand;
            cardLast4    = pm.card?.last4;
            cardExpMonth = pm.card?.exp_month;
            cardExpYear  = pm.card?.exp_year;
          }
        } catch(e) { /* non-critical */ }
        await syncCrmCustomer(users[0].id, {
          lastPaymentAt:     new Date(inv.created * 1000).toISOString(),
          lastPaymentAmount: inv.amount_paid,
          stripeStatus:      'active',
          cardBrand, cardLast4, cardExpMonth, cardExpYear,
        });
      }
      break;
    }
    case 'invoice.payment_failed': {
      const inv = event.data.object;
      const { data: users } = await supabase.from('users').select('id').eq('stripe_customer_id', inv.customer);
      if (users?.length) {
        await syncCrmCustomer(users[0].id, { stripeStatus: 'past_due' });
      }
      break;
    }
  }
  res.json({ received: true });
});

// Helper: upsert a CRM customer record
async function syncCrmCustomer(userId, fields) {
  if (!userId) return;
  const { data: user } = await supabase.from('users').select('id, email, stripe_customer_id, stripe_subscription_id, created_at').eq('id', userId).single();
  if (!user) return;
  const updates = {
    id:         userId,
    user_id:    userId,
    email:      user.email,
    created_at: user.created_at,
    updated_at: new Date().toISOString(),
  };
  if (fields.stripeCustomerId    !== undefined) updates.stripe_customer_id     = fields.stripeCustomerId    || user.stripe_customer_id;
  if (fields.stripeSubscriptionId !== undefined) updates.stripe_subscription_id = fields.stripeSubscriptionId;
  if (fields.stripeStatus        !== undefined) updates.stripe_status          = fields.stripeStatus;
  if (fields.stripePlan          !== undefined) updates.stripe_plan            = fields.stripePlan;
  if (fields.lastPaymentAt       !== undefined) updates.last_payment_at        = fields.lastPaymentAt;
  if (fields.lastPaymentAmount   !== undefined) updates.last_payment_amount    = fields.lastPaymentAmount;
  if (fields.nextBillingAt       !== undefined) updates.next_billing_at        = fields.nextBillingAt;
  if (fields.cardBrand           !== undefined) updates.card_brand             = fields.cardBrand;
  if (fields.cardLast4           !== undefined) updates.card_last4             = fields.cardLast4;
  if (fields.cardExpMonth        !== undefined) updates.card_exp_month         = fields.cardExpMonth;
  if (fields.cardExpYear         !== undefined) updates.card_exp_year          = fields.cardExpYear;
  if (fields.trialEndsAt         !== undefined) updates.trial_ends_at          = fields.trialEndsAt;
  if (fields.subscribedAt        !== undefined) updates.subscribed_at          = fields.subscribedAt;
  if (fields.cancelledAt         !== undefined) updates.cancelled_at           = fields.cancelledAt;
  await supabase.from('crm_customers').upsert(updates, { onConflict: 'id' });
}

// ── Middleware (after webhook)
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────
function sanitizeUser(u) {
  return {
    id:            u.id,
    firstName:     u.first_name,
    lastName:      u.last_name,
    email:         u.email,
    role:          u.role,
    plan:          u.plan,
    status:        u.status,
    company:       u.company,
    preferredName: u.preferred_name,
    advisorId:     u.advisor_id,
    createdAt:     u.created_at,
    lastLogin:     u.last_login,
  };
}

function dbPropToClient(p) {
  return {
    id: p.id,
    address: p.address, suburb: p.suburb, postcode: p.postcode, state: p.state,
    type: p.type, beds: p.beds, baths: p.baths, cars: p.cars, land: p.land,
    purchasePrice: p.purchase_price, purchaseDate: p.purchase_date,
    value: p.value, valuedDate: p.valued_date,
    loan: p.loan, rate: p.rate, repayment: p.repayment, loanType: p.loan_type,
    lender: p.lender, fixedUntil: p.fixed_until,
    weeklyRent: p.weekly_rent, vacancy: p.vacancy, tenant: p.tenant, leaseExpiry: p.lease_expiry,
    rates: p.rates, insurance: p.insurance, mgmt: p.mgmt, maintenance: p.maintenance,
    strata: p.strata, water: p.water,
    notes: p.notes, image: p.image, owners: p.owners,
  };
}

function clientPropToDb(p, userId) {
  return {
    id: p.id, user_id: userId,
    address: p.address, suburb: p.suburb, postcode: p.postcode, state: p.state,
    type: p.type, beds: p.beds, baths: p.baths, cars: p.cars, land: p.land,
    purchase_price: p.purchasePrice, purchase_date: p.purchaseDate,
    value: p.value, valued_date: p.valuedDate,
    loan: p.loan, rate: p.rate, repayment: p.repayment, loan_type: p.loanType,
    lender: p.lender, fixed_until: p.fixedUntil,
    weekly_rent: p.weeklyRent, vacancy: p.vacancy, tenant: p.tenant, lease_expiry: p.leaseExpiry,
    rates: p.rates, insurance: p.insurance, mgmt: p.mgmt, maintenance: p.maintenance,
    strata: p.strata, water: p.water,
    notes: p.notes, image: p.image, owners: p.owners || null,
    created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
  };
}

// ─────────────────────────────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────────────────────────────

// Register
app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, email, password, company, inviteCode } = req.body;

  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }

  const { data: existing } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).maybeSingle();
  if (existing) return res.status(409).json({ error: 'An account with this email already exists.' });

  const { count } = await supabase.from('users').select('*', { count: 'exact', head: true });
  const isFirst = count === 0;

  let assignedRole = isFirst ? 'admin' : 'user';
  let inviteRow = null;
  if (inviteCode && !isFirst) {
    const { data: inv } = await supabase.from('invites')
      .select('*').eq('code', inviteCode.toUpperCase()).eq('status', 'pending').maybeSingle();
    if (!inv) return res.status(400).json({ error: 'Invalid or already-used invitation code.' });
    assignedRole = 'advisor';
    inviteRow = inv;
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const userId = Date.now().toString();

  const { data: user, error } = await supabase.from('users').insert({
    id:            userId,
    first_name:    firstName,
    last_name:     lastName,
    email:         email.toLowerCase(),
    password_hash: passwordHash,
    role:          assignedRole,
    plan:          isFirst ? null : 'free',
    status:        'active',
    company:       company || null,
    created_at:    new Date().toISOString(),
    updated_at:    new Date().toISOString(),
  }).select().single();

  if (error) return res.status(500).json({ error: error.message });

  if (inviteRow) {
    await supabase.from('invites').update({
      status: 'used', used_by: userId, used_at: new Date().toISOString()
    }).eq('id', inviteRow.id);
  }

  const token = jwt.sign(
    { id: user.id, role: user.role, plan: user.plan },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  console.log(`✅  Registered: ${email} as ${assignedRole}`);
  sendWelcomeEmail(user); // non-blocking
  res.json({ token, user: sanitizeUser(user) });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });

  const { data: user } = await supabase.from('users').select('*').eq('email', email.toLowerCase()).maybeSingle();
  if (!user) return res.status(401).json({ error: 'Invalid email or password.' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid email or password.' });

  if (user.status !== 'active') {
    return res.status(403).json({ error: 'Your account has been deactivated. Please contact an administrator.' });
  }

  await supabase.from('users').update({ updated_at: new Date().toISOString(), last_login: new Date().toISOString() }).eq('id', user.id);

  const token = jwt.sign(
    { id: user.id, role: user.role, plan: user.plan },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  console.log(`🔑  Login: ${email}`);
  res.json({ token, user: sanitizeUser(user) });
});

// Forgot password — send reset email
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });

  const { data: user } = await supabase.from('users')
    .select('id, email, first_name, status')
    .eq('email', email.toLowerCase())
    .maybeSingle();

  // Always return success to avoid email enumeration
  if (!user || user.status !== 'active') {
    return res.json({ success: true });
  }

  const token   = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour

  await supabase.from('users').update({
    reset_token:         token,
    reset_token_expires: expires,
    updated_at:          new Date().toISOString(),
  }).eq('id', user.id);

  await sendPasswordResetEmail(user.email, token);
  console.log(`🔑  Password reset requested: ${email}`);
  res.json({ success: true });
});

// Reset password — validate token and set new password
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and password required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const { data: user } = await supabase.from('users')
    .select('id, email, reset_token, reset_token_expires')
    .eq('reset_token', token)
    .maybeSingle();

  if (!user) return res.status(400).json({ error: 'Invalid or expired reset link.' });
  if (new Date(user.reset_token_expires) < new Date()) {
    return res.status(400).json({ error: 'This reset link has expired. Please request a new one.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  await supabase.from('users').update({
    password_hash:       passwordHash,
    reset_token:         null,
    reset_token_expires: null,
    updated_at:          new Date().toISOString(),
  }).eq('id', user.id);

  console.log(`✅  Password reset: ${user.email}`);
  res.json({ success: true });
});

// Get current user
app.get('/api/auth/me', requireAuth, async (req, res) => {
  const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).maybeSingle();
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(sanitizeUser(user));
});

// ─────────────────────────────────────────────────────────────────
// USERS
// ─────────────────────────────────────────────────────────────────
app.get('/api/users', requireAuth, async (req, res) => {
  let query = supabase.from('users').select('*').order('created_at');

  if (req.user.role === 'advisor') {
    query = query.eq('role', 'user').eq('advisor_id', req.user.id);
  } else if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data.map(sanitizeUser));
});

app.put('/api/users/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  if (req.user.role !== 'admin' && req.user.id !== id) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const fieldMap = {
    firstName: 'first_name', lastName: 'last_name', company: 'company',
    preferredName: 'preferred_name', advisorId: 'advisor_id',
    plan: 'plan', status: 'status', role: 'role',
  };

  const updates = { updated_at: new Date().toISOString() };
  for (const [clientKey, dbKey] of Object.entries(fieldMap)) {
    if (req.body[clientKey] !== undefined) updates[dbKey] = req.body[clientKey];
  }

  const { data, error } = await supabase.from('users').update(updates).eq('id', id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(sanitizeUser(data));
});

// ─────────────────────────────────────────────────────────────────
// PROPERTIES
// ─────────────────────────────────────────────────────────────────
app.get('/api/data/properties/:userId', requireAuth, async (req, res) => {
  const { userId } = req.params;
  if (req.user.role === 'user' && req.user.id !== userId) return res.status(403).json({ error: 'Forbidden' });

  const { data, error } = await supabase.from('properties').select('*').eq('user_id', userId).order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data.map(dbPropToClient));
});

app.put('/api/data/properties/:userId', requireAuth, async (req, res) => {
  const { userId } = req.params;
  if (req.user.role !== 'admin' && req.user.id !== userId) return res.status(403).json({ error: 'Forbidden' });

  const properties = req.body;
  await supabase.from('properties').delete().eq('user_id', userId);

  if (properties.length > 0) {
    const rows = properties.map(p => clientPropToDb(p, userId));
    const { error } = await supabase.from('properties').insert(rows);
    if (error) return res.status(500).json({ error: error.message });
  }

  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────
// INCOME LOG
// ─────────────────────────────────────────────────────────────────
app.get('/api/data/income/:userId', requireAuth, async (req, res) => {
  const { userId } = req.params;
  if (req.user.role === 'user' && req.user.id !== userId) return res.status(403).json({ error: 'Forbidden' });

  const { data, error } = await supabase.from('income_log').select('*').eq('user_id', userId);
  if (error) return res.status(500).json({ error: error.message });

  const grouped = {};
  data.forEach(e => {
    if (!grouped[e.property_id]) grouped[e.property_id] = [];
    grouped[e.property_id].push({ id: e.id, date: e.date, type: e.type, description: e.description, amount: e.amount });
  });
  res.json(grouped);
});

app.put('/api/data/income/:userId/:propId', requireAuth, async (req, res) => {
  const { userId, propId } = req.params;
  if (req.user.role !== 'admin' && req.user.id !== userId) return res.status(403).json({ error: 'Forbidden' });

  const entries = req.body;
  await supabase.from('income_log').delete().eq('user_id', userId).eq('property_id', propId);

  if (entries.length > 0) {
    const rows = entries.map(e => ({
      id: e.id, property_id: propId, user_id: userId,
      date: e.date, type: e.type, description: e.description, amount: e.amount,
      created_at: new Date().toISOString(),
    }));
    const { error } = await supabase.from('income_log').insert(rows);
    if (error) return res.status(500).json({ error: error.message });
  }

  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────
// EXPENSES
// ─────────────────────────────────────────────────────────────────
app.get('/api/data/expenses/:userId', requireAuth, async (req, res) => {
  const { userId } = req.params;
  if (req.user.role === 'user' && req.user.id !== userId) return res.status(403).json({ error: 'Forbidden' });

  const { data, error } = await supabase.from('expenses').select('*').eq('user_id', userId);
  if (error) return res.status(500).json({ error: error.message });

  const grouped = {};
  data.forEach(e => {
    if (!grouped[e.property_id]) grouped[e.property_id] = [];
    grouped[e.property_id].push({ id: e.id, date: e.date, category: e.category, description: e.description, amount: e.amount });
  });
  res.json(grouped);
});

app.put('/api/data/expenses/:userId/:propId', requireAuth, async (req, res) => {
  const { userId, propId } = req.params;
  if (req.user.role !== 'admin' && req.user.id !== userId) return res.status(403).json({ error: 'Forbidden' });

  const entries = req.body;
  await supabase.from('expenses').delete().eq('user_id', userId).eq('property_id', propId);

  if (entries.length > 0) {
    const rows = entries.map(e => ({
      id: e.id, property_id: propId, user_id: userId,
      date: e.date, category: e.category, description: e.description, amount: e.amount,
      created_at: new Date().toISOString(),
    }));
    const { error } = await supabase.from('expenses').insert(rows);
    if (error) return res.status(500).json({ error: error.message });
  }

  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────
// MESSAGES
// ─────────────────────────────────────────────────────────────────
app.get('/api/messages/:userId', requireAuth, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

  const { data, error } = await supabase.from('messages').select('*')
    .or(`from_id.eq.${userId},to_id.eq.${userId}`)
    .order('ts');
  if (error) return res.status(500).json({ error: error.message });

  res.json(data.map(m => ({ id: m.id, from: m.from_id, to: m.to_id, body: m.body, ts: m.ts, read: m.read })));
});

app.post('/api/messages', requireAuth, async (req, res) => {
  const { id, to, body } = req.body;
  if (!to || !body) return res.status(400).json({ error: 'to and body required' });

  const { error } = await supabase.from('messages').insert({
    id:      id || ('msg_' + Date.now()),
    from_id: req.user.id,
    to_id:   to,
    body,
    ts:      new Date().toISOString(),
    read:    false,
  });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.put('/api/messages/read', requireAuth, async (req, res) => {
  const { fromId } = req.body;
  await supabase.from('messages').update({ read: true })
    .eq('from_id', fromId).eq('to_id', req.user.id);
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────
// BROADCASTS
// ─────────────────────────────────────────────────────────────────
app.get('/api/broadcasts', async (req, res) => {
  const { data, error } = await supabase.from('broadcasts').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data.map(b => ({ id: b.id, message: b.message, date: b.date, active: b.active, createdAt: b.created_at })));
});

app.post('/api/broadcasts', requireAdmin, async (req, res) => {
  const { id, message, date, active } = req.body;
  const { data, error } = await supabase.from('broadcasts').insert({
    id:        id || ('bcast_' + Date.now()),
    message,   date,
    active:    !!active,
    posted_by: req.user.id,
    created_at: new Date().toISOString(),
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ id: data.id, message: data.message, date: data.date, active: data.active, createdAt: data.created_at });
});

app.put('/api/broadcasts/:id', requireAdmin, async (req, res) => {
  const updates = {};
  if (req.body.active  !== undefined) updates.active  = req.body.active;
  if (req.body.message !== undefined) updates.message = req.body.message;
  if (req.body.date    !== undefined) updates.date    = req.body.date;
  const { error } = await supabase.from('broadcasts').update(updates).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.delete('/api/broadcasts/:id', requireAdmin, async (req, res) => {
  await supabase.from('broadcasts').delete().eq('id', req.params.id);
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────
// INVITES
// ─────────────────────────────────────────────────────────────────
app.get('/api/invites', requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('invites').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data.map(i => ({
    id: i.id, code: i.code, advisorName: i.advisor_name, advisorEmail: i.advisor_email,
    status: i.status, usedBy: i.used_by, usedAt: i.used_at, createdAt: i.created_at,
  })));
});

app.post('/api/invites', requireAdmin, async (req, res) => {
  const { id, code, advisorName, advisorEmail } = req.body;
  const { data, error } = await supabase.from('invites').insert({
    id:            id || ('inv_' + Date.now()),
    code,
    advisor_name:  advisorName,
    advisor_email: advisorEmail,
    status:        'pending',
    created_at:    new Date().toISOString(),
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ id: data.id, code: data.code, advisorName: data.advisor_name, advisorEmail: data.advisor_email, status: data.status, createdAt: data.created_at });
});

// ─────────────────────────────────────────────────────────────────
// STRIPE
// ─────────────────────────────────────────────────────────────────
app.post('/api/create-checkout-session', async (req, res) => {
  const { userId, plan, email, firstName, lastName } = req.body;

  if (!userId || !plan) return res.status(400).json({ error: 'userId and plan are required.' });
  if (!PLAN_PRICES[plan]) return res.status(400).json({ error: `Unknown plan: ${plan}` });
  if (!process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY.startsWith('sk_test_YOUR')) {
    return res.status(503).json({ error: 'Stripe is not configured yet.' });
  }

  const appUrl = process.env.APP_URL || `http://localhost:${PORT}`;
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode:                 'subscription',
      customer_email:       email,
      line_items:           [{ price: PLAN_PRICES[plan], quantity: 1 }],
      metadata:             { userId, plan, firstName, lastName },
      subscription_data:    { metadata: { userId, plan } },
      success_url: `${appUrl}/property-tracker.html?payment=success&plan=${plan}&userId=${encodeURIComponent(userId)}`,
      cancel_url:  `${appUrl}/property-tracker.html?payment=cancelled`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/plan/:userId', async (req, res) => {
  const { data } = await supabase.from('users').select('plan, updated_at').eq('id', req.params.userId).maybeSingle();
  res.json({ plan: data?.plan || null, updatedAt: data?.updated_at || null });
});

app.post('/api/admin/set-plan', async (req, res) => {
  const { userId, plan, adminKey } = req.body;
  if (!adminKey || adminKey !== process.env.ADMIN_KEY) return res.status(403).json({ error: 'Unauthorized' });
  if (!['free', 'investor', 'portfolio'].includes(plan)) return res.status(400).json({ error: 'Invalid plan' });
  await supabase.from('users').update({ plan, updated_at: new Date().toISOString() }).eq('id', userId);
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────
// Admin — Restart Server
// ─────────────────────────────────────────────────────────────────
// Test email
app.post('/api/admin/test-email', requireAdmin, async (req, res) => {
  const { to } = req.body;
  if (!to) return res.status(400).json({ error: 'Recipient email required.' });
  try {
    await sendEmail({
      to,
      subject: `${APP_NAME} — Test Email`,
      html:    `<p>This is a test email from <strong>${APP_NAME}</strong>. If you're reading this, email delivery is working correctly.</p>`,
    });
    res.json({ success: true, message: `Test email sent to ${to}` });
  } catch (err) {
    console.error('Test email error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/restart', requireAdmin, async (req, res) => {
  const apiKey    = process.env.RENDER_API_KEY;
  const serviceId = process.env.RENDER_SERVICE_ID;
  if (!apiKey || !serviceId) return res.status(500).json({ error: 'Render credentials not configured' });

  const r = await fetch(`https://api.render.com/v1/services/${serviceId}/deploys`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ clearCache: 'do_not_clear' }),
  });
  const data = await r.json();
  if (!r.ok) return res.status(500).json({ error: data.message || 'Render API error' });
  res.json({ success: true, deployId: data.id });
});

// ─────────────────────────────────────────────────────────────────
// Admin Stats
// ─────────────────────────────────────────────────────────────────
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const t0 = Date.now();
  const [
    { data: users },
    { data: properties },
    { count: msgCount },
    { count: incomeCount },
    { count: expenseCount },
    { data: usersWithIncome },
    { data: usersWithExpenses },
  ] = await Promise.all([
    supabase.from('users').select('id, role, status, plan, advisor_id, created_at, first_name, last_name, email, company, last_login').order('created_at', { ascending: false }),
    supabase.from('properties').select('id, user_id, value, loan, state, type'),
    supabase.from('messages').select('*', { count: 'exact', head: true }),
    supabase.from('income_log').select('*', { count: 'exact', head: true }),
    supabase.from('expenses').select('*', { count: 'exact', head: true }),
    supabase.from('income_log').select('user_id'),
    supabase.from('expenses').select('user_id'),
  ]);

  const dbMs = Date.now() - t0;

  // ── Core property aggregates ──────────────────────────────────
  const totalValue  = (properties || []).reduce((s, p) => s + (p.value || 0), 0);
  const totalLoan   = (properties || []).reduce((s, p) => s + (p.loan  || 0), 0);

  // ── Property count per user ───────────────────────────────────
  const propCountByUser = {};
  (properties || []).forEach(p => {
    propCountByUser[p.user_id] = (propCountByUser[p.user_id] || 0) + 1;
  });

  // ── Portfolio value per user ──────────────────────────────────
  const valueByUser = {};
  (properties || []).forEach(p => {
    valueByUser[p.user_id] = (valueByUser[p.user_id] || 0) + (p.value || 0);
  });

  // ── Users with activity ───────────────────────────────────────
  const usersWithIncomeSet    = new Set((usersWithIncome   || []).map(r => r.user_id));
  const usersWithExpensesSet  = new Set((usersWithExpenses || []).map(r => r.user_id));

  // ── Regular (non-admin, non-advisor) users ────────────────────
  const clientUsers = (users || []).filter(u => u.role === 'user');

  // ── Property count segments ───────────────────────────────────
  const byPropertyCount = {
    none:     clientUsers.filter(u => !propCountByUser[u.id]).length,
    one:      clientUsers.filter(u => propCountByUser[u.id] === 1).length,
    twoThree: clientUsers.filter(u => propCountByUser[u.id] >= 2 && propCountByUser[u.id] <= 3).length,
    fourPlus: clientUsers.filter(u => (propCountByUser[u.id] || 0) >= 4).length,
  };

  // ── Geographic distribution (by state on properties) ─────────
  const stateCount = {};
  (properties || []).forEach(p => {
    const s = (p.state || '').trim() || 'Unknown';
    stateCount[s] = (stateCount[s] || 0) + 1;
  });
  const byState = Object.entries(stateCount)
    .map(([state, count]) => ({ state, count }))
    .sort((a, b) => b.count - a.count);

  // ── Property type distribution ────────────────────────────────
  const typeCount = {};
  (properties || []).forEach(p => {
    const t = (p.type || 'Unknown');
    typeCount[t] = (typeCount[t] || 0) + 1;
  });
  const byPropertyType = Object.entries(typeCount)
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);

  // ── Portfolio value buckets (per user total) ──────────────────
  const allUserValues = clientUsers.map(u => valueByUser[u.id] || 0);
  const byPortfolioValue = {
    under500k:  allUserValues.filter(v => v > 0 && v <  500000).length,
    f500kTo1m:  allUserValues.filter(v => v >= 500000  && v < 1000000).length,
    f1mTo2m:    allUserValues.filter(v => v >= 1000000 && v < 2000000).length,
    over2m:     allUserValues.filter(v => v >= 2000000).length,
  };

  // ── Upgrade opportunity cohorts ───────────────────────────────
  const upgradeOpportunities = {
    // Free users who have ≥1 property → ready for Starter pitch
    freeWithProperties:    clientUsers.filter(u => u.plan === 'free' && (propCountByUser[u.id] || 0) > 0).length,
    // Starter/investor users with 4+ properties → ready for Portfolio pitch
    starterReadyForPortfolio: clientUsers.filter(u => u.plan === 'investor' && (propCountByUser[u.id] || 0) >= 4).length,
    // Users without an advisor assigned
    withoutAdvisor:        clientUsers.filter(u => !u.advisor_id).length,
    // Registered but never added a property (dormant)
    neverAddedProperty:    clientUsers.filter(u => !(propCountByUser[u.id])).length,
    // Have properties but never logged any income or expenses
    noTransactions:        clientUsers.filter(u =>
      (propCountByUser[u.id] || 0) > 0 &&
      !usersWithIncomeSet.has(u.id) &&
      !usersWithExpensesSet.has(u.id)
    ).length,
  };

  res.json({
    server: {
      uptime:  Math.floor(process.uptime()),
      memory:  Math.round(process.memoryUsage().rss / 1024 / 1024),
      node:    process.version,
      env:     process.env.NODE_ENV || 'development',
      dbPingMs: dbMs,
    },
    users: {
      total:    (users || []).length,
      active:   (users || []).filter(u => u.status === 'active').length,
      admins:   (users || []).filter(u => u.role === 'admin').length,
      advisors: (users || []).filter(u => u.role === 'advisor').length,
      free:     (users || []).filter(u => u.plan === 'free').length,
      investor: (users || []).filter(u => u.plan === 'investor').length,
      portfolio:(users || []).filter(u => u.plan === 'portfolio').length,
      recent:   (users || []).slice(0, 5),
    },
    properties: {
      total:      (properties || []).length,
      totalValue,
      totalLoan,
      totalEquity: totalValue - totalLoan,
    },
    activity: {
      messages:       msgCount || 0,
      incomeRecords:  incomeCount || 0,
      expenseRecords: expenseCount || 0,
    },
    segments: {
      byPropertyCount,
      byState,
      byPropertyType,
      byPortfolioValue,
      upgradeOpportunities,
    },
  });
});

// ─────────────────────────────────────────────────────────────────
// PLATFORM CATEGORIES
// ─────────────────────────────────────────────────────────────────

// GET /api/categories — public, no auth required (needed at app startup)
app.get('/api/categories', async (req, res) => {
  const { data, error } = await supabase
    .from('platform_categories')
    .select('*')
    .order('kind')
    .order('label');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data.map(c => ({
    id:         c.id,
    kind:       c.kind,
    value:      c.value,
    label:      c.label,
    cls:        c.cls,
    activeFrom: c.active_from,
    activeTo:   c.active_to,
    createdAt:  c.created_at,
    updatedAt:  c.updated_at,
  })));
});

// POST /api/categories — admin only, create a new category
app.post('/api/categories', requireAdmin, async (req, res) => {
  const { kind, value, label, cls, activeFrom, activeTo } = req.body;
  if (!kind || !value || !label) return res.status(400).json({ error: 'kind, value and label are required' });
  if (!['expense', 'income'].includes(kind)) return res.status(400).json({ error: 'kind must be expense or income' });

  const { data, error } = await supabase.from('platform_categories').insert({
    id:          'cat_' + Date.now(),
    kind,
    value:       value.toLowerCase().replace(/\s+/g, '_'),
    label,
    cls:         cls || ('cat-' + value.toLowerCase().replace(/\s+/g, '-')),
    active_from: activeFrom || null,
    active_to:   activeTo   || null,
    created_at:  new Date().toISOString(),
    updated_at:  new Date().toISOString(),
  }).select().single();

  if (error) return res.status(500).json({ error: error.message });
  res.json({ id: data.id, kind: data.kind, value: data.value, label: data.label, cls: data.cls, activeFrom: data.active_from, activeTo: data.active_to, createdAt: data.created_at });
});

// PATCH /api/categories/:id — admin only, update label or retire (set activeTo)
app.patch('/api/categories/:id', requireAdmin, async (req, res) => {
  const updates = { updated_at: new Date().toISOString() };
  if (req.body.label      !== undefined) updates.label      = req.body.label;
  if (req.body.cls        !== undefined) updates.cls        = req.body.cls;
  if (req.body.activeFrom !== undefined) updates.active_from = req.body.activeFrom;
  if (req.body.activeTo   !== undefined) updates.active_to   = req.body.activeTo;

  const { error } = await supabase.from('platform_categories').update(updates).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// DELETE /api/categories/:id — admin only
app.delete('/api/categories/:id', requireAdmin, async (req, res) => {
  await supabase.from('platform_categories').delete().eq('id', req.params.id);
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────
// MARKETING CAMPAIGNS
// ─────────────────────────────────────────────────────────────────

// Wrap campaign body in a branded email shell
function wrapMarketingEmail(bodyHtml) {
  return `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1a1a1a;">
    <div style="background:#1E3A5F;padding:28px 32px;border-radius:8px 8px 0 0;">
      <h1 style="color:#fff;margin:0;font-size:22px;">${APP_NAME}</h1>
    </div>
    <div style="background:#fff;padding:32px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px;">
      ${bodyHtml}
      <hr style="border:none;border-top:1px solid #e5e7eb;margin:28px 0 16px;">
      <p style="color:#9ca3af;font-size:11px;margin:0;">You're receiving this because you have an account with ${APP_NAME}.
        <a href="${APP_URL}" style="color:#1E3A5F;">Visit ${APP_NAME}</a></p>
    </div>
  </div>`;
}

// Helper: resolve a segment config into a list of recipient users
async function getSegmentRecipients(segment) {
  let query = supabase.from('users')
    .select('id, email, first_name, last_name, plan, last_login')
    .neq('role', 'admin')
    .eq('status', 'active');

  // Filter by plan (empty array = all plans)
  if (segment.plans && segment.plans.length > 0) {
    query = query.in('plan', segment.plans);
  }

  // Filter by activity
  if (segment.activity === 'active' || segment.activity === 'inactive') {
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    if (segment.activity === 'active') {
      query = query.gte('last_login', cutoff);
    } else {
      // inactive: last_login older than 30 days OR never logged in
      query = query.or(`last_login.lt.${cutoff},last_login.is.null`);
    }
  }

  const { data: users, error } = await query;
  if (error) throw error;
  if (!users || !users.length) return [];

  // Filter by property count (requires a secondary query)
  if (!segment.propCount || segment.propCount === 'all') return users;

  const { data: props } = await supabase
    .from('properties').select('user_id')
    .in('user_id', users.map(u => u.id));

  const countMap = {};
  (props || []).forEach(p => { countMap[p.user_id] = (countMap[p.user_id] || 0) + 1; });

  return users.filter(u => {
    const n = countMap[u.id] || 0;
    if (segment.propCount === 'none') return n === 0;
    if (segment.propCount === 'some') return n >= 1 && n <= 2;
    if (segment.propCount === 'many') return n >= 3;
    return true;
  });
}

// GET /api/marketing/campaigns — list all (admin only)
app.get('/api/marketing/campaigns', requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('marketing_campaigns')
    .select('id, title, subject, segment, status, recipient_count, sent_at, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// POST /api/marketing/campaigns — create draft
app.post('/api/marketing/campaigns', requireAdmin, async (req, res) => {
  const { title, subject, bodyHtml, segment } = req.body;
  if (!title || !subject) return res.status(400).json({ error: 'Title and subject are required.' });
  const { data, error } = await supabase.from('marketing_campaigns').insert({
    title, subject,
    body_html:  bodyHtml || '',
    segment:    segment  || { plans: [], activity: 'all', propCount: 'all' },
    status:     'draft',
    created_by: req.user.id,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// PUT /api/marketing/campaigns/:id — update draft
app.put('/api/marketing/campaigns/:id', requireAdmin, async (req, res) => {
  const { title, subject, bodyHtml, segment } = req.body;
  const updates = { updated_at: new Date().toISOString() };
  if (title     !== undefined) updates.title     = title;
  if (subject   !== undefined) updates.subject   = subject;
  if (bodyHtml  !== undefined) updates.body_html = bodyHtml;
  if (segment   !== undefined) updates.segment   = segment;
  const { error } = await supabase.from('marketing_campaigns').update(updates).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// DELETE /api/marketing/campaigns/:id — drafts only
app.delete('/api/marketing/campaigns/:id', requireAdmin, async (req, res) => {
  await supabase.from('marketing_campaigns').delete().eq('id', req.params.id).eq('status', 'draft');
  res.json({ success: true });
});

// POST /api/marketing/campaigns/preview — resolve segment to recipient list
app.post('/api/marketing/campaigns/preview', requireAdmin, async (req, res) => {
  try {
    const recipients = await getSegmentRecipients(req.body.segment || {});
    res.json({
      count: recipients.length,
      recipients: recipients.map(u => ({
        id: u.id, email: u.email, plan: u.plan,
        name: `${u.first_name || ''} ${u.last_name || ''}`.trim(),
      })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/marketing/campaigns/:id/send — send campaign to segment
app.post('/api/marketing/campaigns/:id/send', requireAdmin, async (req, res) => {
  const { data: campaign, error: camErr } = await supabase
    .from('marketing_campaigns').select('*').eq('id', req.params.id).single();
  if (camErr || !campaign) return res.status(404).json({ error: 'Campaign not found.' });
  if (campaign.status === 'sent') return res.status(400).json({ error: 'Campaign already sent.' });

  try {
    const recipients = await getSegmentRecipients(campaign.segment || {});
    if (!recipients.length) return res.status(400).json({ error: 'No recipients match the selected segment.' });

    let sent = 0, failed = 0;
    for (const user of recipients) {
      try {
        // Allow {{name}} personalisation token in body
        const personalised = (campaign.body_html || '').replace(/\{\{name\}\}/g, user.first_name || 'there');
        await sendEmail({
          to:      user.email,
          subject: campaign.subject,
          html:    wrapMarketingEmail(personalised),
        });
        sent++;
      } catch (e) {
        console.error(`Marketing send failed for ${user.email}:`, e.message);
        failed++;
      }
    }

    await supabase.from('marketing_campaigns').update({
      status:          'sent',
      recipient_count: sent,
      sent_at:         new Date().toISOString(),
      updated_at:      new Date().toISOString(),
    }).eq('id', req.params.id);

    console.log(`📧  Campaign "${campaign.title}" sent to ${sent} recipients (${failed} failed)`);
    res.json({ success: true, sent, failed });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────
// AGENT AI RULE MANAGEMENT
// ─────────────────────────────────────────────────────────────────

// POST /api/ai-rules/suggestions — log an unmatched customer query
app.post('/api/ai-rules/suggestions', requireAuth, async (req, res) => {
  const { query, userId } = req.body;
  if (!query || query.length < 3) return res.json({ ok: true }); // ignore trivial queries

  const normalised = query.trim().toLowerCase().slice(0, 300);

  // Check if this exact query already exists
  const { data: existing } = await supabase
    .from('ai_rule_suggestions')
    .select('id, asked_count, user_ids')
    .eq('query', normalised)
    .eq('status', 'pending')
    .maybeSingle();

  if (existing) {
    // Increment count and add user if not already in list
    const userIds = existing.user_ids || [];
    if (!userIds.includes(userId)) userIds.push(userId);
    await supabase.from('ai_rule_suggestions').update({
      asked_count:  existing.asked_count + 1,
      user_ids:     userIds,
      last_asked_at: new Date().toISOString(),
    }).eq('id', existing.id);
  } else {
    await supabase.from('ai_rule_suggestions').insert({
      id:            require('crypto').randomUUID(),
      query:         normalised,
      user_ids:      userId ? [userId] : [],
      asked_count:   1,
      first_asked_at: new Date().toISOString(),
      last_asked_at:  new Date().toISOString(),
      status:        'pending',
    });
  }
  res.json({ ok: true });
});

// GET /api/ai-rules/suggestions — list pending suggestions (admin)
app.get('/api/ai-rules/suggestions', requireAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('ai_rule_suggestions')
    .select('*')
    .eq('status', 'pending')
    .order('asked_count', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// DELETE /api/ai-rules/suggestions/:id — dismiss suggestion (admin)
app.delete('/api/ai-rules/suggestions/:id', requireAdmin, async (req, res) => {
  await supabase.from('ai_rule_suggestions')
    .update({ status: 'dismissed' })
    .eq('id', req.params.id);
  res.json({ success: true });
});

// GET /api/ai-rules — list active custom rules (all authenticated users, for assistant)
app.get('/api/ai-rules', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('ai_rules')
    .select('id, name, pattern, topic, data_query, custom_response, active, created_at')
    .eq('active', true)
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// POST /api/ai-rules — create new rule and mark suggestion as approved (admin)
app.post('/api/ai-rules', requireAdmin, async (req, res) => {
  const { name, pattern, dataQuery, customResponse, suggestionId } = req.body;
  if (!name || !pattern) return res.status(400).json({ error: 'Name and pattern are required.' });

  const id = require('crypto').randomUUID();
  const { error } = await supabase.from('ai_rules').insert({
    id,
    name,
    pattern,
    topic:           name,
    data_query:      dataQuery || null,
    custom_response: customResponse || null,
    active:          true,
    created_by:      req.user.id,
    created_at:      new Date().toISOString(),
    updated_at:      new Date().toISOString(),
  });
  if (error) return res.status(500).json({ error: error.message });

  // Mark the originating suggestion as approved
  if (suggestionId) {
    await supabase.from('ai_rule_suggestions')
      .update({ status: 'approved' })
      .eq('id', suggestionId);
  }

  res.json({ success: true, id });
});

// PUT /api/ai-rules/:id — update rule (admin)
app.put('/api/ai-rules/:id', requireAdmin, async (req, res) => {
  const { name, pattern, dataQuery, customResponse } = req.body;
  const updates = { updated_at: new Date().toISOString() };
  if (name           !== undefined) updates.name            = name;
  if (pattern        !== undefined) updates.pattern         = pattern;
  if (dataQuery      !== undefined) updates.data_query      = dataQuery || null;
  if (customResponse !== undefined) updates.custom_response = customResponse || null;
  const { error } = await supabase.from('ai_rules').update(updates).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// DELETE /api/ai-rules/:id — delete rule (admin)
app.delete('/api/ai-rules/:id', requireAdmin, async (req, res) => {
  await supabase.from('ai_rules').delete().eq('id', req.params.id);
  res.json({ success: true });
});

// GET /api/marketing/users/:userId/campaigns — campaigns sent to a specific user
app.get('/api/marketing/users/:userId/campaigns', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    // Get the user to know their plan, last_login
    const { data: user, error: uErr } = await supabase
      .from('users').select('id, email, first_name, last_name, plan, last_login, status')
      .eq('id', userId).single();
    if (uErr || !user) return res.status(404).json({ error: 'User not found' });

    // Get their property count
    const { data: props } = await supabase
      .from('properties').select('id').eq('user_id', userId);
    const propCount = (props || []).length;

    // Get all sent campaigns
    const { data: campaigns } = await supabase
      .from('marketing_campaigns')
      .select('id, title, subject, segment, status, recipient_count, sent_at, created_at')
      .eq('status', 'sent')
      .order('sent_at', { ascending: false });

    // Check which campaigns this user would have qualified for
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const isActive = user.last_login && user.last_login >= cutoff;

    const receivedCampaigns = (campaigns || []).filter(c => {
      const seg = c.segment || {};

      // Plan check
      if (seg.plans && seg.plans.length > 0 && !seg.plans.includes(user.plan || 'free')) return false;

      // Activity check
      if (seg.activity === 'active' && !isActive) return false;
      if (seg.activity === 'inactive' && isActive) return false;

      // Property count check
      if (seg.propCount === 'none' && propCount > 0) return false;
      if (seg.propCount === 'some' && (propCount < 1 || propCount > 2)) return false;
      if (seg.propCount === 'many' && propCount < 3) return false;

      return true;
    });

    // Determine which segments the user currently qualifies for (for the 360 view)
    const segmentMembership = [];
    if (user.plan === 'free') segmentMembership.push('Free Plan');
    if (user.plan === 'investor') segmentMembership.push('Investor Plan');
    if (user.plan === 'portfolio') segmentMembership.push('Portfolio Plan');
    if (isActive) segmentMembership.push('Active (last 30 days)');
    else segmentMembership.push('Inactive (30+ days)');
    if (propCount === 0) segmentMembership.push('No properties');
    else if (propCount <= 2) segmentMembership.push(`${propCount} propert${propCount === 1 ? 'y' : 'ies'}`);
    else segmentMembership.push(`${propCount} properties (power user)`);

    res.json({
      campaigns: receivedCampaigns,
      segmentMembership,
      lastContacted: receivedCampaigns.length > 0 ? receivedCampaigns[0].sent_at : null,
      propertyCount: propCount,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────
// CRM
// ─────────────────────────────────────────────────────────────────

// GET /api/crm/customers — list all customers with CRM data (admin only)
app.get('/api/crm/customers', requireAdmin, async (req, res) => {
  try {
    const { data: users } = await supabase
      .from('users')
      .select('id, first_name, last_name, email, company, plan, status, role, created_at, last_login, stripe_customer_id, stripe_subscription_id')
      .order('created_at', { ascending: false });

    const { data: crmRows } = await supabase.from('crm_customers').select('*');
    const { data: noteCounts } = await supabase.from('crm_notes').select('user_id');

    const crmMap   = {};
    (crmRows || []).forEach(r => { crmMap[r.user_id] = r; });
    const noteMap  = {};
    (noteCounts || []).forEach(n => { noteMap[n.user_id] = (noteMap[n.user_id] || 0) + 1; });

    const result = (users || []).filter(u => u.role !== 'admin').map(u => {
      const crm = crmMap[u.id] || {};
      return {
        id:              u.id,
        firstName:       u.first_name,
        lastName:        u.last_name,
        email:           u.email,
        company:         u.company,
        plan:            u.plan || 'free',
        status:          u.status,
        createdAt:       u.created_at,
        lastLogin:       u.last_login,
        stripeCustomerId: u.stripe_customer_id || crm.stripe_customer_id,
        stripeStatus:    crm.stripe_status || null,
        lastPaymentAt:   crm.last_payment_at || null,
        lastPaymentAmount: crm.last_payment_amount || null,
        nextBillingAt:   crm.next_billing_at || null,
        cardLast4:       crm.card_last4 || null,
        cardBrand:       crm.card_brand || null,
        marketingOptIn:  crm.marketing_opt_in || false,
        noteCount:       noteMap[u.id] || 0,
      };
    });
    res.json(result);
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/crm/customers/:userId — single customer full detail
app.get('/api/crm/customers/:userId', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { data: user } = await supabase.from('users')
      .select('*').eq('id', userId).single();
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { data: crm } = await supabase.from('crm_customers')
      .select('*').eq('user_id', userId).maybeSingle();

    const { data: notes } = await supabase.from('crm_notes')
      .select('*, author:created_by(first_name, last_name)')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    const { data: props } = await supabase.from('properties')
      .select('id').eq('user_id', userId);

    // Fetch live Stripe data if customer ID exists
    let stripeData = null;
    const stripeCustomerId = user.stripe_customer_id || crm?.stripe_customer_id;
    if (stripeCustomerId) {
      try {
        const [customer, subscriptions, invoices] = await Promise.all([
          stripe.customers.retrieve(stripeCustomerId),
          stripe.subscriptions.list({ customer: stripeCustomerId, limit: 5 }),
          stripe.invoices.list({ customer: stripeCustomerId, limit: 10 }),
        ]);
        const sub = subscriptions.data[0];
        stripeData = {
          customer,
          subscription: sub || null,
          invoices: invoices.data.map(inv => ({
            id:         inv.id,
            number:     inv.number,
            status:     inv.status,
            amount:     inv.amount_paid,
            currency:   inv.currency,
            created:    new Date(inv.created * 1000).toISOString(),
            pdf:        inv.invoice_pdf,
            hostedUrl:  inv.hosted_invoice_url,
          })),
          paymentMethod: sub?.default_payment_method
            ? await stripe.paymentMethods.retrieve(sub.default_payment_method).catch(() => null)
            : null,
        };
      } catch(e) { stripeData = { error: e.message }; }
    }

    res.json({
      id:          user.id,
      firstName:   user.first_name,
      lastName:    user.last_name,
      email:       user.email,
      company:     user.company,
      phone:       user.phone || null,
      plan:        user.plan || 'free',
      status:      user.status,
      role:        user.role,
      createdAt:   user.created_at,
      lastLogin:   user.last_login,
      propertyCount: (props || []).length,
      crm:         crm || {},
      stripe:      stripeData,
      notes:       (notes || []).map(n => ({
        id:        n.id,
        note:      n.note,
        createdAt: n.created_at,
        author:    n.author ? `${n.author.first_name} ${n.author.last_name}` : 'Admin',
      })),
    });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/crm/customers/:userId/sync — force sync from Stripe
app.post('/api/crm/customers/:userId/sync', requireAdmin, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users')
      .select('id, stripe_customer_id').eq('id', req.params.userId).single();
    if (!user?.stripe_customer_id) return res.json({ synced: false, reason: 'No Stripe customer ID' });

    const [customer, subscriptions] = await Promise.all([
      stripe.customers.retrieve(user.stripe_customer_id),
      stripe.subscriptions.list({ customer: user.stripe_customer_id, limit: 1 }),
    ]);
    const sub = subscriptions.data[0];
    let cardBrand = null, cardLast4 = null, cardExpMonth = null, cardExpYear = null;
    if (sub?.default_payment_method) {
      const pm = await stripe.paymentMethods.retrieve(sub.default_payment_method).catch(() => null);
      if (pm?.card) { cardBrand = pm.card.brand; cardLast4 = pm.card.last4; cardExpMonth = pm.card.exp_month; cardExpYear = pm.card.exp_year; }
    }
    await syncCrmCustomer(user.id, {
      stripeCustomerId:    user.stripe_customer_id,
      stripeSubscriptionId: sub?.id,
      stripeStatus:        sub?.status || 'inactive',
      nextBillingAt:       sub?.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : null,
      trialEndsAt:         sub?.trial_end ? new Date(sub.trial_end * 1000).toISOString() : null,
      cardBrand, cardLast4, cardExpMonth, cardExpYear,
    });
    res.json({ synced: true });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/crm/customers/:userId — update marketing opt-in (admin)
app.patch('/api/crm/customers/:userId', requireAdmin, async (req, res) => {
  const { marketingOptIn } = req.body;
  await supabase.from('crm_customers').upsert({
    id: req.params.userId, user_id: req.params.userId,
    marketing_opt_in: marketingOptIn,
    updated_at: new Date().toISOString(),
  }, { onConflict: 'id' });
  res.json({ success: true });
});

// GET /api/crm/notes/:userId — get notes for a customer
app.get('/api/crm/notes/:userId', requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('crm_notes')
    .select('*').eq('user_id', req.params.userId).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// POST /api/crm/notes — add a note
app.post('/api/crm/notes', requireAdmin, async (req, res) => {
  const { userId, note } = req.body;
  if (!userId || !note) return res.status(400).json({ error: 'userId and note required' });
  const { data, error } = await supabase.from('crm_notes').insert({
    id: require('crypto').randomUUID(),
    user_id:    userId,
    note:       note.trim(),
    created_by: req.user.id,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// DELETE /api/crm/notes/:id — delete a note
app.delete('/api/crm/notes/:id', requireAdmin, async (req, res) => {
  await supabase.from('crm_notes').delete().eq('id', req.params.id);
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────
// Health
// ─────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status:   'ok',
    supabase: !!process.env.SUPABASE_URL,
    stripe:   !!process.env.STRIPE_SECRET_KEY && !process.env.STRIPE_SECRET_KEY.includes('YOUR'),
    version:  require('./package.json').version,
  });
});

app.listen(PORT, () => {
  console.log('\n╔══════════════════════════════════════════╗');
  console.log('║   Wealth Manager — API Server            ║');
  console.log('╠══════════════════════════════════════════╣');
  console.log(`║  App:      http://localhost:${PORT}/property-tracker.html`);
  console.log(`║  API:      http://localhost:${PORT}/api/health`);
  console.log(`║  Supabase: ${process.env.SUPABASE_URL ? '✓ connected' : '✗ not configured'}`);
  console.log('╚══════════════════════════════════════════╝\n');
});
