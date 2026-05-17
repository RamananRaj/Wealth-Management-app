require('dotenv').config();

const express  = require('express');
const cors     = require('cors');
const stripe   = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { createClient } = require('@supabase/supabase-js');
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Supabase (service-role key = full DB access, used only server-side)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-to-a-long-random-string';

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
        console.log(`✅  Plan upgraded: user ${userId} → ${plan}`);
      }
      break;
    }
    case 'customer.subscription.updated': {
      const sub = event.data.object;
      const priceId = sub.items.data[0]?.price?.id;
      const newPlan = Object.entries(PLAN_PRICES).find(([, pid]) => pid === priceId)?.[0];
      if (newPlan) {
        const { data: users } = await supabase.from('users').select('id').eq('stripe_customer_id', sub.customer);
        if (users?.length) {
          await supabase.from('users').update({ plan: newPlan, updated_at: new Date().toISOString() }).eq('id', users[0].id);
        }
      }
      break;
    }
    case 'customer.subscription.deleted': {
      const sub = event.data.object;
      const { data: users } = await supabase.from('users').select('id').eq('stripe_customer_id', sub.customer);
      if (users?.length) {
        await supabase.from('users').update({ plan: 'free', updated_at: new Date().toISOString() }).eq('id', users[0].id);
      }
      break;
    }
  }
  res.json({ received: true });
});

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

  await supabase.from('users').update({ updated_at: new Date().toISOString() }).eq('id', user.id);

  const token = jwt.sign(
    { id: user.id, role: user.role, plan: user.plan },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  console.log(`🔑  Login: ${email}`);
  res.json({ token, user: sanitizeUser(user) });
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
  ] = await Promise.all([
    supabase.from('users').select('id, role, status, plan, created_at, first_name, last_name, email').order('created_at', { ascending: false }),
    supabase.from('properties').select('id, user_id, value, loan'),
    supabase.from('messages').select('*', { count: 'exact', head: true }),
    supabase.from('income_log').select('*', { count: 'exact', head: true }),
    supabase.from('expenses').select('*', { count: 'exact', head: true }),
  ]);

  const dbMs = Date.now() - t0;
  const totalValue  = (properties || []).reduce((s, p) => s + (p.value || 0), 0);
  const totalLoan   = (properties || []).reduce((s, p) => s + (p.loan  || 0), 0);

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
      messages: msgCount || 0,
      incomeRecords: incomeCount || 0,
      expenseRecords: expenseCount || 0,
    },
  });
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
