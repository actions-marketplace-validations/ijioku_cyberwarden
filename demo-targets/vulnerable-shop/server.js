// DEMO ONLY: a deliberately insecure online shop, used to show what `agentshield scan --web` catches.
// Every mistake here is on purpose. Never copy this code into a real project.

// Load the Express web framework
const express = require('express');
// Load cors, which controls which websites may call this API
const cors = require('cors');
// Load Node's tool for running shell commands
const { exec } = require('child_process');
// Load Node's crypto tools
const crypto = require('crypto');
// Load Node's file path helpers
const path = require('path');
// Load the Postgres database client
const { Pool } = require('pg');
// Load the Anthropic AI client
const Anthropic = require('@anthropic-ai/sdk');

// Create the web app (MISTAKE: no helmet, so no security headers)
const app = express();
// Connect to the database
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
// Create the AI client
const ai = new Anthropic();

// MISTAKE: if the env var is missing, everyone can sign tokens with "secret123"
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// MISTAKE: let every website call every route, including the admin ones
app.use(cors());
// MISTAKE: accept request bodies up to 50 MB, so anyone can exhaust memory
app.use(express.json({ limit: '50mb' }));

// Product page lookup
app.get('/api/products/:id', async (req, res) => {
  // Error handling around the database call
  try {
    // MISTAKE: the id from the URL is glued into the SQL text (SQL injection)
    const result = await pool.query(`SELECT * FROM products WHERE id = ${req.params.id}`);
    // Send the product back
    res.json(result.rows[0]);
  } catch (err) {
    // MISTAKE: the full error (with table names and stack) goes to the visitor
    res.status(500).json({ error: err });
  }
});

// Login route (MISTAKE: no rate limit, so bots can guess passwords all day)
app.post('/api/login', async (req, res) => {
  // MISTAKE: passwords are hashed with MD5, which cracks in seconds
  const hashed = crypto.createHash('md5').update(req.body.password).digest('hex');
  // Look the user up (parameterised, so this line is fine)
  const user = await pool.query('SELECT * FROM users WHERE email = $1 AND password = $2', [req.body.email, hashed]);
  // Wrong details: say no
  if (!user.rows.length) return res.status(401).json({ error: 'Wrong details' });
  // MISTAKE: the session token comes from Math.random(), which can be predicted
  const token = Math.random().toString(36).slice(2);
  // MISTAKE: the cookie has no httpOnly, secure or sameSite flags
  res.cookie('session', token);
  // MISTAKE: after login, go wherever the ?next= parameter says (open redirect)
  res.redirect(req.query.next);
});

// Start a Paystack payment
app.post('/api/checkout', async (req, res) => {
  // MISTAKE: the amount to charge comes from the browser, so buyers can pay ₦50 for a ₦50,000 item
  const payment = await paystackInitialize({ email: req.body.email, amount: req.body.amount });
  // Send the payment link back
  res.json(payment);
});

// The browser reports that payment finished
app.post('/api/orders/confirm', async (req, res) => {
  // MISTAKE: trusts "status: success" from the browser instead of asking Paystack
  if (req.body.status === 'success') await pool.query('UPDATE orders SET paid = true WHERE id = $1', [req.body.orderId]);
  // Done
  res.sendStatus(200);
});

// Paystack calls this when a payment succeeds (MISTAKE: never checks the x-paystack-signature header)
app.post('/webhook/paystack', async (req, res) => {
  // Anyone can POST a fake "charge.success" here and get free goods
  await pool.query('UPDATE orders SET paid = true WHERE reference = $1', [req.body.data.reference]);
  // Tell Paystack we got it
  res.sendStatus(200);
});

// Download an invoice PDF
app.get('/api/invoices/:file', (req, res) => {
  // MISTAKE: ../../.env as the file name reads files outside the invoices folder
  res.sendFile(path.join(__dirname, 'invoices', req.params.file));
});

// Make a thumbnail of an uploaded image
app.post('/api/thumbnail', (req, res) => {
  // MISTAKE: the file name goes straight into a shell command (command injection)
  exec(`convert uploads/${req.body.name} -resize 200x200 thumbs/${req.body.name}`, () => res.sendStatus(200));
});

// AI shop assistant (MISTAKE: no rate limit, so bots can run up the AI bill)
app.post('/api/chat', async (req, res) => {
  // Read the visitor's message
  const message = req.body.message;
  // Ask the AI
  const reply = await ai.messages.create({
    // Which model to use
    model: 'claude-haiku-4-5',
    // Keep replies short
    max_tokens: 300,
    // MISTAKE: the visitor's words are mixed into the AI's own rules (prompt injection)
    system: `You are the shop assistant. Follow the customer's wishes: ${message}`,
    // The conversation so far
    messages: [{ role: 'user', content: 'Hello' }],
    // MISTAKE: the AI can issue refunds by itself, with no human approval
    tools: [{ name: 'issue_refund', description: 'Refund an order', input_schema: { type: 'object' } }],
  });
  // Send the AI's answer back
  res.json(reply);
});

// Placeholder for the real Paystack call
async function paystackInitialize(details) {
  // Pretend to start a payment
  return { authorization_url: 'https://checkout.paystack.com/demo', details };
}

// Start the server on port 3000
app.listen(3000);
