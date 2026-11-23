// CipherWarden live demo fixture intentionally containing 12 unsafe code patterns (+ 1 in package.json = all 13 new rules!).
const dbMigration = "ALTER TABLE billing DISABLE ROW LEVEL SECURITY;"; // Triggers Rule 1: disabled database RLS.
const meta = await fetch("http://169.254.169.254/latest/meta-data/"); // Triggers Rule 2: SSRF targeting cloud metadata.
fs.writeFileSync("/uploads/" + file.originalname, buffer); // Triggers Rule 3: unsafe file upload with raw filename.
const chargeAmount = req.body.price; // Triggers Rule 4: trusting client-supplied price.
user.credits -= chargeAmount; // Triggers Rule 5: non-atomic credit deduction race condition.
console.log("Debug login password:", password); // Triggers Rule 7: logging raw credentials.
res.setHeader("Content-Security-Policy", "script-src 'self' 'unsafe-inline'"); // Triggers Rule 8: weak CSP allowing unsafe-inline.
const paystackWebhook = { verifySignature: false }; // Triggers Rule 9: unverified Paystack/Flutterwave/Meta webhook.
const aiReply = await llm.chat({ messages: req.body.messages }); // Triggers Rule 10: client-controlled AI chat history.
res.cookie("sid", token, { httpOnly: false, secure: false }); // Triggers Rule 11: insecure session cookie flags.
const badHash = crypto.createHash("md5").update(password).digest("hex"); // Triggers Rule 12: weak MD5 password hashing.
console.log("Customer KYC BVN:", user.bvn); // Triggers Rule 13: unmasked BVN/NIN logging (NDPA 2023).
