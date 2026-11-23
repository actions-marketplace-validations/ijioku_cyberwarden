// Demo fixture intentionally containing unsafe patterns so AgentShield's new Defense-in-Depth rules can catch them live.
const dbMigration = "ALTER TABLE billing DISABLE ROW LEVEL SECURITY;"; // Triggers Rule 1: disabled database RLS.
const meta = await fetch("http://169.254.169.254/latest/meta-data/"); // Triggers Rule 2: SSRF targeting cloud metadata.
fs.writeFileSync("/uploads/" + file.originalname, buffer); // Triggers Rule 3: unsafe file upload with raw filename.
const chargeAmount = req.body.price; // Triggers Rule 4: trusting client-supplied price.
user.credits -= chargeAmount; // Triggers Rule 5: non-atomic credit deduction race condition.
console.log("Debug login password:", password); // Triggers Rule 7: logging raw credentials.
