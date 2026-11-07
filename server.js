require("dotenv").config();
const express = require("express");
const path = require("path");
const rateLimit = require("express-rate-limit");
const twilio = require("twilio");

const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SID, PORT = 3000 } = process.env;

if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_VERIFY_SID) {
  console.error("Missing Twilio settings. Copy .env.example to .env and fill in all three values.");
  process.exit(1);
}

const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
const verify = client.verify.v2.services(TWILIO_VERIFY_SID);

const app = express();
// If you host behind a proxy (Render, Railway, Nginx), uncomment so rate limits see the real IP:
// app.set("trust proxy", 1);
app.use(express.json({ limit: "2kb" }));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

const E164 = /^\+[1-9]\d{6,14}$/;

// Stops people from using your page to spam SMS (you pay for every SMS).
const sendLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please wait a few minutes and try again." },
});
const verifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Please wait a few minutes and try again." },
});

app.post("/api/send-otp", sendLimiter, async (req, res) => {
  const phone = String((req.body && req.body.phone) || "");
  if (!E164.test(phone)) return res.status(400).json({ error: "Enter a valid phone number." });

  try {
    await verify.verifications.create({ to: phone, channel: "sms" });
    res.json({ ok: true });
  } catch (e) {
    console.error("send-otp failed:", e.status, e.code, e.message);
    let error = "Could not send the code. Please try again.";
    if (e.code === 60200) error = "That phone number is not valid.";
    else if (e.code === 60203) error = "Too many codes were sent to this number. Try again later.";
    else if (e.code === 60205) error = "This number cannot receive SMS.";
    res.status(e.status && e.status >= 400 && e.status < 500 ? 400 : 502).json({ error });
  }
});

app.post("/api/verify-otp", verifyLimiter, async (req, res) => {
  const phone = String((req.body && req.body.phone) || "");
  const code = String((req.body && req.body.code) || "");
  if (!E164.test(phone) || !/^\d{4,10}$/.test(code)) {
    return res.status(400).json({ ok: false, error: "Invalid request." });
  }

  try {
    const check = await verify.verificationChecks.create({ to: phone, code });
    if (check.status === "approved") {
      // The number is now proven to belong to this user.
      // Do your own work HERE on the server: log the user in, save the verified number, etc.
      return res.json({ ok: true });
    }
    return res.json({ ok: false }); // wrong code, user can try again
  } catch (e) {
    console.error("verify-otp failed:", e.status, e.code, e.message);
    if (e.code === 60202) return res.json({ ok: false, maxed: true, error: "Too many wrong tries. Send a new code." });
    if (e.status === 404 || e.code === 20404) return res.json({ ok: false, maxed: true, error: "This code has expired. Send a new one." });
    res.status(502).json({ ok: false, error: "Could not check the code. Please try again." });
  }
});

app.listen(PORT, () => console.log("Running on http://localhost:" + PORT));
