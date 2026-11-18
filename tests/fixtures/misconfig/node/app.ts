import jwt from "jsonwebtoken";
import cors from "cors";
import session from "express-session";
import _ from "lodash";

// VULNERABLE: any origin + credentials.
app.use(cors({ origin: true, credentials: true }));
// SAFE: explicit origin list.
app.use(cors({ origin: ["https://app.example"], credentials: true }));

// VULNERABLE: session cookie without HttpOnly.
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { httpOnly: false, secure: true } }));

export function readClaims(token: string) {
  // VULNERABLE: decode only, no verify anywhere in this file.
  return jwt.decode(token);
}

export function legacyVerify(token: string) {
  // VULNERABLE: accepts alg=none and ignores expiry.
  return jwt.decode(token, { algorithms: ["HS256", "none"], ignoreExpiration: true });
}

export function newApiKey() {
  return "key_" + Math.random().toString(36); // VULNERABLE (api key)
}

export function shuffleSeed() {
  return Math.random(); // SAFE (not a security value)
}

app.post("/settings", (req, res) => {
  const settings = {};
  _.merge(settings, req.body); // VULNERABLE: prototype pollution
  res.json(settings);
});

app.post("/settings-safe", (req, res) => {
  const settings = { theme: String(req.body.theme) };
  _.merge(settings, { saved: true }); // SAFE: literal source
  res.json(settings);
});
