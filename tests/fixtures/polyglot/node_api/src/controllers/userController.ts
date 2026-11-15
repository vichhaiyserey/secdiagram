import https from "https";
import { pool } from "../db";

export async function listUsers(req, res) {
  const rows = await pool.query("SELECT id, name FROM users");
  res.json(rows);
}

export const insecureAgent = new https.Agent({ rejectUnauthorized: false });

export function evaluate(expression: string) {
  // SAFE: literal only.
  return eval("1 + 1");
}
