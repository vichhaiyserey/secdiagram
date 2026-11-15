import { Router } from "express";

export const router = Router();

router.get("/public/search", async (req, res) => {
  res.json(await pool.query(`SELECT * FROM t WHERE q = '${req.query.q}'`));
});

router.get("/private/search", requireAuth, async (req, res) => {
  res.json(await pool.query(`SELECT * FROM t WHERE q = '${req.query.q}'`));
});
