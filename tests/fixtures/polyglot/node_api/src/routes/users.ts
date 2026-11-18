import { Router } from "express";
import { exec } from "child_process";
import fs from "fs";
import { pool } from "../db";
import { listUsers } from "../controllers/userController";

export const usersRouter = Router();

usersRouter.get("/users", listUsers);

// VULNERABLE: SQL built with a template literal from the query string.
usersRouter.get("/users/search", async (req, res) => {
  const name = req.query.name;
  const rows = await pool.query(`SELECT * FROM users WHERE name = '${name}'`);
  res.json(rows);
});

// SAFE: parameterized query.
usersRouter.get("/users/:id", async (req, res) => {
  const rows = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  res.json(rows);
});

// SAFE: numeric cast breaks the taint chain.
usersRouter.get("/users/:id/age", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const rows = await pool.query("SELECT age FROM users WHERE id = " + id);
  res.json(rows);
});

// VULNERABLE: command injection.
usersRouter.post("/users/export", (req, res) => {
  const { format } = req.body;
  exec("export-users --format " + format, () => res.sendStatus(202));
});

// VULNERABLE: path traversal.
usersRouter.get("/avatars/:file", (req, res) => {
  const target = "/srv/avatars/" + req.params.file;
  fs.readFile(target, (err, data) => res.send(data));
});

// VULNERABLE: reflected XSS.
usersRouter.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});
