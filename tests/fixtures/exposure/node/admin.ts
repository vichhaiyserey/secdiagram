import { Router } from "express";

export const admin = Router();
admin.use(authMiddleware);

admin.get("/admin/users", (req, res) => res.json([]));
