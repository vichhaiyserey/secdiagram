import { Router } from "express";
import { OrderRepository, OrderService } from "../services/orderService";

export const ordersRouter = Router();
const orderService = new OrderService(new OrderRepository());

// VULNERABLE (interprocedural): route -> service -> repository SQL.
ordersRouter.get("/orders", async (req, res) => {
  const status = req.query.status;
  res.json(await orderService.search(status));
});

// SAFE: numeric conversion before the service call.
ordersRouter.get("/orders/count", async (req, res) => {
  res.json(await orderService.search(parseInt(req.query.limit, 10)));
});
