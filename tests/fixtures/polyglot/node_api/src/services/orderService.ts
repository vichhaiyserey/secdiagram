import { exec } from "child_process";
import { pool } from "../db";

export class OrderRepository {
  findByStatus(status: string) {
    return pool.query(`SELECT * FROM orders WHERE status = '${status}'`);
  }
}

export class OrderService {
  constructor(private readonly repository: OrderRepository) {}

  search(status: string) {
    return this.repository.findByStatus(status.toLowerCase());
  }
}

export function reportCommand() {
  return process.argv[2];
}

export function runReport() {
  // VULNERABLE (interprocedural): the helper returns process input.
  exec("report " + reportCommand());
}
