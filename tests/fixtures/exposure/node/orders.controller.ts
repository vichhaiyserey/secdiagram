import { Controller, Get, UseGuards } from "@nestjs/common";

@Controller("orders")
@UseGuards(JwtAuthGuard)
export class OrdersController {
  @Get()
  list() {
    return [];
  }
}
