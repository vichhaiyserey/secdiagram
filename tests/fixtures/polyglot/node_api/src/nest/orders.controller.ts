import { Body, Controller, Get, Injectable, Param, Post } from "@nestjs/common";

@Injectable()
export class OrdersService {
  findOne(id: string) {
    return { id };
  }
}

@Controller("orders")
export class OrdersController {
  constructor(private readonly ordersService: OrdersService) {}

  @Get(":id")
  findOne(@Param("id") id: string) {
    return this.ordersService.findOne(id);
  }

  @Post()
  async create(@Body() body: any) {
    // VULNERABLE: fetch to a user-controlled URL.
    return fetch(body.callbackUrl);
  }
}
