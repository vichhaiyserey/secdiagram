using Microsoft.AspNetCore.Mvc;
using Shop.Api.Services;

namespace Shop.Api.Controllers;

[ApiController]
[Route("api/orders")]
public class OrdersController : ControllerBase
{
    private readonly IOrderService _orders;

    public OrdersController(IOrderService orders)
    {
        _orders = orders;
    }

    // VULNERABLE (interprocedural): controller -> service -> repository SQL.
    [HttpGet("search")]
    public IActionResult Search([FromQuery] string customer)
    {
        return Ok(_orders.FindByCustomer(customer));
    }

    // SAFE: the numeric cast ends the taint chain before the service call.
    [HttpGet("by-number")]
    public IActionResult ByNumber([FromQuery] string number)
    {
        return Ok(_orders.FindByCustomer(int.Parse(number).ToString()));
    }
}
