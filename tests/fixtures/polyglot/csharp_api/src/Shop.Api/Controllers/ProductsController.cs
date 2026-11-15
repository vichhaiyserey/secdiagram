using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Shop.Api.Services;

namespace Shop.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ProductsController : ControllerBase
{
    private readonly IProductService _products;
    private readonly IHttpClientFactory _http;

    public ProductsController(IProductService products, IHttpClientFactory http)
    {
        _products = products;
        _http = http;
    }

    // VULNERABLE: SQL built from the route parameter.
    [HttpGet("{name}")]
    public IActionResult GetByName(string name, CancellationToken cancellationToken)
    {
        using var conn = new SqlConnection("Server=db;Database=shop");
        var sql = "SELECT * FROM Products WHERE Name = '" + name + "'";
        using var cmd = new SqlCommand(sql, conn);
        return Ok(_products.Describe(name));
    }

    // SAFE: parameterized query with a bound parameter.
    [HttpGet("by-id/{id}")]
    public IActionResult GetById(int id)
    {
        using var conn = new SqlConnection("Server=db;Database=shop");
        using var cmd = new SqlCommand("SELECT * FROM Products WHERE Id = @id", conn);
        cmd.Parameters.AddWithValue("@id", id);
        return Ok();
    }

    // VULNERABLE: command injection from the query string.
    [HttpPost("export")]
    public IActionResult Export([FromQuery] string format)
    {
        Process.Start("/usr/bin/exporter", "--format " + format);
        return Accepted();
    }

    // VULNERABLE: SSRF via user-supplied URL.
    [HttpGet("preview")]
    public async Task<IActionResult> Preview([FromQuery] string url)
    {
        var client = _http.CreateClient();
        var body = await client.GetStringAsync(url);
        return Content(body);
    }

    // VULNERABLE: open redirect.
    [HttpGet("go")]
    public IActionResult Go(string returnUrl) => Redirect(returnUrl);

    // SAFE: local-only redirect.
    [HttpGet("home")]
    public IActionResult Home(string returnUrl) => LocalRedirect(Url.IsLocalUrl(returnUrl) ? returnUrl : "/");
}
