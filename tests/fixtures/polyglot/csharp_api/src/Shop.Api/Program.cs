using Microsoft.EntityFrameworkCore;
using Shop.Api.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddScoped<IProductService, ProductService>();
var app = builder.Build();

var api = app.MapGroup("/api/v2");

api.MapGet("/health", () => Results.Ok("ok"));

// VULNERABLE: raw SQL interpolation from a minimal API parameter.
api.MapGet("/search", (string term, ShopDbContext db) =>
    db.Products.FromSqlRaw($"SELECT * FROM Products WHERE Name LIKE '%{term}%'").ToList());

// SAFE: FromSqlInterpolated parameterizes the value.
api.MapGet("/search-safe", (string term, ShopDbContext db) =>
    db.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE Name = {term}").ToList());

app.MapControllers();
app.Run();

public class ShopDbContext : DbContext
{
    public DbSet<Product> Products { get; set; } = null!;
}

public class Product
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
}
