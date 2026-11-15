var app = WebApplication.CreateBuilder(args).Build();
var secure = app.MapGroup("/secure").RequireAuthorization();
secure.MapGet("/report", (string name) => Results.Ok(name));
app.MapGet("/open", (string name) => Results.Ok(name)).AllowAnonymous();
app.MapGet("/plain", (string name) => Results.Ok(name));
