using System.Xml;
using Microsoft.IdentityModel.Tokens;

public class Startup
{
    public void Configure(IApplicationBuilder app, IServiceCollection services)
    {
        // VULNERABLE: unconditional developer exception page.
        app.UseDeveloperExceptionPage();

        services.AddAuthentication().AddJwtBearer(o =>
        {
            o.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = false,   // VULNERABLE (signature)
                ValidateLifetime = false,           // VULNERABLE (lifetime)
                ValidateAudience = true,            // SAFE
            };
        });

        // VULNERABLE: any origin + credentials.
        services.AddCors(c => c.AddDefaultPolicy(p => p.SetIsOriginAllowed(_ => true).AllowCredentials()));
        // SAFE: explicit origin.
        services.AddCors(c => c.AddPolicy("strict", p => p.WithOrigins("https://app.example").AllowCredentials()));

        services.ConfigureApplicationCookie(o =>
        {
            o.Cookie.HttpOnly = false;              // VULNERABLE
            o.Cookie.SecurePolicy = CookieSecurePolicy.Always; // SAFE
        });
    }

    public XmlReader Reader(Stream s)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse }; // VULNERABLE
        return XmlReader.Create(s, settings);
    }

    public string NewResetToken() => new Random().Next().ToString(); // VULNERABLE (reset token)

    public int Dice() => new Random().Next(1, 7); // SAFE (not a security value)
}
