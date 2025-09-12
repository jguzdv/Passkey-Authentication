using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddAuthorization()
    .AddAuthentication(opt =>
    {
        opt.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        opt.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(opt =>
    {
        builder.Configuration.GetSection("Authentication:OpenIdConnect").Bind(opt);

        opt.Authority = "https://login.uni-mainz.de/adfs";
        opt.ClientId = "ottenhus-test";
        opt.ClientSecret = "yZVQMGU-17V42g3dKgCglfVpLGhjwsJ6PMJ3mhTb";
        opt.ResponseType = "id_token code";
    });


var app = builder.Build();

app.MapGet("/", (ClaimsPrincipal user) => string.Join("\n", user.Claims.Select(x => $"{x.Type}: {x.Value}")))
    .RequireAuthorization();

app.Run();
