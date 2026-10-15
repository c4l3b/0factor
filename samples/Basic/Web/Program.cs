using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(options =>
    {
        options.Authority = builder.Configuration.GetConnectionString("auth");
        options.ClientId = "web";
        options.ResponseType = "code";
        options.UsePkce = true;
        options.SaveTokens = true; // Retain the ID token for the OIDC sign-out request.
        options.RequireHttpsMetadata = false;
        options.MapInboundClaims = false;
        options.Scope.Add("email");
        options.TokenValidationParameters.NameClaimType = "name";

        // This local-only sample uses HTTP. Lax cookies work for the same-site form_post callback.
        options.CorrelationCookie.SameSite = options.NonceCookie.SameSite = SameSiteMode.Lax;
        options.CorrelationCookie.SecurePolicy = options.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();
app.MapGet("/login", () => Results.Challenge(new() { RedirectUri = "/" }));
app.MapGet("/logout", () => Results.SignOut(new() { RedirectUri = "/" },
    [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));

app.Run();
