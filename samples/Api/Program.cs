using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Resolves https+http://keycloak, the authority Aspire.Keycloak.Authentication uses. Usually in ServiceDefaults.
builder.Services.AddServiceDiscovery();
builder.Services.ConfigureHttpClientDefaults(http => http.AddServiceDiscovery());

builder.Services.AddAuthentication()
    .AddKeycloakJwtBearer("keycloak", realm: "shop", options =>
    {
        options.Audience = "store.api"; // added to store.web tokens by the realm's oidc-audience-mapper
        options.RequireHttpsMetadata = false;
        options.MapInboundClaims = false;
    });
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("tenant", policy => policy.RequireClaim("tenant_id"));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/orders", (ClaimsPrincipal user) => $"Orders for {user.FindFirstValue("preferred_username")}").RequireAuthorization();
app.MapGet("/tenant", (ClaimsPrincipal user) => $"Tenant {user.FindFirstValue("tenant_id")}").RequireAuthorization("tenant");

app.Run();
