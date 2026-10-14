using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.JsonWebTokens;

var builder = WebApplication.CreateBuilder(args);

// Resolves https+http://keycloak and https+http://api. Usually in ServiceDefaults.
builder.Services.AddServiceDiscovery();
builder.Services.ConfigureHttpClientDefaults(http => http.AddServiceDiscovery());
builder.Services.AddHttpClient("api", client => client.BaseAddress = new("https+http://api"));
builder.Services.AddRazorPages();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(options => options.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    })
    .AddKeycloakOpenIdConnect("keycloak", realm: "shop", options =>
    {
        options.ClientId = "store.web";
        options.ClientSecret = "web-secret";
        options.ResponseType = "code";
        options.SaveTokens = true;
        options.RequireHttpsMetadata = false;
        options.MapInboundClaims = false;
        options.TokenValidationParameters.NameClaimType = "preferred_username";
        // Plain-http sample: the default correlation and nonce cookies are SameSite=None; Secure, which HttpClient
        // (the e2e tests) never sends over http. Lax still works for the form_post back from 0factor: same site.
        options.CorrelationCookie.SameSite = options.NonceCookie.SameSite = SameSiteMode.Lax;
        options.CorrelationCookie.SecurePolicy = options.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        // The usual Keycloak recipe: realm roles are only in the access token, under realm_access.roles.
        options.Events.OnTokenValidated = context =>
        {
            var identity = (ClaimsIdentity)context.Principal!.Identity!;
            var accessToken = new JsonWebToken(context.TokenEndpointResponse!.AccessToken);
            if (accessToken.TryGetPayloadValue<JsonElement>("realm_access", out var realmAccess))
                foreach (var role in realmAccess.GetProperty("roles").EnumerateArray())
                    identity.AddClaim(new Claim(identity.RoleClaimType, role.GetString()!));
            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapGet("/login", () => Results.Challenge(new() { RedirectUri = "/" }));
app.MapGet("/logout", () => Results.SignOut(new() { RedirectUri = "/" },
    [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));

// Calls the Api with the signed-in user's access token and passes its status code through.
app.MapGet("/call/{name:regex(^(orders|tenant)$)}", async (string name, HttpContext context, IHttpClientFactory http) =>
{
    using var request = new HttpRequestMessage(HttpMethod.Get, name);
    request.Headers.Authorization = new("Bearer", await context.GetTokenAsync("access_token"));
    using var response = await http.CreateClient("api").SendAsync(request);
    return Results.Text($"Api /{name}: {(int)response.StatusCode} {response.StatusCode}\n{await response.Content.ReadAsStringAsync()}",
        statusCode: (int)response.StatusCode);
}).RequireAuthorization();

app.Run();
