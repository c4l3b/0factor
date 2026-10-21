namespace ZeroFactor;

/// <summary>
/// Keycloak's CORS for browser clients: preflights are answered for any origin, the actual response carries
/// <c>Access-Control-Allow-Origin</c> only when the origin is one of the client's <c>webOrigins</c>.
/// Public GETs (discovery, certs, realm info) allow any origin, like Keycloak's <c>allowAllOrigins()</c>.
/// </summary>
public static class Cors
{
    const string Oidc = "/realms/{realm}/protocol/openid-connect/";

    public static void MapCorsPreflight(this WebApplication app)
    {
        (string Path, string Methods)[] endpoints =
        [
            (Oidc + "token", "GET, POST, OPTIONS"), (Oidc + "userinfo", "GET, POST, OPTIONS"),
            (Oidc + "logout", "GET, POST, OPTIONS"), (Oidc + "revoke", "GET, POST, OPTIONS"),
            ("/realms/{realm}/.well-known/openid-configuration", "GET"), (Oidc + "certs", "GET"), ("/realms/{realm}", "GET, HEAD, OPTIONS"),
        ];
        foreach (var (path, methods) in endpoints)
            app.MapMethods(path, ["OPTIONS"], (HttpContext context) =>
            {
                var headers = context.Response.Headers;
                if (context.Request.Headers.Origin.ToString() is not { Length: > 0 } origin) return Results.Ok();
                headers.AccessControlAllowOrigin = origin;
                headers.AccessControlAllowCredentials = "true";
                headers.AccessControlAllowMethods = methods;
                headers.AccessControlAllowHeaders = "Origin, Accept, X-Requested-With, Content-Type, Authorization, DPoP";
                headers.AccessControlMaxAge = "3600";
                headers.Vary = "Origin";
                return Results.Ok();
            });
    }

    /// <summary>Allows the request's origin on the response when <paramref name="client"/> lists it.</summary>
    internal static void Apply(HttpContext context, Realm realm, Client? client)
    {
        context.Response.Headers.Vary = "Origin";
        if (client is null || context.Request.Headers.Origin.ToString() is not { Length: > 0 } origin || !Allows(realm, client, origin)) return;
        context.Response.Headers.AccessControlAllowOrigin = origin;
        context.Response.Headers.AccessControlAllowCredentials = "true";
    }

    /// <summary>Allows any request origin on the response, for Keycloak's public endpoints.</summary>
    internal static void AllowAnyOrigin(HttpContext context)
    {
        context.Response.Headers.Vary = "Origin";
        if (context.Request.Headers.Origin.ToString() is not { Length: > 0 } origin) return;
        context.Response.Headers.AccessControlAllowOrigin = origin;
        context.Response.Headers.AccessControlAllowCredentials = "true";
    }

    /// <summary>Keycloak's <c>webOrigins</c>: exact origins, <c>*</c> for any, <c>+</c> for the redirect URIs' origins.</summary>
    internal static bool Allows(Realm realm, Client client, string origin) =>
        realm.Lenient || client.WebOrigins.Any(o => o == "*" || o == origin || (o == "+" && client.RedirectUris.Any(redirect =>
            Uri.TryCreate(redirect.TrimEnd('*'), UriKind.Absolute, out var target) && target.GetLeftPart(UriPartial.Authority) == origin)));
}
