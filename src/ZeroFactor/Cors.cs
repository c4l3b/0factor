namespace ZeroFactor;

/// <summary>
/// Keycloak's CORS for browser clients: preflights are answered for any origin, the actual response carries
/// <c>Access-Control-Allow-Origin</c> only when the origin is one of the client's <c>webOrigins</c>.
/// </summary>
public static class Cors
{
    const string Oidc = "/realms/{realm}/protocol/openid-connect/";

    public static void MapCorsPreflight(this WebApplication app)
    {
        foreach (var path in new[] { "token", "userinfo", "logout", "revoke" })
            app.MapMethods(Oidc + path, ["OPTIONS"], (HttpContext context) =>
            {
                var headers = context.Response.Headers;
                if (context.Request.Headers.Origin.ToString() is not { Length: > 0 } origin) return Results.Ok();
                headers.AccessControlAllowOrigin = origin;
                headers.AccessControlAllowCredentials = "true";
                headers.AccessControlAllowMethods = "GET, POST, OPTIONS";
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

    /// <summary>Keycloak's <c>webOrigins</c>: exact origins, <c>*</c> for any, <c>+</c> for the redirect URIs' origins.</summary>
    internal static bool Allows(Realm realm, Client client, string origin) =>
        realm.Lenient || client.WebOrigins.Any(o => o == "*" || o == origin || (o == "+" && client.RedirectUris.Any(redirect =>
            Uri.TryCreate(redirect.TrimEnd('*'), UriKind.Absolute, out var target) && target.GetLeftPart(UriPartial.Authority) == origin)));
}
