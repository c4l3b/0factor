using System.Net.Http.Headers;
using System.Text.Json.Nodes;

namespace ZeroFactor;

/// <summary>Keycloak's userinfo, token introspection and revocation endpoints. Status codes and messages follow Keycloak 26.</summary>
public static class Introspection
{
    public static void MapIntrospection(this WebApplication app)
    {
        app.MapMethods("/realms/{realm}/protocol/openid-connect/userinfo", ["GET", "POST"], UserInfo);
        app.MapPost("/realms/{realm}/protocol/openid-connect/token/introspect", Introspect);
        app.MapPost("/realms/{realm}/protocol/openid-connect/revoke", Revoke);
    }

    static async Task<IResult> UserInfo(string realm, HttpContext context, Store store)
    {
        if (store.GetRealm(realm) is not { } r) return Discovery.RealmNotFound();
        var request = context.Request;
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";

        var token = AuthenticationHeaderValue.TryParse(request.Headers.Authorization, out var header)
            && header.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase) ? header.Parameter : null;
        if (token is null && request.HasFormContentType)
            token = (await request.ReadFormAsync())["access_token"].ToString() is { Length: > 0 } t ? t : null;
        if (token is null) return Unauthorized(context, $"Bearer realm=\"{r.Name}\"");

        // ponytail: stateless, so a token stays valid after logout until it expires; check an ended-sid set if a test needs it.
        if (Jwt.Validate(RealmKey.For(store, r), token, Discovery.Issuer(request, r.Name)) is not { } payload
            || (string?)payload["typ"] != "Bearer"
            || r.Users.Find(u => u.Id == (string?)payload["sub"]) is not { Enabled: true } user)
            return Unauthorized(context, $"Bearer realm=\"{r.Name}\", error=\"invalid_token\", error_description=\"Token verification failed\"");

        Cors.Apply(context, r, store.GetClient(r, (string?)payload["azp"] ?? ""));
        var claims = new JsonObject { ["sub"] = user.Id };
        foreach (var (name, value) in Token.UserClaims(r, user)) claims[name] = value?.DeepClone();
        return Discovery.Json(claims);
    }

    static IResult Unauthorized(HttpContext context, string challenge)
    {
        context.Response.Headers.WWWAuthenticate = challenge;
        return Results.StatusCode(StatusCodes.Status401Unauthorized);
    }

    static async Task<IResult> Introspect(string realm, HttpContext context, Store store)
    {
        if (store.GetRealm(realm) is not { } r) return Discovery.RealmNotFound();
        var form = context.Request.HasFormContentType ? await context.Request.ReadFormAsync() : FormCollection.Empty;
        if (Token.AuthenticateClient(context.Request, form, store, r).Client is not { } client)
            return Error("Authentication failed.", StatusCodes.Status401Unauthorized);
        if (client.PublicClient) return Error("Client not allowed.", StatusCodes.Status403Forbidden);
        if (form["token"].ToString() is not { Length: > 0 } token) return Error("Token not provided.", StatusCodes.Status400BadRequest);

        // Like Keycloak, refresh tokens are only introspected with token_type_hint=refresh_token.
        var refresh = form["token_type_hint"] == "refresh_token";
        if (Jwt.Validate(RealmKey.For(store, r), token, Discovery.Issuer(context.Request, r.Name)) is not { } payload
            || !(refresh ? (string?)payload["typ"] is "Refresh" or "Offline" : (string?)payload["typ"] == "Bearer")
            || r.Users.Find(u => u.Id == (string?)payload["sub"]) is not { Enabled: true } user)
            return Discovery.Json(new JsonObject { ["active"] = false });

        payload["client_id"] = (string?)payload["azp"];
        payload["username"] = user.Username;
        payload["token_type"] = (string?)payload["typ"];
        payload["active"] = true;
        return Discovery.Json(payload);
    }

    static IResult Error(string description, int statusCode) =>
        Discovery.Json(new JsonObject { ["error"] = "invalid_request", ["error_description"] = description }, statusCode);

    static async Task<IResult> Revoke(string realm, HttpContext context, Store store)
    {
        if (store.GetRealm(realm) is not { } r) return Discovery.RealmNotFound();
        var form = context.Request.HasFormContentType ? await context.Request.ReadFormAsync() : FormCollection.Empty;
        var (client, error) = Token.AuthenticateClient(context.Request, form, store, r);
        Cors.Apply(context, r, client);
        if (client is null) return error!;
        if (form["token"].ToString() is not { Length: > 0 } token) return Error("Token not provided", StatusCodes.Status400BadRequest);
        // Keycloak answers an unusable token with 200 and an error body.
        if (Jwt.Validate(RealmKey.For(store, r), token, Discovery.Issuer(context.Request, r.Name)) is null)
            return Discovery.Json(new JsonObject { ["error"] = "invalid_token", ["error_description"] = "Invalid token" });
        // ponytail: no-op, tokens are stateless and stay valid until they expire. Add a revoked-jti set if a test needs revocation.
        return Results.Ok();
    }
}
