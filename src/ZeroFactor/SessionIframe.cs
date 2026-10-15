namespace ZeroFactor;

/// <summary>Keycloak's browser session-status protocol and third-party cookie probes.</summary>
public static class SessionIframe
{
    internal const string StatusCookie = "ZF_SESSION_STATUS";

    public static void MapSessionIframe(this WebApplication app)
    {
        const string path = "/realms/{realm}/protocol/openid-connect/";
        app.MapGet(path + "login-status-iframe.html", IResult (string realm, HttpContext context, Store store) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            return store.GetRealm(realm) is null ? Discovery.RealmNotFound() : Slices.SessionStatus.Create();
        });
        app.MapGet(path + "login-status-iframe.html/init", IResult (string realm, HttpContext context, Store store) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            if (store.GetRealm(realm) is not { } r) return Discovery.RealmNotFound();
            var clientId = context.Request.Query["client_id"].ToString();
            var origin = context.Request.Query["origin"].ToString();
            if (clientId.Length == 0 || !Uri.TryCreate(origin, UriKind.Absolute, out var uri)
                || uri.Scheme is not ("http" or "https") || uri.GetLeftPart(UriPartial.Authority) != origin)
                return Results.NotFound();
            if (store.GetClient(r, clientId) is not { } client) return Results.NotFound();
            var serverOrigin = new Uri(Discovery.RealmUrl(context.Request, realm)).GetLeftPart(UriPartial.Authority);
            return origin == serverOrigin || Cors.Allows(r, client, origin) ? Results.NoContent() : Results.NotFound();
        });
        app.MapGet(path + "3p-cookies/step1.html", IResult (string realm, HttpContext context, Store store) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            return store.GetRealm(realm) is null ? Discovery.RealmNotFound() : Slices.CookieProbe.Create();
        });
        app.MapGet(path + "3p-cookies/step2.html", IResult (string realm, HttpContext context, Store store) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            return store.GetRealm(realm) is null ? Discovery.RealmNotFound() : Slices.CookieProbeResult.Create();
        });
    }
}
