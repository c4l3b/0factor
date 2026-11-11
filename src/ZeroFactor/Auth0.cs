using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;

namespace ZeroFactor;

/// <summary>
/// Auth0-shaped endpoints for the <c>@auth0/auth0-spa-js</c> SDK: a sibling of the Keycloak-shaped endpoints over the
/// same realm and store. The SDK builds every URL from a <c>domain</c> base, so with a domain of
/// <c>{base}/realms/{realm}</c> these routes live under the realm. The access-token <c>aud</c> is taken from Auth0's
/// <c>audience</c> request parameter, carried by <see cref="Authorize"/> and applied by <see cref="Token"/>.
/// </summary>
public static class Auth0
{
    public static void MapAuth0(this WebApplication app)
    {
        app.MapMethods("/realms/{realm}/authorize", ["GET", "POST"],
            (string realm, HttpContext context, Store store, AuthCodes codes) => Authorize.Auth(realm, context, store, codes, auth0: true));
        app.MapPost("/realms/{realm}/oauth/token", Token0);
        app.MapGet("/realms/{realm}/.well-known/jwks.json", Discovery.Jwks);
        app.MapMethods("/realms/{realm}/userinfo", ["GET", "POST"], Introspection.UserInfo);
        app.MapGet("/realms/{realm}/v2/logout", Logout0); // GET only, like Auth0; Logout0 maps the query, not a form.
    }

    /// <summary>auth0-spa-js posts the token request as JSON by default (its <c>useFormData</c> option switches to a form).</summary>
    static async Task<IResult> Token0(string realm, HttpContext context, Store store, AuthCodes codes)
    {
        var form = context.Request.HasFormContentType ? await context.Request.ReadFormAsync() : await JsonForm(context.Request);
        return Token.Handle(realm, context, store, codes, form);
    }

    /// <summary>Auth0's <c>/v2/logout</c> uses <c>returnTo</c>; map it onto Keycloak's <c>post_logout_redirect_uri</c> (<c>client_id</c> matches).</summary>
    static Task<IResult> Logout0(string realm, HttpContext context, Store store)
    {
        var query = QueryHelpers.ParseQuery(context.Request.QueryString.Value);
        if (query.TryGetValue("returnTo", out var returnTo)) query["post_logout_redirect_uri"] = returnTo;
        context.Request.Query = new QueryCollection(query);
        return Authorize.Logout(realm, context, store);
    }

    /// <summary>Flattens a JSON object body into a form so <see cref="Token.Handle"/> reads it like a Keycloak form post.</summary>
    static async Task<IFormCollection> JsonForm(HttpRequest request)
    {
        var fields = new Dictionary<string, StringValues>();
        try
        {
            // JsonDocument tolerates duplicate keys (last one wins here); JsonObject throws on them.
            using var json = await JsonDocument.ParseAsync(request.Body);
            if (json.RootElement.ValueKind == JsonValueKind.Object)
                foreach (var property in json.RootElement.EnumerateObject())
                    if (property.Value.ValueKind != JsonValueKind.Null)
                        fields[property.Name] = property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : property.Value.GetRawText();
        }
        catch (JsonException) { } // empty or malformed body: Token.Handle reports the missing grant_type
        return new FormCollection(fields);
    }
}
