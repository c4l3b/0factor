using System.Security.Cryptography;
using System.Buffers.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZeroFactor;

/// <summary>Keycloak's discovery, JWKS and realm-info endpoints.</summary>
public static class Discovery
{
    /// <summary>Exact <c>ZF_ISSUER</c> override, otherwise the realm's public URL.</summary>
    public static string Issuer(HttpRequest request, string realm)
    {
        var issuer = request.HttpContext.RequestServices.GetRequiredService<IConfiguration>()["ZF_ISSUER"];
        return string.IsNullOrEmpty(issuer) ? RealmUrl(request, realm) : issuer;
    }

    /// <summary><c>{base}/realms/{realm}</c>. Base is <c>ZF_HOSTNAME</c> when set, else the (forwarded) request URL.</summary>
    public static string RealmUrl(HttpRequest request, string realm)
    {
        var hostname = request.HttpContext.RequestServices.GetRequiredService<IConfiguration>()["ZF_HOSTNAME"];
        var baseUrl = string.IsNullOrEmpty(hostname) ? $"{request.Scheme}://{request.Host}{request.PathBase}" : hostname.TrimEnd('/');
        return $"{baseUrl}/realms/{realm}";
    }

    public static void MapDiscovery(this WebApplication app)
    {
        app.MapGet("/realms/{realm}/.well-known/openid-configuration", (string realm, HttpRequest request, Store store) =>
        {
            if (store.GetRealm(realm) is null) return RealmNotFound();
            var issuer = Issuer(request, realm);
            var oidc = RealmUrl(request, realm) + "/protocol/openid-connect";
            return Json(new JsonObject
            {
                ["issuer"] = issuer,
                ["authorization_endpoint"] = oidc + "/auth",
                ["token_endpoint"] = oidc + "/token",
                ["introspection_endpoint"] = oidc + "/token/introspect",
                ["userinfo_endpoint"] = oidc + "/userinfo",
                ["end_session_endpoint"] = oidc + "/logout",
                ["check_session_iframe"] = oidc + "/login-status-iframe.html",
                ["jwks_uri"] = oidc + "/certs",
                ["revocation_endpoint"] = oidc + "/revoke",
                ["grant_types_supported"] = Array("authorization_code", "refresh_token", "client_credentials", "password"),
                ["response_types_supported"] = Array("code"),
                ["response_modes_supported"] = Array("query", "fragment", "form_post"),
                ["subject_types_supported"] = Array("public"),
                ["id_token_signing_alg_values_supported"] = Array("RS256"),
                ["code_challenge_methods_supported"] = Array("plain", "S256"),
                ["token_endpoint_auth_methods_supported"] = Array("client_secret_basic", "client_secret_post"),
                ["scopes_supported"] = Array("openid", "profile", "email", "roles", "offline_access"),
                ["claims_supported"] = Array("iss", "sub", "aud", "exp", "iat", "auth_time", "name", "given_name", "family_name",
                    "preferred_username", "email", "acr", "azp", "nonce"),
                ["authorization_response_iss_parameter_supported"] = true,
            });
        });

        app.MapGet("/realms/{realm}/protocol/openid-connect/certs", (string realm, Store store) =>
        {
            if (store.GetRealm(realm) is not { } r) return RealmNotFound();
            var key = RealmKey.For(store, r);
            var der = key.Certificate.RawData;
            return Json(new JsonObject
            {
                ["keys"] = new JsonArray(new JsonObject
                {
                    ["kid"] = key.Kid,
                    ["kty"] = "RSA",
                    ["alg"] = "RS256",
                    ["use"] = "sig",
                    ["x5c"] = Array(Convert.ToBase64String(der)),
                    ["x5t"] = Base64Url.EncodeToString(SHA1.HashData(der)),
                    ["x5t#S256"] = Base64Url.EncodeToString(SHA256.HashData(der)),
                    ["n"] = key.N,
                    ["e"] = key.E,
                }),
            });
        });

        app.MapGet("/realms/{realm}", (string realm, HttpRequest request, Store store) =>
        {
            if (store.GetRealm(realm) is not { } r) return RealmNotFound();
            var realmUrl = RealmUrl(request, realm);
            return Json(new JsonObject
            {
                ["realm"] = realm,
                ["public_key"] = Convert.ToBase64String(RealmKey.For(store, r).Rsa.ExportSubjectPublicKeyInfo()),
                ["token-service"] = realmUrl + "/protocol/openid-connect",
                ["account-service"] = realmUrl + "/account",
                ["tokens-not-before"] = 0,
            });
        });
    }

    public static IResult RealmNotFound() => Json(new JsonObject { ["error"] = "Realm does not exist" }, StatusCodes.Status404NotFound);

    // Relaxed escaping writes base64 '+' as-is, like Keycloak, instead of \u002B.
    static readonly JsonSerializerOptions relaxed = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public static IResult Json(JsonNode json, int statusCode = StatusCodes.Status200OK) =>
        Results.Content(json.ToJsonString(relaxed), "application/json", statusCode: statusCode);

    internal static JsonArray Array(params string[] values) => new([.. values.Select(v => (JsonNode)v)]);
}
