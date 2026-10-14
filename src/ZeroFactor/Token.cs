using System.Buffers.Text;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace ZeroFactor;

/// <summary>
/// Keycloak's token endpoint: <c>authorization_code</c> (+PKCE), <c>refresh_token</c>, <c>client_credentials</c> and
/// <c>password</c> with the password ignored. Claims, error codes and messages follow Keycloak 26.
/// </summary>
public static class Token
{
    // Keycloak's default-roles-{realm} composite: these realm roles plus the account client roles.
    static readonly string[] defaultAccountRoles = ["manage-account", "manage-account-links", "view-profile"];
    const int OfflineLifespan = 2592000; // Keycloak's offlineSessionIdleTimeout default, 30 days.

    public static void MapToken(this WebApplication app) =>
        app.MapPost("/realms/{realm}/protocol/openid-connect/token", Post);

    static async Task<IResult> Post(string realm, HttpContext context, Store store, AuthCodes codes)
    {
        if (store.GetRealm(realm) is not { } r) return Discovery.RealmNotFound();
        var form = context.Request.HasFormContentType ? await context.Request.ReadFormAsync() : FormCollection.Empty;
        string? Get(string name) => form[name].ToString() is { Length: > 0 } v ? v : null;

        if (Get("grant_type") is not { } grantType) return Error("invalid_request", "Missing form parameter: grant_type");

        var (client, error) = AuthenticateClient(context.Request, form, store, r);
        if (client is null) return error!;

        User? FindById(string? id) => r.Users.Find(u => u.Id == id);

        switch (grantType)
        {
            case "authorization_code":
            {
                if (Get("code") is not { } value) return Error("invalid_request", "Missing parameter: code");
                if (codes.Redeem(value) is not { } code || code.Realm != r.Name) return Error("invalid_grant", "Code not valid");
                if (code.ClientId != client.ClientId) return Error("invalid_grant", "Auth error: Found different client_id in clientSession");
                if (Get("redirect_uri") != code.RedirectUri) return Error("invalid_grant", "Incorrect redirect_uri");
                if (code.CodeChallenge is not null)
                {
                    if (Get("code_verifier") is not { } verifier) return Error("invalid_grant", "PKCE code verifier not specified");
                    var computed = code.CodeChallengeMethod == "S256"
                        ? Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))
                        : verifier;
                    if (computed != code.CodeChallenge) return Error("invalid_grant", "PKCE verification failed: Code mismatch");
                }
                if (FindById(code.UserId) is not { Enabled: true } user) return Error("invalid_grant", "User disabled");
                return Tokens(context, store, r, client, user, Scope(code.Scope), code.Sid, code.AuthTime, code.Nonce, null);
            }

            case "refresh_token":
            {
                if (Get("refresh_token") is not { } value) return Error("invalid_request", "No refresh token");
                var issuer = Discovery.Issuer(context.Request, r.Name);
                if (Jwt.Validate(RealmKey.For(store, r), value, issuer) is not { } refresh
                    || (string?)refresh["typ"] is not ("Refresh" or "Offline"))
                    return Error("invalid_grant", "Invalid refresh token");
                if ((string?)refresh["azp"] != client.ClientId)
                    return Error("invalid_grant", "Invalid refresh token. Token client and authorized client don't match");
                if (FindById((string?)refresh["sub"]) is not { } user) return Error("invalid_grant", "Unknown user");
                if (!user.Enabled) return Error("invalid_grant", "User disabled");
                return Tokens(context, store, r, client, user, (string)refresh["scope"]!, (string)refresh["sid"]!,
                    (long)refresh["auth_time"]!, null, null);
            }

            case "client_credentials":
            {
                if (client.PublicClient)
                    return Error("unauthorized_client", "Public client not allowed to retrieve service account", StatusCodes.Status401Unauthorized);
                if (!r.Lenient && !client.ServiceAccountsEnabled)
                    return Error("unauthorized_client", "Client not enabled to retrieve service account", StatusCodes.Status401Unauthorized);
                // A real user record, so roles and claims can be edited like any user's.
                // ponytail: two concurrent first requests can create two service-account users; dev traffic never does.
                var name = $"service-account-{client.ClientId}";
                var user = r.FindUser(name);
                if (user is null) store.AddUser(r, user = new User { Username = name, EmailVerified = false });
                if (!user.Enabled) return Error("invalid_grant", "User disabled");
                var host = context.Connection.RemoteIpAddress?.ToString();
                var extra = new JsonObject { ["clientHost"] = host, ["clientAddress"] = host, ["client_id"] = client.ClientId };
                return Tokens(context, store, r, client, user, Scope(Get("scope")), null, null, null, extra);
            }

            case "password":
            {
                if (!r.Lenient && !client.DirectAccessGrantsEnabled)
                    return Error("unauthorized_client", "Client not allowed for direct access grants");
                if (Get("username") is not { } username)
                    return Error("invalid_request", "Missing parameter: username", StatusCodes.Status401Unauthorized);
                // The password parameter is accepted and ignored: that's the zero factor.
                if (Authorize.FindByEmail(r, username) is not { } user) return Error("invalid_grant", "Invalid user credentials");
                if (!user.Enabled) return Error("invalid_grant", "Account disabled");
                store.Update(_ => user.LastLoginAt = DateTimeOffset.UtcNow);
                return Tokens(context, store, r, client, user, Scope(Get("scope")), Guid.NewGuid().ToString(), Now, null, null);
            }

            default:
                return Error("unsupported_grant_type", "Unsupported grant_type");
        }
    }

    /// <summary>
    /// The client from <c>client_secret_basic</c>, else <c>client_secret_post</c>; public clients send <c>client_id</c> only and
    /// lenient realms accept any secret. Otherwise the token endpoint's 401. Shared by token, introspection and revocation.
    /// </summary>
    internal static (Client? Client, IResult? Error) AuthenticateClient(HttpRequest request, IFormCollection form, Store store, Realm realm)
    {
        string? Get(string name) => form[name].ToString() is { Length: > 0 } v ? v : null;
        var (clientId, secret) = (Get("client_id"), Get("client_secret"));
        if (AuthenticationHeaderValue.TryParse(request.Headers.Authorization, out var header)
            && header.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase) && header.Parameter is { } basic)
        {
            try
            {
                var pair = Encoding.UTF8.GetString(Convert.FromBase64String(basic));
                if (pair.IndexOf(':') is var colon and > 0)
                    (clientId, secret) = (Uri.UnescapeDataString(pair[..colon]), Uri.UnescapeDataString(pair[(colon + 1)..]));
            }
            catch (FormatException) { }
        }
        const string invalidCredentials = "Invalid client or Invalid client credentials";
        if (clientId is null || store.GetClient(realm, clientId) is not { } client)
            return (null, Error("invalid_client", invalidCredentials, StatusCodes.Status401Unauthorized));
        if (!client.PublicClient && !realm.Lenient && client.Secret != secret)
            return (null, Error("unauthorized_client", invalidCredentials, StatusCodes.Status401Unauthorized));
        return (client, null);
    }

    /// <summary>Keycloak's token scope: <c>openid</c> when requested, the default <c>profile email</c>, then the rest requested.</summary>
    static string Scope(string? requested)
    {
        var scopes = (requested ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return string.Join(' ', (scopes.Contains("openid") ? ["openid"] : Array.Empty<string>()).Concat(["profile", "email"]).Concat(scopes).Distinct());
    }

    /// <summary>
    /// Access, ID (when scope has <c>openid</c>) and refresh tokens. No <paramref name="sid"/> means a service-account token:
    /// no session and no refresh token, like Keycloak.
    /// </summary>
    static IResult Tokens(HttpContext context, Store store, Realm realm, Client client, User user, string scope, string? sid,
        long? authTime, string? nonce, JsonObject? extra)
    {
        var key = RealmKey.For(store, realm);
        var issuer = Discovery.Issuer(context.Request, realm.Name);
        var now = Now;
        var exp = now + realm.AccessTokenLifespan;
        var scopes = scope.Split(' ');

        // realm_access, resource_access and aud as Keycloak's roles scope and audience mappers build them.
        var clientRoles = user.ClientRoles.Where(p => p.Value.Count > 0).ToDictionary(p => p.Key, p => p.Value.ToList());
        if (!clientRoles.TryGetValue("account", out var account)) clientRoles["account"] = account = [];
        account.AddRange(defaultAccountRoles.Except(account));
        var audience = client.ProtocolMappers
            .Where(m => m.Mapper == "oidc-audience-mapper" && m.Config.GetValueOrDefault("access.token.claim") != "false")
            .SelectMany(m => new[] { m.Config.GetValueOrDefault("included.client.audience"), m.Config.GetValueOrDefault("included.custom.audience") })
            .Concat(client.Audience)
            .Concat(clientRoles.Keys.Where(k => k != client.ClientId))
            .OfType<string>().Where(a => a != "").Distinct().ToList();
        var resourceAccess = new JsonObject();
        foreach (var (id, roles) in clientRoles) resourceAccess[id] = new JsonObject { ["roles"] = Discovery.Array([.. roles]) };
        var origins = client.WebOrigins.SelectMany(o => o == "+" ? client.RedirectUris.Select(Origin) : [o]).OfType<string>().Distinct().ToArray();

        var access = Compact(new JsonObject
        {
            ["exp"] = exp, ["iat"] = now, ["auth_time"] = authTime, ["jti"] = Guid.NewGuid().ToString(), ["iss"] = issuer,
            ["aud"] = audience.Count == 1 ? (JsonNode)audience[0] : Discovery.Array([.. audience]),
            ["sub"] = user.Id, ["typ"] = "Bearer", ["azp"] = client.ClientId, ["sid"] = sid, ["acr"] = "1",
            ["allowed-origins"] = origins.Length > 0 ? Discovery.Array(origins) : null,
            ["realm_access"] = new JsonObject
            {
                ["roles"] = Discovery.Array([.. new[] { "offline_access", $"default-roles-{realm.Name}" }.Concat(user.RealmRoles).Append("uma_authorization").Distinct()]),
            },
            ["resource_access"] = resourceAccess,
            ["scope"] = scope,
        });
        Merge(access, extra);
        Merge(access, UserClaims(realm, user));
        var accessToken = Jwt.Create(key, access);

        string? idToken = null;
        if (scopes.Contains("openid"))
        {
            var id = Compact(new JsonObject
            {
                ["exp"] = exp, ["iat"] = now, ["auth_time"] = authTime, ["jti"] = Guid.NewGuid().ToString(), ["iss"] = issuer,
                ["aud"] = client.ClientId, ["sub"] = user.Id, ["typ"] = "ID", ["azp"] = client.ClientId, ["nonce"] = nonce, ["sid"] = sid,
                ["at_hash"] = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)).AsSpan(0, 16)),
                ["acr"] = "1",
            });
            Merge(id, extra);
            Merge(id, UserClaims(realm, user));
            idToken = Jwt.Create(key, id);
        }

        // Stateless refresh token, a new one on every use. Offline tokens outlive the SSO session.
        string? refreshToken = null;
        long refreshExpiresIn = 0;
        if (sid is not null)
        {
            var offline = scopes.Contains("offline_access");
            // ponytail: Keycloak's offline tokens have no exp; ours expire after the offline idle timeout so Jwt.Validate stays uniform.
            var refreshExp = offline ? now + OfflineLifespan
                : Math.Min(now + realm.SsoSessionIdleTimeout, authTime!.Value + realm.SsoSessionMaxLifespan);
            refreshExpiresIn = offline ? 0 : refreshExp - now;
            refreshToken = Jwt.Create(key, new JsonObject
            {
                ["exp"] = refreshExp, ["iat"] = now, ["jti"] = Guid.NewGuid().ToString(), ["iss"] = issuer, ["aud"] = issuer,
                ["sub"] = user.Id, ["typ"] = offline ? "Offline" : "Refresh", ["azp"] = client.ClientId, ["sid"] = sid,
                ["auth_time"] = authTime, ["scope"] = scope,
            });
        }

        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
        return Discovery.Json(Compact(new JsonObject
        {
            ["access_token"] = accessToken,
            ["expires_in"] = realm.AccessTokenLifespan,
            ["refresh_expires_in"] = refreshExpiresIn,
            ["refresh_token"] = refreshToken,
            ["token_type"] = "Bearer",
            ["id_token"] = idToken,
            ["not-before-policy"] = 0,
            ["session_state"] = sid,
            ["scope"] = scope,
        }));
    }

    /// <summary>
    /// Profile and email claims, then registration-field attribute claims, then the user's extra claims (reserved names
    /// skipped), so extra claims win. Shared by tokens and userinfo.
    /// </summary>
    public static JsonObject UserClaims(Realm realm, User user)
    {
        var name = string.Join(' ', new[] { user.FirstName, user.LastName }.Where(n => !string.IsNullOrEmpty(n)));
        var claims = Compact(new JsonObject
        {
            ["email_verified"] = user.EmailVerified,
            ["name"] = name == "" ? null : name,
            ["preferred_username"] = user.Username,
            ["given_name"] = user.FirstName,
            ["family_name"] = user.LastName,
            ["email"] = user.Email,
        });
        Merge(claims, realm.AttributeClaims(user));
        foreach (var (claim, value) in user.Claims ?? [])
            if (!User.ReservedClaims.Contains(claim)) claims[claim] = value?.DeepClone();
        return claims;
    }

    static void Merge(JsonObject target, JsonObject? source)
    {
        foreach (var (name, value) in source ?? []) target[name] = value?.DeepClone();
    }

    static JsonObject Compact(JsonObject json)
    {
        foreach (var name in json.Where(p => p.Value is null).Select(p => p.Key).ToList()) json.Remove(name);
        return json;
    }

    static string? Origin(string redirectUri) =>
        Uri.TryCreate(redirectUri.TrimEnd('*'), UriKind.Absolute, out var uri) ? uri.GetLeftPart(UriPartial.Authority) : null;

    internal static IResult Error(string error, string description, int statusCode = StatusCodes.Status400BadRequest) =>
        Discovery.Json(new JsonObject { ["error"] = error, ["error_description"] = description }, statusCode);

    static long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
}
