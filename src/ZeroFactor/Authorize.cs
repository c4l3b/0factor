using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.WebUtilities;

namespace ZeroFactor;

/// <summary>An issued authorization code and everything the token endpoint must check it against.</summary>
public record AuthCode(string Realm, string ClientId, string RedirectUri, string? Scope, string? Nonce,
    string? CodeChallenge, string? CodeChallengeMethod, string UserId, string Sid, long AuthTime, DateTimeOffset Expires);

/// <summary>Single-use authorization codes with a 60 s lifetime, in memory only.</summary>
public class AuthCodes
{
    readonly ConcurrentDictionary<string, AuthCode> codes = new();

    public string Issue(AuthCode code)
    {
        // ponytail: O(n) sweep of expired codes on every issue; dev-scale traffic. A timer if it ever matters.
        foreach (var (key, value) in codes)
            if (value.Expires <= DateTimeOffset.UtcNow) codes.TryRemove(key, out _);
        var id = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        codes[id] = code;
        return id;
    }

    /// <summary>Removes and returns the code; null when unknown, already used or expired.</summary>
    public AuthCode? Redeem(string code) => codes.TryRemove(code, out var c) && c.Expires > DateTimeOffset.UtcNow ? c : null;
}

public record LoginModel(string Realm, string Action, string Auth, string? Email, string? Error, List<User> Users);
public record ErrorModel(string Message);
public record FormPostModel(string Action, List<KeyValuePair<string, string?>> Values);

/// <summary>
/// Keycloak's authorization endpoint and the email-only login page. The pending request travels through the login
/// form as a signed JWT (<c>typ: AuthRequest</c>); the SSO session is a signed JWT in the <c>ZF_SESSION</c> cookie.
/// </summary>
public static class Authorize
{
    const string SessionCookie = "ZF_SESSION";
    const int LoginLifespan = 1800; // Keycloak's accessCodeLifespanLogin default.
    static readonly string[] carried = ["client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge",
        "code_challenge_method", "response_mode"];

    public static void MapAuthorize(this WebApplication app)
    {
        app.MapMethods("/realms/{realm}/protocol/openid-connect/auth", ["GET", "POST"], Auth);
        app.MapPost("/realms/{realm}/login-actions/authenticate", Authenticate);
    }

    static async Task<IResult> Auth(string realm, HttpContext context, Store store, AuthCodes codes)
    {
        var request = context.Request;
        var form = request.HasFormContentType ? await request.ReadFormAsync() : null;
        string? Get(string name) => (form is null ? request.Query[name] : form[name]).ToString() is { Length: > 0 } v ? v : null;

        if (store.GetRealm(realm) is not { } r) return Error("Realm does not exist.", StatusCodes.Status404NotFound);
        if (Get("client_id") is not { } clientId) return Error("Missing parameter: client_id");
        if (store.GetClient(r, clientId) is not { } client) return Error("Client not found.");
        if (Get("redirect_uri") is not { } redirectUri || !(r.Lenient || client.RedirectUris.Exists(u => Matches(u, redirectUri))))
            return Error("Invalid parameter: redirect_uri");
        if (Get("response_mode") is { } mode && mode is not ("query" or "fragment" or "form_post"))
            return Error("Invalid parameter: response_mode");

        // From here on errors go back to the client.
        var issuer = Discovery.Issuer(request, realm);
        var auth = new JsonObject { ["typ"] = "AuthRequest", ["iss"] = issuer, ["exp"] = Now + LoginLifespan };
        foreach (var name in carried)
            if (Get(name) is { } value) auth[name] = value;

        var responseType = Get("response_type");
        if (responseType is null) return Redirect(auth, issuer, "invalid_request", "Missing parameter: response_type");
        if (responseType != "code") return Redirect(auth, issuer, "unsupported_response_type", "Unsupported response_type");
        if (!client.StandardFlowEnabled)
            return Redirect(auth, issuer, "unauthorized_client",
                "Client is not allowed to initiate browser login with given response_type. Standard flow is disabled for the client.");

        var requiredMethod = client.Attributes.GetValueOrDefault("pkce.code.challenge.method") is { Length: > 0 } m ? m : null;
        var challenge = Get("code_challenge");
        var method = Get("code_challenge_method") ?? (challenge is null ? null : "plain");
        if (requiredMethod is not null && challenge is null)
            return Redirect(auth, issuer, "invalid_request", "Missing parameter: code_challenge");
        if (method is not (null or "plain" or "S256") || (requiredMethod is not null && method != requiredMethod))
            return Redirect(auth, issuer, "invalid_request", "Invalid parameter: code_challenge_method");
        if (method is not null) auth["code_challenge_method"] = method;

        var prompt = Get("prompt")?.Split(' ') ?? [];
        var key = RealmKey.For(store, r);
        if (!prompt.Contains("login") && ReadSession(context, key, r, issuer) is var (user, sid, authTime))
        {
            SetSession(context, key, r, issuer, user.Id, sid, authTime);
            return Complete(codes, r, issuer, auth, user, sid, authTime);
        }
        if (prompt.Contains("none")) return Redirect(auth, issuer, "login_required", null);

        return Login(context, r, Jwt.Create(key, auth), Get("login_hint"), null);
    }

    static async Task<IResult> Authenticate(string realm, HttpContext context, Store store, AuthCodes codes)
    {
        if (store.GetRealm(realm) is not { } r) return Error("Realm does not exist.", StatusCodes.Status404NotFound);
        var form = await context.Request.ReadFormAsync();
        var signed = form["auth"].ToString();
        if (ReadAuth(context, store, r, signed) is not { } auth)
            return Error("Your login attempt timed out. Start again from the application.");

        var email = form["email"].ToString().Trim();
        if (email == "") return Login(context, r, signed, null, "Enter an email address.");
        var user = FindByEmail(r, email);
        if (user is null)
            return r.RegistrationAllowed
                ? Register.Page(context, r, signed, auth, email.ToLowerInvariant(), [], [])
                : Login(context, r, signed, email, "No user with that email.");
        if (!user.Enabled) return Login(context, r, signed, email, "Account is disabled, contact your administrator.");
        return SignIn(context, store, codes, r, auth, user);
    }

    internal static User? FindByEmail(Realm realm, string email) =>
        realm.Users.Find(u => string.Equals(u.Username, email, StringComparison.OrdinalIgnoreCase)
            || string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase));

    /// <summary>The pending authorization request carried by the login and registration forms; null when forged or expired.</summary>
    internal static JsonObject? ReadAuth(HttpContext context, Store store, Realm realm, string signed) =>
        Jwt.Validate(RealmKey.For(store, realm), signed, Discovery.Issuer(context.Request, realm.Name)) is { } auth
            && (string?)auth["typ"] == "AuthRequest" ? auth : null;

    /// <summary>Starts a new SSO session for <paramref name="user"/> and answers the pending authorization request.</summary>
    internal static IResult SignIn(HttpContext context, Store store, AuthCodes codes, Realm realm, JsonObject auth, User user)
    {
        var issuer = Discovery.Issuer(context.Request, realm.Name);
        store.Update(_ => user.LastLoginAt = DateTimeOffset.UtcNow);
        var (sid, authTime) = (Guid.NewGuid().ToString(), Now);
        SetSession(context, RealmKey.For(store, realm), realm, issuer, user.Id, sid, authTime);
        return Complete(codes, realm, issuer, auth, user, sid, authTime);
    }

    /// <summary>The authorization endpoint URL that restarts <paramref name="auth"/> at the login page.</summary>
    internal static string RestartUrl(HttpContext context, Realm realm, JsonObject auth) =>
        $"{context.Request.PathBase}/realms/{realm.Name}/protocol/openid-connect/auth" + QueryString.Create(
            carried.Where(n => auth[n] is not null).Select(n => new KeyValuePair<string, string?>(n, (string?)auth[n])));

    static IResult Complete(AuthCodes codes, Realm realm, string issuer, JsonObject auth, User user, string sid, long authTime)
    {
        var code = codes.Issue(new AuthCode(realm.Name, (string)auth["client_id"]!, (string)auth["redirect_uri"]!, (string?)auth["scope"],
            (string?)auth["nonce"], (string?)auth["code_challenge"], (string?)auth["code_challenge_method"], user.Id, sid, authTime,
            DateTimeOffset.UtcNow.AddSeconds(60)));
        return Respond(auth, [new("state", (string?)auth["state"]), new("session_state", sid), new("iss", issuer), new("code", code)]);
    }

    static IResult Redirect(JsonObject auth, string issuer, string error, string? description) =>
        Respond(auth, [new("error", error), new("error_description", description), new("state", (string?)auth["state"]), new("iss", issuer)]);

    /// <summary>Sends the response parameters to the client's redirect URI using the requested response mode.</summary>
    static IResult Respond(JsonObject auth, List<KeyValuePair<string, string?>> values)
    {
        values.RemoveAll(v => v.Value is null);
        var redirectUri = (string)auth["redirect_uri"]!;
        return ((string?)auth["response_mode"] ?? "query") switch
        {
            // No JavaScript allowed, so no auto-submit: the page shows a Continue button.
            "form_post" => Slices.FormPost.Create(new FormPostModel(redirectUri, values)),
            "fragment" => Results.Redirect(redirectUri + "#" + QueryString.Create(values).ToUriComponent()[1..]),
            _ => Results.Redirect(QueryHelpers.AddQueryString(redirectUri, values)),
        };
    }

    /// <summary>Exact match, or Keycloak's trailing <c>*</c> prefix wildcard.</summary>
    static bool Matches(string allowed, string redirectUri) =>
        allowed.EndsWith('*') ? redirectUri.StartsWith(allowed[..^1], StringComparison.Ordinal) : allowed == redirectUri;

    static (User User, string Sid, long AuthTime)? ReadSession(HttpContext context, RealmKey key, Realm realm, string issuer)
    {
        if (context.Request.Cookies[SessionCookie] is not { } raw
            || Jwt.Validate(key, raw, issuer) is not { } session
            || (string?)session["typ"] != "Session"
            || realm.Users.Find(u => u.Id == (string?)session["sub"]) is not { Enabled: true } user)
            return null;
        return (user, (string)session["sid"]!, (long)session["auth_time"]!);
    }

    /// <summary>Issues or refreshes the session cookie: idle timeout from now, capped at the max lifespan from login.</summary>
    static void SetSession(HttpContext context, RealmKey key, Realm realm, string issuer, string userId, string sid, long authTime)
    {
        var token = Jwt.Create(key, new JsonObject
        {
            ["typ"] = "Session", ["iss"] = issuer, ["sub"] = userId, ["sid"] = sid, ["auth_time"] = authTime,
            ["exp"] = Math.Min(Now + realm.SsoSessionIdleTimeout, authTime + realm.SsoSessionMaxLifespan),
        });
        context.Response.Cookies.Append(SessionCookie, token, new CookieOptions
        {
            Path = $"{context.Request.PathBase}/realms/{realm.Name}/",
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
        });
    }

    static IResult Login(HttpContext context, Realm realm, string auth, string? email, string? error)
    {
        var users = realm.Users.OrderByDescending(u => u.LastLoginAt).ThenByDescending(u => u.CreatedTimestamp).ToList();
        var page = Slices.Login.Create(new LoginModel(realm.Name, $"{context.Request.PathBase}/realms/{realm.Name}/login-actions/authenticate",
            auth, email, error, users));
        if (error is not null) page.StatusCode = StatusCodes.Status400BadRequest;
        return page;
    }

    internal static IResult Error(string message, int statusCode = StatusCodes.Status400BadRequest)
    {
        var page = Slices.ErrorPage.Create(new ErrorModel(message));
        page.StatusCode = statusCode;
        return page;
    }

    static long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
}
