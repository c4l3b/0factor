using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace ZeroFactor;

// Keycloak realm-export property names wherever Keycloak has one. Unknown properties are ignored on read.

public class StoreData
{
    public List<Realm> Realms { get; set; } = [];
}

public class Realm
{
    [JsonPropertyName("realm")]
    public string Name { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public bool RegistrationAllowed { get; set; }
    public int AccessTokenLifespan { get; set; } = 300;
    public int SsoSessionIdleTimeout { get; set; } = 1800;
    public int SsoSessionMaxLifespan { get; set; } = 36000;
    public Roles Roles { get; set; } = new();
    public List<Client> Clients { get; set; } = [];
    public List<User> Users { get; set; } = [];

    // 0factor extensions
    public List<RegistrationField>? RegistrationFields { get; set; }
    public bool AgentNotesRequired { get; set; }
    /// <summary>No imported clients: any client_id, redirect URI and secret is accepted. Derived on import.</summary>
    public bool Lenient { get; set; }
    /// <summary>Generated on first use; preserved across re-imports.</summary>
    public SigningKey? SigningKey { get; set; }

    /// <summary>Configured registration fields, or the default: optional first and last name.</summary>
    public List<RegistrationField> Fields => RegistrationFields ??
        [new() { Name = "firstName", Label = "First name" }, new() { Name = "lastName", Label = "Last name" }];

    /// <summary>
    /// Claims from registration fields that set <c>claim</c>, read from the user's attributes, like a Keycloak user-attribute
    /// mapper with the default String type. The token endpoint (#7) adds these to ID token, access token and userinfo.
    /// </summary>
    public JsonObject AttributeClaims(User user)
    {
        var claims = new JsonObject();
        foreach (var field in Fields)
            if (field.Claim is { Length: > 0 } claim && !User.ReservedClaims.Contains(claim)
                && user.Attributes.GetValueOrDefault(field.Name) is [var value, ..])
                claims[claim] = value;
        return claims;
    }

    public User? FindUser(string username) =>
        Users.Find(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));

    /// <summary>Creates any realm or client role the user has that the realm doesn't define yet.</summary>
    public void EnsureRoles(User user)
    {
        foreach (var name in user.RealmRoles)
            if (!Roles.Realm.Exists(r => r.Name == name))
                Roles.Realm.Add(new Role { Name = name });

        foreach (var (clientId, names) in user.ClientRoles)
        {
            if (!Roles.Client.TryGetValue(clientId, out var roles))
                Roles.Client[clientId] = roles = [];
            foreach (var name in names)
                if (!roles.Exists(r => r.Name == name))
                    roles.Add(new Role { Name = name });
        }
    }
}

public class Roles
{
    public List<Role> Realm { get; set; } = [];
    public Dictionary<string, List<Role>> Client { get; set; } = [];
}

public class Role
{
    public string Name { get; set; } = "";
    public string? Description { get; set; }
}

public class Client
{
    public string ClientId { get; set; } = "";
    public string? Secret { get; set; }
    public bool PublicClient { get; set; }
    public List<string> RedirectUris { get; set; } = [];
    public List<string> WebOrigins { get; set; } = [];
    public bool StandardFlowEnabled { get; set; } = true;
    public bool DirectAccessGrantsEnabled { get; set; }
    public bool ServiceAccountsEnabled { get; set; }
    /// <summary>Honored: <c>pkce.code.challenge.method</c>, <c>post.logout.redirect.uris</c>.</summary>
    public Dictionary<string, string> Attributes { get; set; } = [];
    /// <summary>Only <c>oidc-audience-mapper</c> is honored.</summary>
    public List<ProtocolMapper> ProtocolMappers { get; set; } = [];
}

public class ProtocolMapper
{
    public string Name { get; set; } = "";
    public string Protocol { get; set; } = "openid-connect";
    [JsonPropertyName("protocolMapper")]
    public string Mapper { get; set; } = "";
    public Dictionary<string, string> Config { get; set; } = [];
}

public class User
{
    public string Id { get; set; } = "";
    public string Username { get; set; } = "";
    public string? Email { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public bool Enabled { get; set; } = true;
    public bool EmailVerified { get; set; } = true;
    public Dictionary<string, List<string>> Attributes { get; set; } = [];
    public List<string> RealmRoles { get; set; } = [];
    public Dictionary<string, List<string>> ClientRoles { get; set; } = [];
    public long CreatedTimestamp { get; set; }

    /// <summary>Read from Keycloak exports only so service-account users can be skipped on import.</summary>
    public string? ServiceAccountClientId { get; set; }

    // 0factor extensions
    public string? AgentNotes { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
    /// <summary>Listed first on the login page.</summary>
    public bool Pinned { get; set; }
    /// <summary>Left off the login page's user list; typing the email still signs in.</summary>
    public bool Hidden { get; set; }
    /// <summary>Arbitrary JSON merged into tokens and userinfo. Names in <see cref="ReservedClaims"/> are rejected.</summary>
    public JsonObject? Claims { get; set; }

    /// <summary>Claims 0factor sets itself; roles go through role fields and audiences through audience mappers.</summary>
    public static readonly HashSet<string> ReservedClaims = ["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "auth_time", "azp", "typ",
        "sid", "session_state", "nonce", "at_hash", "acr", "scope", "realm_access", "resource_access"];

    /// <summary>The reserved names used in <paramref name="claims"/>, empty when none.</summary>
    public static List<string> Reserved(JsonObject? claims) =>
        claims is null ? [] : claims.Select(c => c.Key).Where(ReservedClaims.Contains).ToList();
}

public class SigningKey
{
    /// <summary>Base64 PKCS#8 RSA private key.</summary>
    public string PrivateKey { get; set; } = "";
    /// <summary>Base64 DER self-signed X.509 certificate for the key (JWKS <c>x5c</c>).</summary>
    public string Certificate { get; set; } = "";
}

public class RegistrationField
{
    public string Name { get; set; } = "";
    public string? Label { get; set; }
    public string Type { get; set; } = "text";
    public bool Required { get; set; }
    public List<string>? Options { get; set; }
    public string? Claim { get; set; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = true,
    AllowTrailingCommas = true,
    ReadCommentHandling = JsonCommentHandling.Skip)]
[JsonSerializable(typeof(StoreData))]
[JsonSerializable(typeof(Realm))]
[JsonSerializable(typeof(List<RegistrationField>))]
public partial class StoreJsonContext : JsonSerializerContext;
