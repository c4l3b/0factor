using System.Buffers.Text;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZeroFactor;

/// <summary>A realm's RSA signing key loaded from its persisted <see cref="ZeroFactor.SigningKey"/>.</summary>
public sealed class RealmKey
{
    static readonly ConditionalWeakTable<SigningKey, RealmKey> cache = [];

    public RSA Rsa { get; }
    public X509Certificate2 Certificate { get; }
    /// <summary>RFC 7638 JWK thumbprint, base64url SHA-256.</summary>
    public string Kid { get; }
    public string N { get; }
    public string E { get; }

    RealmKey(SigningKey key)
    {
        Rsa = RSA.Create();
        Rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(key.PrivateKey), out _);
        Certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(key.Certificate));
        var p = Rsa.ExportParameters(false);
        (N, E) = (Base64Url.EncodeToString(p.Modulus), Base64Url.EncodeToString(p.Exponent));
        Kid = Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes($$"""{"e":"{{E}}","kty":"RSA","n":"{{N}}"}""")));
    }

    /// <summary>The realm's key, generating and persisting an RSA 2048 key and self-signed cert on first use.</summary>
    public static RealmKey For(Store store, Realm realm)
    {
        if (realm.SigningKey is null) store.Update(_ => realm.SigningKey ??= Generate(realm.Name));
        return cache.GetValue(realm.SigningKey!, k => new RealmKey(k));
    }

    static SigningKey Generate(string realm)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={realm}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        return new SigningKey
        {
            PrivateKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()),
            Certificate = Convert.ToBase64String(cert.RawData),
        };
    }
}

/// <summary>Minimal RS256 JWS: compact serialization, signature + <c>exp</c> + <c>iss</c> validation.</summary>
public static class Jwt
{
    public static string Create(RealmKey key, JsonObject payload)
    {
        var header = new JsonObject { ["alg"] = "RS256", ["typ"] = "JWT", ["kid"] = key.Kid };
        var signingInput = $"{Encode(header)}.{Encode(payload)}";
        var signature = key.Rsa.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }

    /// <summary>
    /// The payload when the signature is ours, <c>iss</c> matches and (unless <paramref name="allowExpired"/>) <c>exp</c> is in
    /// the future; otherwise null.
    /// </summary>
    public static JsonObject? Validate(RealmKey key, string token, string issuer, bool allowExpired = false)
    {
        var parts = token.Split('.');
        if (parts.Length != 3) return null;
        try
        {
            if (JsonNode.Parse(Base64Url.DecodeFromChars(parts[0])) is not JsonObject header
                || (string?)header["alg"] != "RS256"
                || !key.Rsa.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), Base64Url.DecodeFromChars(parts[2]),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                return null;

            if (JsonNode.Parse(Base64Url.DecodeFromChars(parts[1])) is not JsonObject payload
                || (string?)payload["iss"] != issuer
                || payload["exp"] is not JsonValue exp
                || (!allowExpired && exp.GetValue<long>() <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()))
                return null;
            return payload;
        }
        catch (Exception e) when (e is FormatException or JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    static string Encode(JsonObject json) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(json.ToJsonString()));
}
