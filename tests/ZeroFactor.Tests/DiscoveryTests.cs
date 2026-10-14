using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace ZeroFactor.Tests;

public sealed class DiscoveryTests : IDisposable
{
    const string Issuer = "http://localhost/realms/test";
    readonly string dataDir = Directory.CreateTempSubdirectory("zf-data-").FullName;
    readonly List<WebApplicationFactory<Program>> factories = [];

    public void Dispose()
    {
        factories.ForEach(f => f.Dispose());
        Directory.Delete(dataDir, true);
    }

    WebApplicationFactory<Program> Start(params (string Key, string Value)[] settings)
    {
        var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("ZF_DATA_DIR", dataDir).UseSetting("ZF_IMPORT_DIR", Path.Combine(dataDir, "none"));
            foreach (var (key, value) in settings) b.UseSetting(key, value);
        });
        factories.Add(factory);
        return factory;
    }

    static RealmKey Key(WebApplicationFactory<Program> factory, string realm = "test")
    {
        var store = factory.Services.GetRequiredService<Store>();
        return RealmKey.For(store, store.GetRealm(realm)!);
    }

    static async Task<JsonObject> GetJson(HttpClient client, string url)
    {
        var response = await client.GetAsync(url, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        return JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
    }

    static long Now(int offset = 0) => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + offset;

    [Fact]
    public async Task Signed_token_validates_with_IdentityModel_using_keys_from_our_jwks()
    {
        var factory = Start();
        var client = factory.CreateClient();
        var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
            $"{Issuer}/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(client) { RequireHttps = false });
        var config = await manager.GetConfigurationAsync(TestContext.Current.CancellationToken);

        var token = Jwt.Create(Key(factory), new JsonObject
        {
            ["iss"] = Issuer, ["sub"] = "alice", ["aud"] = "web", ["exp"] = Now(300), ["iat"] = Now(),
            ["org"] = new JsonObject { ["id"] = 42 },
        });
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = config.Issuer,
            ValidAudience = "web",
            IssuerSigningKeys = config.SigningKeys,
        });

        Assert.True(result.IsValid, result.Exception?.ToString());
        Assert.Equal(Issuer, config.Issuer);
        var jwt = (JsonWebToken)result.SecurityToken;
        Assert.Equal(Key(factory).Kid, jwt.Kid);
        Assert.Equal("JWT", jwt.Typ);
        Assert.Equal("alice", jwt.Subject);

        // The x5c certificate alone is enough too, for libraries that only read it.
        var jwk = Assert.Single(config.JsonWebKeySet.Keys);
        var certKey = new X509SecurityKey(System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(Convert.FromBase64String(jwk.X5c[0])));
        var viaCert = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = Issuer, ValidAudience = "web", IssuerSigningKey = certKey, TryAllIssuerSigningKeys = true,
        });
        Assert.True(viaCert.IsValid, viaCert.Exception?.ToString());
        Assert.Equal(Base64UrlEncoder.Encode(certKey.Certificate.GetCertHash()), jwk.X5t);
    }

    [Fact]
    public void Validate_checks_signature_expiry_and_issuer()
    {
        var factory = Start();
        var key = Key(factory);
        string Sign(string iss, long exp) => Jwt.Create(key, new JsonObject { ["iss"] = iss, ["exp"] = exp, ["sub"] = "alice" });

        var good = Sign(Issuer, Now(60));
        Assert.Equal("alice", (string?)Jwt.Validate(key, good, Issuer)!["sub"]);

        Assert.Null(Jwt.Validate(key, Sign(Issuer, Now(-1)), Issuer));
        Assert.Null(Jwt.Validate(key, Sign("http://evil/realms/test", Now(60)), Issuer));
        Assert.Null(Jwt.Validate(Key(factory, "other"), good, Issuer));
        var parts = good.Split('.');
        var forged = System.Buffers.Text.Base64Url.EncodeToString("""{"iss":"http://localhost/realms/test","exp":9999999999,"sub":"bob"}"""u8);
        Assert.Null(Jwt.Validate(key, $"{parts[0]}.{forged}.{parts[2]}", Issuer));
        Assert.Null(Jwt.Validate(key, "not.a.jwt", Issuer));
        Assert.Null(Jwt.Validate(key, "garbage", Issuer));
    }

    [Fact]
    public async Task Discovery_matches_Keycloak_26_names_and_shapes()
    {
        var ours = await GetJson(Start().CreateClient(), "/realms/test/.well-known/openid-configuration");
        var keycloak = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "keycloak-26-discovery.json")))!.AsObject();
        var keycloakIssuer = (string)keycloak["issuer"]!;

        foreach (var (name, value) in ours)
        {
            Assert.True(keycloak.ContainsKey(name), $"Keycloak has no {name}");
            var expected = keycloak[name]!;
            Assert.Equal(expected.GetValueKind(), value!.GetValueKind());
            switch (value.GetValueKind())
            {
                case JsonValueKind.String:
                    Assert.Equal(((string)expected!).Replace(keycloakIssuer, Issuer), (string)value!);
                    break;
                case JsonValueKind.Array:
                    Assert.Subset(expected.AsArray().Select(v => (string)v!).ToHashSet(), value.AsArray().Select(v => (string)v!).ToHashSet());
                    break;
                default:
                    Assert.True(JsonNode.DeepEquals(expected, value), name);
                    break;
            }
        }
        string[] required = ["issuer", "authorization_endpoint", "token_endpoint", "introspection_endpoint", "userinfo_endpoint",
            "end_session_endpoint", "check_session_iframe", "jwks_uri", "revocation_endpoint", "grant_types_supported", "response_types_supported",
            "response_modes_supported", "subject_types_supported", "id_token_signing_alg_values_supported",
            "code_challenge_methods_supported", "token_endpoint_auth_methods_supported", "scopes_supported", "claims_supported",
            "authorization_response_iss_parameter_supported"];
        Assert.All(required, name => Assert.True(ours.ContainsKey(name), name));
    }

    [Fact]
    public async Task Jwks_and_realm_info_have_Keycloak_shape_and_key_survives_restart()
    {
        var client = Start().CreateClient();
        var jwk = Assert.Single((await GetJson(client, "/realms/test/protocol/openid-connect/certs"))["keys"]!.AsArray())!.AsObject();
        Assert.Equal(["kid", "kty", "alg", "use", "x5c", "x5t", "x5t#S256", "n", "e"], jwk.Select(p => p.Key));
        Assert.Equal("RSA", (string?)jwk["kty"]);
        Assert.Equal("RS256", (string?)jwk["alg"]);
        Assert.Equal("sig", (string?)jwk["use"]);
        Assert.Equal("AQAB", (string?)jwk["e"]);
        Assert.Equal(2048, Base64UrlEncoder.DecodeBytes((string)jwk["n"]!).Length * 8);
        // RFC 7638 thumbprint, as IdentityModel computes it.
        Assert.Equal((string?)jwk["kid"], Base64UrlEncoder.Encode(JsonWebKey.Create(jwk.ToJsonString()).ComputeJwkThumbprint()));

        var raw = await client.GetStringAsync("/realms/test", TestContext.Current.CancellationToken);
        Assert.DoesNotContain("\\u002B", raw);
        var info = await GetJson(client, "/realms/test");
        Assert.Equal(["realm", "public_key", "token-service", "account-service", "tokens-not-before"], info.Select(p => p.Key));
        Assert.Equal("test", (string?)info["realm"]);
        Assert.Equal($"{Issuer}/protocol/openid-connect", (string?)info["token-service"]);
        Assert.Equal($"{Issuer}/account", (string?)info["account-service"]);
        Assert.Equal(0, (int)info["tokens-not-before"]!);
        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String((string)info["public_key"]!), out _);
        Assert.Equal((string?)jwk["n"], Base64UrlEncoder.Encode(rsa.ExportParameters(false).Modulus));

        Assert.Contains("\"signingKey\"", File.ReadAllText(Path.Combine(dataDir, "0factor.json")));
        factories[0].Dispose();
        factories.Clear();
        var restarted = await GetJson(Start().CreateClient(), "/realms/test/protocol/openid-connect/certs");
        Assert.Equal((string?)jwk["kid"], (string?)restarted["keys"]![0]!["kid"]);
    }

    [Fact]
    public void Reimport_keeps_the_signing_key()
    {
        var importDir = Directory.CreateTempSubdirectory("zf-import-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(importDir, "shop.json"), """{ "realm": "shop" }""");
            var store = Store.Open(dataDir);
            store.Import(importDir);
            var kid = RealmKey.For(store, store.GetRealm("shop")!).Kid;

            var reopened = Store.Open(dataDir);
            reopened.Import(importDir);
            Assert.Equal(kid, RealmKey.For(reopened, reopened.GetRealm("shop")!).Kid);
        }
        finally
        {
            Directory.Delete(importDir, true);
        }
    }

    [Fact]
    public async Task Issuer_honors_forwarded_headers_and_ZF_HOSTNAME()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/realms/test/.well-known/openid-configuration");
        request.Headers.Add("X-Forwarded-Proto", "https");
        request.Headers.Add("X-Forwarded-Host", "auth.example.test:8443");
        var response = await Start().CreateClient().SendAsync(request, TestContext.Current.CancellationToken);
        var doc = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("https://auth.example.test:8443/realms/test", (string?)doc["issuer"]);

        var fixedHost = await GetJson(Start(("ZF_HOSTNAME", "https://id.example.test/")).CreateClient(), "/realms/test/.well-known/openid-configuration");
        Assert.Equal("https://id.example.test/realms/test", (string?)fixedHost["issuer"]);
        Assert.Equal("https://id.example.test/realms/test/protocol/openid-connect/certs", (string?)fixedHost["jwks_uri"]);
    }

    [Theory]
    [InlineData("http://localhost")]
    [InlineData("https://old.example.test/legacy/")]
    public async Task Issuer_override_preserves_exact_value_and_realm_endpoint_urls(string issuer)
    {
        var client = Start(("ZF_ISSUER", issuer), ("ZF_HOSTNAME", "https://id.example.test/")).CreateClient();
        var doc = await GetJson(client, "/realms/test/.well-known/openid-configuration");
        Assert.Equal(issuer, (string?)doc["issuer"]);
        foreach (var name in new[] { "authorization_endpoint", "token_endpoint", "introspection_endpoint", "userinfo_endpoint",
                     "end_session_endpoint", "check_session_iframe", "jwks_uri", "revocation_endpoint" })
            Assert.StartsWith("https://id.example.test/realms/test/protocol/openid-connect/", (string?)doc[name]);
        var info = await GetJson(client, "/realms/test");
        Assert.Equal("https://id.example.test/realms/test/protocol/openid-connect", (string?)info["token-service"]);
        var page = await client.GetStringAsync("/_0factor/realms/test", TestContext.Current.CancellationToken);
        Assert.Contains("https://id.example.test/realms/test/.well-known/openid-configuration", page);
    }

    [Theory]
    [InlineData("/realms/nope/.well-known/openid-configuration")]
    [InlineData("/realms/nope/protocol/openid-connect/certs")]
    [InlineData("/realms/nope")]
    public async Task Unknown_realm_in_strict_mode_is_Keycloak_404(string url)
    {
        var response = await Start(("ZF_STRICT", "true")).CreateClient().GetAsync(url, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("""{"error":"Realm does not exist"}""", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
}
