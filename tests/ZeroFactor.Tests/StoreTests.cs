using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace ZeroFactor.Tests;

public sealed class StoreTests : IDisposable
{
    readonly string dataDir = Directory.CreateTempSubdirectory("zf-data-").FullName;
    readonly string importDir = Directory.CreateTempSubdirectory("zf-import-").FullName;

    public void Dispose()
    {
        Directory.Delete(dataDir, true);
        Directory.Delete(importDir, true);
    }

    static string Json(Realm realm) => JsonSerializer.Serialize(realm, StoreJsonContext.Default.Realm);

    void ImportFile(string name, string json) => File.WriteAllText(Path.Combine(importDir, name), json);

    [Fact]
    public void Keycloak_export_imports_persists_and_survives_restart()
    {
        File.Copy(Path.Combine(AppContext.BaseDirectory, "fixtures", "shop-realm.json"), Path.Combine(importDir, "shop-realm.json"));

        var first = Store.Open(dataDir);
        first.Import(importDir);
        var realm = first.GetRealm("shop")!;

        Assert.False(realm.Lenient);
        Assert.True(realm.RegistrationAllowed);
        Assert.Equal(600, realm.AccessTokenLifespan);
        Assert.Contains(realm.Roles.Realm, r => r.Name == "admin");
        Assert.Contains(realm.Roles.Client["store.api"], r => r.Name == "orders.write");

        var web = realm.Clients.Single(c => c.ClientId == "store.web");
        Assert.Equal("web-secret", web.Secret);
        Assert.Equal(["https://localhost:7001/signin-oidc"], web.RedirectUris);
        Assert.Equal("S256", web.Attributes["pkce.code.challenge.method"]);
        Assert.Equal("+", web.Attributes["post.logout.redirect.uris"]);
        var audience = Assert.Single(web.ProtocolMappers);
        Assert.Equal("oidc-audience-mapper", audience.Mapper);
        Assert.Equal("store.api", audience.Config["included.client.audience"]);
        Assert.True(realm.Clients.Single(c => c.ClientId == "store.spa").PublicClient);

        Assert.Equal(["alice@example.com", "bob@example.com"], realm.Users.Select(u => u.Username).Order());
        var alice = realm.FindUser("alice@example.com")!;
        Assert.Equal("a427a505-292b-4658-9be0-7e10d816d861", alice.Id);
        Assert.Equal(["acme"], alice.Attributes["tenant"]);
        Assert.Contains("admin", alice.RealmRoles);
        Assert.Equal(["orders.read", "orders.write"], alice.ClientRoles["store.api"]);

        var imported = Json(realm);
        Assert.Equal(imported, Json(Store.Open(dataDir).GetRealm("shop")!));

        var resynced = Store.Open(dataDir);
        resynced.Import(importDir);
        Assert.Equal(imported, Json(resynced.GetRealm("shop")!));
    }

    [Fact]
    public void Corrupt_data_file_fails_startup_and_is_not_modified()
    {
        var path = Path.Combine(dataDir, "0factor.json");
        File.WriteAllText(path, """{ "realms": [ { "realm": "shop", """);
        var before = File.ReadAllBytes(path);

        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b
            .UseSetting("ZF_DATA_DIR", dataDir)
            .UseSetting("ZF_IMPORT_DIR", importDir));

        var error = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("0factor.json", error.ToString());
        Assert.Equal(before, File.ReadAllBytes(path));
        Assert.Equal(["0factor.json"], Directory.GetFiles(dataDir).Select(Path.GetFileName));
    }

    [Fact]
    public void Resync_overwrites_file_data_keeps_registered_users_and_creates_missing_roles()
    {
        ImportFile("shop.json", """
            {
              "realm": "shop",
              "users": [
                { "username": "Alice@Example.com", "realmRoles": ["admin"], "clientRoles": { "store.api": ["orders.write"] },
                  "claims": { "tenant_id": "acme", "org": { "id": 42 } }, "agentNotes": "admin" }
              ]
            }
            """);
        var store = Store.Open(dataDir);
        store.Import(importDir);
        var realm = store.GetRealm("shop")!;
        var aliceId = realm.FindUser("alice@example.com")!.Id;
        store.Update(_ => realm.Users.Add(new User { Id = "registered", Username = "carol@example.com" }));
        store.Update(_ => realm.Users.Add(new User { Id = "taken", Username = "erin@example.com" }));

        Assert.True(realm.Lenient);
        Assert.Contains(realm.Roles.Realm, r => r.Name == "admin");
        Assert.Contains(realm.Roles.Client["store.api"], r => r.Name == "orders.write");
        Assert.Equal(42, (int)realm.FindUser("alice@example.com")!.Claims!["org"]!["id"]!);

        ImportFile("shop.json", """{ "realm": "shop", "accessTokenLifespan": 60, "users": [ { "username": "alice@example.com", "agentNotes": "edited" }, { "id": "taken", "username": "bob@example.com" } ] }""");
        store = Store.Open(dataDir);
        store.Import(importDir);
        realm = store.GetRealm("shop")!;

        Assert.Equal(60, realm.AccessTokenLifespan);
        Assert.Empty(realm.Roles.Realm);
        var alice = realm.FindUser("alice@example.com")!;
        Assert.Equal(aliceId, alice.Id);
        Assert.Equal("edited", alice.AgentNotes);
        Assert.Equal("registered", realm.FindUser("carol@example.com")!.Id);
        // A file user's id wins over a registered user that chose the same id.
        Assert.Equal("taken", realm.FindUser("bob@example.com")!.Id);
        Assert.Null(realm.FindUser("erin@example.com"));
    }

    [Fact]
    public void Lenient_realms_auto_create_and_accept_any_client()
    {
        var store = Store.Open(dataDir);
        var realm = store.GetRealm("anything")!;

        Assert.True(realm.RegistrationAllowed);
        Assert.NotNull(store.GetClient(realm, "my-app"));
        Assert.Contains("\"my-app\"", File.ReadAllText(Path.Combine(dataDir, "0factor.json")));
    }

    [Fact]
    public void Imported_clients_and_strict_mode_reject_unknowns()
    {
        ImportFile("shop.json", """{ "realm": "shop", "clients": [ { "clientId": "web" } ] }""");
        var store = Store.Open(dataDir);
        store.Import(importDir);
        var realm = store.GetRealm("shop")!;

        Assert.NotNull(store.GetClient(realm, "web"));
        Assert.Null(store.GetClient(realm, "other"));

        Store.Open(dataDir).GetRealm("auto");
        var strict = Store.Open(dataDir, strict: true);
        Assert.Null(strict.GetRealm("unknown"));
        Assert.Null(strict.GetClient(strict.GetRealm("auto")!, "other"));
    }

    [Fact]
    public void Import_rejects_reserved_claim_names()
    {
        ImportFile("bad.json", """{ "realm": "bad", "users": [{ "username": "a@example.com", "claims": { "tenant": "x", "aud": "y" } }] }""");
        var e = Assert.Throws<InvalidOperationException>(() => Store.Open(dataDir).Import(importDir));
        Assert.Contains("user a@example.com sets reserved claims: aud.", e.Message);
    }
}
