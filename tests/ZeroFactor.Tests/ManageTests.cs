using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using static ZeroFactor.Tests.AuthorizeTests;
using static ZeroFactor.Tests.TokenTests;

namespace ZeroFactor.Tests;

public sealed class ManageTests : IDisposable
{
    const string Request = "client_id=web&redirect_uri=http://app.test/cb&response_type=code&state=s1";
    readonly string dataDir = Directory.CreateTempSubdirectory("zf-data-").FullName;
    readonly string importDir = Directory.CreateTempSubdirectory("zf-import-").FullName;
    readonly List<IDisposable> disposables = [];
    static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        disposables.ForEach(d => d.Dispose());
        Directory.Delete(dataDir, true);
        Directory.Delete(importDir, true);
    }

    (WebApplicationFactory<Program> Factory, HttpClient Client, Store Store) Start()
    {
        File.Copy(Path.Combine(AppContext.BaseDirectory, "fixtures", "shop-realm.json"), Path.Combine(importDir, "shop-realm.json"));
        File.WriteAllText(Path.Combine(importDir, "test.json"), """
            { "realm": "test", "users": [
              { "username": "alice@example.com", "email": "alice@example.com", "firstName": "Alice", "agentNotes": "old notes" },
              { "username": "dave@example.com", "email": "dave@example.com", "agentNotes": "dave" } ] }
            """);
        var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b => b
            .UseSetting("ZF_DATA_DIR", dataDir).UseSetting("ZF_IMPORT_DIR", importDir));
        disposables.Add(factory);
        return (factory, Browser(factory), factory.Services.GetRequiredService<Store>());
    }

    static Task<HttpResponseMessage> Edit(HttpClient client, string realm, User user, string notes, string realmRoles = "",
        string clientRoles = "", string claims = "") =>
        client.PostAsync($"/_0factor/realms/{realm}/users/{user.Id}", new FormUrlEncodedContent([new("realmRoles", realmRoles),
            new("clientRoles", clientRoles), new("claims", claims), new("agentNotes", notes)]), Ct);

    static async Task<string> Page(HttpClient client, string url)
    {
        var response = await client.GetAsync(url, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await Html(response);
    }

    [Fact]
    public async Task Realm_list_and_page_show_users_clients_and_discovery_url()
    {
        var (_, client, store) = Start();

        var realms = await Page(client, "/_0factor/");
        Assert.Contains("href=\"realms/shop\"", realms);
        Assert.Contains("href=\"realms/test\"", realms);

        var shop = await Page(client, "/_0factor/realms/shop");
        Assert.Contains("value=\"http://localhost/realms/shop/.well-known/openid-configuration\"", shop);
        Assert.Contains("data-testid=\"client-store.web\"", shop);
        Assert.Contains("<td>confidential</td>", shop);
        Assert.Contains("<label for=\"alice@example.com-agentNotes\">", shop);
        Assert.Contains(">Delete user alice@example.com</button>", shop);
        var alice = store.GetRealm("shop")!.FindUser("alice@example.com")!;
        Assert.Contains($"action=\"/_0factor/realms/shop/users/{alice.Id}\"", shop);
        Assert.Contains($"action=\"/_0factor/realms/shop/users/{alice.Id}/delete\"", shop);

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/_0factor/realms/nope", Ct)).StatusCode);
        Assert.DoesNotContain("data-testid=\"realm-nope\"", await Page(client, "/_0factor/"));
    }

    [Fact]
    public async Task User_with_a_chosen_id_is_shown_and_editable()
    {
        var (_, client, store) = Start();
        var realm = store.GetRealm("test")!;
        store.AddUser(realm, new User { Id = "auth0|seed/42", Username = "seed@example.com", Email = "seed@example.com" });

        var page = await Page(client, "/_0factor/realms/test");
        Assert.Contains("<dd data-testid=\"user-id\">auth0|seed/42</dd>", page);
        Assert.Contains("action=\"/_0factor/realms/test/users/auth0%7Cseed%2F42\"", page);

        Assert.Equal(HttpStatusCode.Redirect, (await client.PostAsync("/_0factor/realms/test/users/auth0%7Cseed%2F42",
            new FormUrlEncodedContent([new("agentNotes", "seeded")]), Ct)).StatusCode);
        Assert.Equal("seeded", realm.FindUser("seed@example.com")!.AgentNotes);
        Assert.Equal(HttpStatusCode.Redirect, (await client.PostAsync("/_0factor/realms/test/users/auth0%7Cseed%2F42/delete", null, Ct)).StatusCode);
        Assert.Null(realm.FindUser("seed@example.com"));
    }

    [Fact]
    public async Task Edited_notes_show_on_the_login_page()
    {
        var (_, client, store) = Start();
        var alice = store.GetRealm("test")!.FindUser("alice@example.com")!;

        var saved = await Edit(client, "test", alice, "admin in tenant acme");
        Assert.Equal(HttpStatusCode.Redirect, saved.StatusCode);
        Assert.Equal("/_0factor/realms/test?saved=alice@example.com", saved.Headers.Location?.OriginalString);
        Assert.Contains("Saved alice@example.com.", await Page(client, saved.Headers.Location!.OriginalString));

        var login = await Page(client, Auth("test", Request));
        Assert.Contains("admin in tenant acme", login);
        Assert.DoesNotContain("old notes", login);
    }

    [Fact]
    public async Task Added_role_and_claim_reach_the_next_token_and_refresh()
    {
        var (factory, client, store) = Start();
        var api = factory.CreateClient();
        var alice = store.GetRealm("test")!.FindUser("alice@example.com")!;
        var before = await Exchange(api, "test", ("grant_type", "password"), ("client_id", "web"), ("username", "alice@example.com"));

        Assert.Equal(HttpStatusCode.Redirect, (await Edit(client, "test", alice, "notes", "admin", "store.api:orders.write",
            """{"tenant_id": "acme"}""")).StatusCode);
        Assert.Contains(store.GetRealm("test")!.Roles.Realm, r => r.Name == "admin");

        var next = Payload((string)(await Exchange(api, "test", ("grant_type", "password"), ("client_id", "web"),
            ("username", "alice@example.com")))["access_token"]!);
        var refreshed = Payload((string)(await Exchange(api, "test", ("grant_type", "refresh_token"), ("client_id", "web"),
            ("refresh_token", (string)before["refresh_token"]!)))["access_token"]!);
        foreach (var token in new[] { next, refreshed })
        {
            Assert.Contains("admin", token["realm_access"]!["roles"]!.AsArray().Select(n => (string?)n));
            Assert.Equal("orders.write", (string?)token["resource_access"]!["store.api"]!["roles"]![0]);
            Assert.Equal("acme", (string?)token["tenant_id"]);
        }
        Assert.Null(Payload((string)before["access_token"]!)["tenant_id"]);

        // Same validation as registration; nothing is saved on error.
        var bad = await Edit(client, "test", alice, "", claims: """{"sub": "x"}""");
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        var html = await Html(bad);
        Assert.Contains("data-testid=\"alice@example.com-claims-error\">Reserved claim names can&#x27;t be set: sub.", html);
        Assert.DoesNotContain("data-testid=\"alice@example.com-agentNotes-error\"", html);
        Assert.Equal("acme", (string?)alice.Claims!["tenant_id"]);
    }

    [Fact]
    public async Task Service_account_user_is_listed_and_editable()
    {
        var (factory, client, store) = Start();
        var api = factory.CreateClient();
        (string, string)[] credentials = [("grant_type", "client_credentials"), ("client_id", "store.api"), ("client_secret", "api-secret")];
        await Exchange(api, "shop", credentials);
        var account = store.GetRealm("shop")!.FindUser("service-account-store.api")!;

        Assert.Contains("data-testid=\"user-service-account-store.api\"", await Page(client, "/_0factor/realms/shop"));
        Assert.Equal(HttpStatusCode.Redirect, (await Edit(client, "shop", account, "orders api", "admin", claims: """{"tenant_id": "acme"}""")).StatusCode);

        var access = Payload((string)(await Exchange(api, "shop", credentials))["access_token"]!);
        Assert.Contains("admin", access["realm_access"]!["roles"]!.AsArray().Select(n => (string?)n));
        Assert.Equal("acme", (string?)access["tenant_id"]);
    }

    [Fact]
    public async Task Deleted_user_is_gone_from_login_page_and_data_file()
    {
        var (_, client, store) = Start();
        var dave = store.GetRealm("test")!.FindUser("dave@example.com")!;
        Assert.Contains("dave@example.com", await Page(client, Auth("test", Request)));

        var deleted = await client.PostAsync($"/_0factor/realms/test/users/{dave.Id}/delete", null, Ct);
        Assert.Equal(HttpStatusCode.Redirect, deleted.StatusCode);
        Assert.Contains("Deleted dave@example.com.", await Page(client, deleted.Headers.Location!.OriginalString));

        Assert.DoesNotContain("dave@example.com", await Page(client, Auth("test", Request)));
        Assert.DoesNotContain("dave@example.com", await File.ReadAllTextAsync(Path.Combine(dataDir, "0factor.json"), Ct));
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync($"/_0factor/realms/test/users/{dave.Id}/delete", null, Ct)).StatusCode);
    }
}
