extern alias AppHost;
extern alias BasicAppHost;

using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Aspire.Hosting.Testing;

namespace ZeroFactor.Tests;

/// <summary>
/// The samples/ AppHost with the real 0factor container, driven like a browser with no browser: HttpClient, cookies and
/// form posts only. Web and Api use the official Aspire.Keycloak.Authentication handlers, unchanged.
/// </summary>
public class EndToEndTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;

    record Page(Uri Uri, string Html);

    [Theory]
    [InlineData("", "")]
    [InlineData("Avery", "Reader")]
    public async Task Basic_sample_shows_the_registered_email_and_optional_name(string firstName, string lastName)
    {
        var image = Environment.GetEnvironmentVariable("ZF_E2E_IMAGE");
        Assert.SkipWhen(string.IsNullOrEmpty(image), "Set ZF_E2E_IMAGE to a locally built 0factor image to run the end-to-end test.");

        var appHost = await DistributedApplicationTestingBuilder.CreateAsync<BasicAppHost::Projects.BasicAppHost>(Ct);
        var provider = appHost.Resources.OfType<ZeroFactorResource>().Single();
        var endpoint = provider.Annotations.OfType<EndpointAnnotation>().Single();
        endpoint.Port = null;
        endpoint.IsProxied = true;
        var container = provider.Annotations.OfType<ContainerImageAnnotation>().Single();
        var colon = image.LastIndexOf(':');
        container.Registry = null;
        (container.Image, container.Tag) = colon > image.LastIndexOf('/') ? (image[..colon], image[(colon + 1)..]) : (image, "latest");

        await using var app = await appHost.BuildAsync(Ct);
        await app.StartAsync(Ct);
        await app.ResourceNotifications.WaitForResourceHealthyAsync("auth", Ct);
        var web = app.GetEndpoint("web", "http");
        await Listening(web);

        using var browser = new HttpClient(new HttpClientHandler { CookieContainer = new() });
        var home = await Get(browser, web);
        Assert.Contains("data-testid=\"login\"", home.Html);
        Assert.DoesNotContain("data-testid=\"profile\"", home.Html);

        // No import: discovery creates the realm, and the real ASP.NET OIDC handler registers this client.
        var login = await Get(browser, new Uri(web, "/login"));
        Assert.Contains("Sign in to basic-sample", login.Html);
        var email = $"basic-{Guid.NewGuid():N}@example.com";
        var register = await Read(await Submit(browser, login, "login-form", ("email", email)));
        var callback = await Read(await Submit(browser, register, "register-form",
            ("email", email), ("firstName", firstName), ("lastName", lastName)));
        home = await Read(await Submit(browser, callback, "form-post"));

        Assert.Equal(web.AbsolutePath, home.Uri.AbsolutePath);
        Assert.Contains("data-testid=\"profile\"", home.Html);
        Assert.Contains($"data-testid=\"user-email\">{email}</dd>", home.Html);
        Assert.DoesNotContain("data-testid=\"login\"", home.Html);
        if (firstName.Length == 0)
            Assert.DoesNotContain("data-testid=\"user-name\"", home.Html);
        else
            Assert.Contains($"data-testid=\"user-name\">{firstName} {lastName}</dd>", home.Html);

        // A subsequent visit uses the app's session cookie.
        Assert.Contains(email, (await Get(browser, web)).Html);

        Assert.Contains("data-testid=\"logout\"", home.Html);
        home = await Get(browser, new Uri(web, "/logout"));
        Assert.Contains("data-testid=\"login\"", home.Html);
        Assert.DoesNotContain("data-testid=\"profile\"", home.Html);
        Assert.DoesNotContain("data-testid=\"logout\"", home.Html);
        // Ending the provider session prevents the next login from silently signing us straight back in.
        Assert.Contains("Sign in to basic-sample", (await Get(browser, new Uri(web, "/login"))).Html);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Sample_signs_in_calls_the_api_and_signs_out_through_0factor(bool fixedPort)
    {
        // The image under test, e.g. `docker build -t 0factor:e2e .` then ZF_E2E_IMAGE=0factor:e2e. CI does both.
        var image = Environment.GetEnvironmentVariable("ZF_E2E_IMAGE");
        Assert.SkipWhen(string.IsNullOrEmpty(image), "Set ZF_E2E_IMAGE to a locally built 0factor image to run the end-to-end test.");

        var appHost = await DistributedApplicationTestingBuilder.CreateAsync<AppHost::Projects.AppHost>(Ct);
        var provider = appHost.Resources.OfType<ZeroFactorResource>().Single();
        var endpoint = provider.Annotations.OfType<EndpointAnnotation>().Single();
        Assert.False(endpoint.IsProxied); // AddZeroFactor with a fixed port must keep that port in testing.
        if (fixedPort)
        {
            // Avoid colliding with an AppHost already running on the developer's default port.
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            endpoint.Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        else
        {
            endpoint.Port = null;
            endpoint.IsProxied = true;
        }
        var container = provider.Annotations.OfType<ContainerImageAnnotation>().Single();
        var colon = image.LastIndexOf(':');
        container.Registry = null;
        (container.Image, container.Tag) = colon > image.LastIndexOf('/') ? (image[..colon], image[(colon + 1)..]) : (image, "latest");
        await using var app = await appHost.BuildAsync(Ct);
        await app.StartAsync(Ct);
        await app.ResourceNotifications.WaitForResourceHealthyAsync("keycloak", Ct);
        var (web, api, zf) = (app.GetEndpoint("web", "http"), app.GetEndpoint("api", "http"), app.GetEndpoint("keycloak", "http"));
        if (fixedPort) Assert.Equal(endpoint.Port, zf.Port);
        using var metadataClient = new HttpClient();
        var metadata = JsonNode.Parse(await metadataClient.GetStringAsync(new Uri(zf, "/realms/shop/.well-known/openid-configuration"), Ct))!;
        Assert.Equal(new Uri(zf, "/realms/shop").ToString(), (string?)metadata["issuer"]);
        await Listening(web);
        await Listening(api);

        var browser = new HttpClient(new HttpClientHandler { CookieContainer = new() });
        var email = $"e2e-{Guid.NewGuid():N}@example.com";
        const string notes = "Created by the end-to-end test.";

        // Unknown email: Web -> 0factor login -> registration -> form_post back to Web, signed in.
        var login = await Get(browser, new Uri(web, "/admin"));
        Assert.Contains("Sign in to shop", login.Html);
        var register = await Read(await Submit(browser, login, "login-form", ("email", email)));
        Assert.Contains("Create a user in shop", register.Html);
        var formPost = await Read(await Submit(browser, register, "register-form", ("email", email), ("firstName", "Erin"), ("agentNotes", notes)));
        Assert.Equal(HttpStatusCode.Forbidden, (await Submit(browser, formPost, "form-post")).StatusCode); // signed in, not admin
        Assert.Contains($"Signed in as {email}", (await Get(browser, web)).Html);

        // Web calls Api with the user's access token; the tenant policy needs a tenant_id claim.
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync(new Uri(web, "/call/orders"), Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.GetAsync(new Uri(web, "/call/tenant"), Ct)).StatusCode);

        // Management page: make the user an admin in tenant acme.
        var manage = await Get(browser, new Uri(zf, "/_0factor/realms/shop"));
        var saved = await Read(await Submit(browser, manage, $"edit-{email}", ("realmRoles", "admin"), ("claims", """{"tenant_id": "acme"}"""),
            ("agentNotes", notes)));
        Assert.Contains($"Saved {email}.", saved.Html);

        // Sign out; the next sign-in shows the user with its notes, and one click signs in with the new role and claim.
        Assert.Contains("data-testid=\"sign-in\"", (await Get(browser, new Uri(web, "/logout"))).Html);
        login = await Get(browser, new Uri(web, "/admin"));
        Assert.Contains($"data-testid=\"user-{email}\"", login.Html);
        Assert.Contains(notes, login.Html);
        formPost = await Read(await Submit(browser, login, "user-list", ("email", email)));
        var admin = await Read(await Submit(browser, formPost, "form-post"));
        Assert.Contains("data-testid=\"admin-title\"", admin.Html);
        var tenant = await browser.GetAsync(new Uri(web, "/call/tenant"), Ct);
        Assert.Equal(HttpStatusCode.OK, tenant.StatusCode);
        Assert.Contains("Tenant acme", await tenant.Content.ReadAsStringAsync(Ct));

        // No browser: password grant, then refresh, and the Api accepts both access tokens.
        var tokenEndpoint = new Uri(zf, "/realms/shop/protocol/openid-connect/token");
        (string, string)[] client = [("client_id", "store.web"), ("client_secret", "web-secret")];
        var tokens = await Post(tokenEndpoint, [.. client, ("grant_type", "password"), ("username", email), ("password", "ignored")]);
        Assert.Equal(HttpStatusCode.OK, await CallApi(api, "/tenant", tokens));
        var refreshed = await Post(tokenEndpoint, [.. client, ("grant_type", "refresh_token"), ("refresh_token", (string)tokens["refresh_token"]!)]);
        Assert.NotEqual((string?)tokens["access_token"], (string?)refreshed["access_token"]);
        Assert.Equal(HttpStatusCode.OK, await CallApi(api, "/tenant", refreshed));
    }

    /// <summary>Project resources have no health check; wait until Kestrel answers.</summary>
    static async Task Listening(Uri uri)
    {
        using var client = new HttpClient();
        for (var i = 0; ; i++)
            try
            {
                await client.GetAsync(uri, Ct);
                return;
            }
            catch (HttpRequestException) when (i < 60)
            {
                await Task.Delay(500, Ct);
            }
    }

    static async Task<Page> Get(HttpClient browser, Uri uri) => await Read(await browser.GetAsync(uri, Ct));

    static async Task<Page> Read(HttpResponseMessage response)
    {
        Assert.True(response.IsSuccessStatusCode, $"{response.RequestMessage!.RequestUri}: {(int)response.StatusCode}");
        return new(response.RequestMessage!.RequestUri!, await AuthorizeTests.Html(response));
    }

    /// <summary>Posts the form with id <paramref name="id"/>: its hidden inputs plus <paramref name="fields"/>.</summary>
    static Task<HttpResponseMessage> Submit(HttpClient browser, Page page, string id, params (string Name, string Value)[] fields)
    {
        var form = Regex.Match(page.Html, $"<form [^>]*id=\"{Regex.Escape(id)}\"[^>]*>.*?</form>", RegexOptions.Singleline);
        Assert.True(form.Success, $"No form {id} on {page.Uri}");
        var action = new Uri(page.Uri, WebUtility.HtmlDecode(Regex.Match(form.Value, "action=\"([^\"]*)\"").Groups[1].Value));
        var values = Regex.Matches(form.Value, "<input type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\"")
            .Select(m => new KeyValuePair<string, string>(m.Groups[1].Value, WebUtility.HtmlDecode(m.Groups[2].Value)))
            .Concat(fields.Select(f => new KeyValuePair<string, string>(f.Name, f.Value)));
        return browser.PostAsync(action, new FormUrlEncodedContent(values), Ct);
    }

    static async Task<JsonObject> Post(Uri uri, (string Name, string Value)[] fields)
    {
        using var client = new HttpClient();
        var response = await client.PostAsync(uri, new FormUrlEncodedContent(fields.Select(f => new KeyValuePair<string, string>(f.Name, f.Value))), Ct);
        var body = await response.Content.ReadAsStringAsync(Ct);
        Assert.True(response.IsSuccessStatusCode, body);
        return JsonNode.Parse(body)!.AsObject();
    }

    static async Task<HttpStatusCode> CallApi(Uri api, string path, JsonObject tokens)
    {
        using var client = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(api, path));
        request.Headers.Authorization = new("Bearer", (string)tokens["access_token"]!);
        return (await client.SendAsync(request, Ct)).StatusCode;
    }
}
