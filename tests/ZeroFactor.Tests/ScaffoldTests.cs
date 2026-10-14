using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace ZeroFactor.Tests;

public class ScaffoldTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    readonly HttpClient client = factory.CreateClient();

    [Fact]
    public async Task Health_returns_200()
    {
        var response = await client.GetAsync("/health", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Root_redirects_to_the_management_page()
    {
        var response = await factory.CreateClient(new() { AllowAutoRedirect = false }).GetAsync("/", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/_0factor/", response.Headers.Location?.OriginalString);
    }
}
