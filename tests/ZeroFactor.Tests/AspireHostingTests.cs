#pragma warning disable ASPIRECERTIFICATES001 // Aspire certificate APIs are experimental
using Aspire.Hosting;
using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;
using Aspire.Hosting.ApplicationModel;
using Microsoft.Extensions.DependencyInjection;

namespace ZeroFactor.Tests;

public class AspireHostingTests
{
    [Fact]
    public void AddZeroFactor_mirrors_the_Keycloak_resource()
    {
        var builder = DistributedApplication.CreateBuilder();

        var resource = builder.AddZeroFactor("keycloak", port: 8080).Resource;

        var endpoint = Assert.Single(resource.Annotations.OfType<EndpointAnnotation>());
        Assert.Equal("http", endpoint.Name);
        Assert.Equal("http", endpoint.UriScheme);
        Assert.Equal(8080, endpoint.Port);
        Assert.False(endpoint.IsProxied);
        Assert.Equal(8080, endpoint.TargetPort);

        var image = Assert.Single(resource.Annotations.OfType<ContainerImageAnnotation>());
        Assert.Equal("docker.io", image.Registry);
        Assert.Equal("c4l3b/0factor", image.Image);
        Assert.Equal(typeof(ZeroFactorResource).Assembly.GetName().Version!.ToString(3), image.Tag);

        Assert.Single(resource.Annotations.OfType<HealthCheckAnnotation>());
        Assert.IsAssignableFrom<IResourceWithServiceDiscovery>(resource);
    }

    [Fact]
    public void Port_defaults_to_one_derived_from_the_AppHost()
    {
        static EndpointAnnotation Endpoint(string name)
            => DistributedApplication.CreateBuilder().AddZeroFactor(name).Resource.Annotations.OfType<EndpointAnnotation>().Single();

        var endpoint = Endpoint("keycloak");

        Assert.InRange(endpoint.Port!.Value, 20000, 29999);
        Assert.False(endpoint.IsProxied);
        Assert.Equal(8080, endpoint.TargetPort);
        Assert.Equal(endpoint.Port, Endpoint("keycloak").Port); // stable across restarts
        Assert.NotEqual(endpoint.Port, Endpoint("other").Port);
    }

    [Fact]
    public void Dynamic_port_is_still_available()
    {
        var builder = DistributedApplication.CreateBuilder();
        var endpoint = builder.AddZeroFactor("keycloak", port: null, isProxied: true).Resource.Annotations.OfType<EndpointAnnotation>().Single();
        Assert.Null(endpoint.Port);
        Assert.True(endpoint.IsProxied);
    }

    [Fact]
    public void Proxy_behavior_can_be_overridden()
    {
        var builder = DistributedApplication.CreateBuilder();
        var endpoint = builder.AddZeroFactor("keycloak", port: 8080, isProxied: true).Resource.Annotations.OfType<EndpointAnnotation>().Single();
        Assert.True(endpoint.IsProxied);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Issuer_and_environment_use_the_allocated_host_port(bool existingDiscoveryLink)
    {
        var builder = DistributedApplication.CreateBuilder();
        var oidc = builder.AddZeroFactor("keycloak");
        var endpoint = oidc.Resource.Annotations.OfType<EndpointAnnotation>().Single();
        endpoint.AllocatedEndpoint = new AllocatedEndpoint(endpoint, "localhost", 12345);
        if (existingDiscoveryLink)
            oidc.WithUrlForEndpoint("http", _ => new() { Url = "/realms/shop/.well-known/openid-configuration" });
        var consumer = builder.AddExecutable("consumer", "unused", ".").WithReference(oidc, realm: "shop");

        Assert.Equal("http://localhost:12345/realms/shop", await oidc.GetIssuer("shop").GetValueAsync(TestContext.Current.CancellationToken));
        var providerEnv = await Environment(oidc.Resource, builder);
        var consumerEnv = await Environment(consumer.Resource, builder);
        Assert.Equal("http://localhost:12345", providerEnv["ZF_HOSTNAME"]);
        Assert.Equal("http://localhost:12345/realms/shop", consumerEnv["ConnectionStrings__keycloak"]);

        builder.AddExecutable("consumer2", "unused", ".").WithReference(oidc, realm: "shop");
        var urls = new List<ResourceUrlAnnotation>();
        var context = new ResourceUrlsCallbackContext(builder.ExecutionContext, oidc.Resource, urls, TestContext.Current.CancellationToken);
        foreach (var callback in oidc.Resource.Annotations.OfType<ResourceUrlsCallbackAnnotation>())
            await callback.Callback(context);
        Assert.Contains(urls, u => u.Url.EndsWith("/_0factor/") && u.DisplayText == "Users");
        Assert.Single(urls, u => u.Url.EndsWith("/_0factor/realms/shop"));
        var discovery = Assert.Single(urls, u => u.Url.EndsWith("/realms/shop/.well-known/openid-configuration"));
        Assert.Equal("shop discovery", discovery.DisplayText);
    }

    [Theory]
    [InlineData(true, false, "https")]  // trusted developer certificate: HTTPS by default
    [InlineData(false, false, "http")]  // no trusted certificate: HTTP as before
    [InlineData(true, true, "http")]    // WithoutHttpsCertificate opts out
    public async Task Https_follows_the_Aspire_developer_certificate(bool useForHttps, bool optOut, string scheme)
    {
        var builder = DistributedApplication.CreateBuilder();
        var oidc = builder.AddZeroFactor("auth", port: 7281);
        if (optOut) oidc.WithoutHttpsCertificate();
        var consumer = builder.AddExecutable("consumer", "unused", ".").WithReference(oidc, realm: "shop");
        builder.Services.AddSingleton<IDeveloperCertificateService>(new DevCerts(useForHttps));
        builder.Configuration["DcpPublisher:CliPath"] = "unused"; // Build validates these; nothing is started.
        builder.Configuration["DcpPublisher:DashboardPath"] = "unused";
        using var app = builder.Build();
        await builder.Eventing.PublishAsync(new BeforeStartEvent(app.Services, app.Services.GetRequiredService<DistributedApplicationModel>()), TestContext.Current.CancellationToken);

        var endpoint = oidc.Resource.Annotations.OfType<EndpointAnnotation>().Single();
        Assert.Equal(("http", scheme, 7281, 8080), (endpoint.Name, endpoint.UriScheme, endpoint.Port, endpoint.TargetPort));
        endpoint.AllocatedEndpoint = new AllocatedEndpoint(endpoint, "localhost", 7281);
        Assert.Equal($"{scheme}://localhost:7281", (await Environment(oidc.Resource, builder))["ZF_HOSTNAME"]);
        Assert.Equal($"{scheme}://localhost:7281/realms/shop", (await Environment(consumer.Resource, builder))["ConnectionStrings__auth"]);
    }

    sealed class DevCerts(bool useForHttps) : IDeveloperCertificateService
    {
        public ImmutableList<X509Certificate2> Certificates => [];
        public bool SupportsContainerTrust => true;
        public bool UseForHttps => useForHttps;
        public bool TrustCertificate => useForHttps;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Certificate_is_served_by_Kestrel_on_the_container_port(bool password)
    {
        var builder = DistributedApplication.CreateBuilder();
        var oidc = builder.AddZeroFactor("auth");
        var env = new Dictionary<string, object>();
        var context = new HttpsCertificateConfigurationCallbackAnnotationContext
        {
            ExecutionContext = builder.ExecutionContext, Resource = oidc.Resource, Arguments = [], EnvironmentVariables = env,
            CertificatePath = ReferenceExpression.Create($"/certs/cert.pem"), KeyPath = ReferenceExpression.Create($"/certs/key.pem"),
            CertificateWithKeyPath = ReferenceExpression.Create($"/certs/both.pem"), PfxPath = ReferenceExpression.Create($"/certs/cert.pfx"),
            Password = password ? ReferenceExpression.Create($"secret") : null, CancellationToken = TestContext.Current.CancellationToken,
        };
        await Assert.Single(oidc.Resource.Annotations.OfType<HttpsCertificateConfigurationCallbackAnnotation>()).Callback(context);

        var values = new Dictionary<string, string?>();
        foreach (var (name, value) in env)
            values[name] = value is IValueProvider provider ? await provider.GetValueAsync(TestContext.Current.CancellationToken) : (string)value;
        const string prefix = "Kestrel__Endpoints__https__";
        Assert.Equal("https://*:8080", values[prefix + "Url"]);
        Assert.Equal(password ? "/certs/cert.pfx" : "/certs/cert.pem", values[prefix + "Certificate__Path"]);
        Assert.Equal(password ? null : "/certs/key.pem", values.GetValueOrDefault(prefix + "Certificate__KeyPath"));
        Assert.Equal(password ? "secret" : null, values.GetValueOrDefault(prefix + "Certificate__Password"));
    }

    static async Task<Dictionary<string, string?>> Environment(IResource resource, IDistributedApplicationBuilder builder)
    {
        var values = new Dictionary<string, object>();
        var context = new EnvironmentCallbackContext(builder.ExecutionContext, resource, values, TestContext.Current.CancellationToken);
        foreach (var callback in resource.Annotations.OfType<EnvironmentCallbackAnnotation>())
            await callback.Callback(context);
        var result = new Dictionary<string, string?>();
        foreach (var (name, value) in values)
            result[name] = value is IValueProvider provider ? await provider.GetValueAsync(TestContext.Current.CancellationToken) : value.ToString();
        return result;
    }

    [Fact]
    public void WithDataVolume_mounts_data()
    {
        var builder = DistributedApplication.CreateBuilder();

        var resource = builder.AddZeroFactor("keycloak").WithDataVolume().Resource;

        var mount = Assert.Single(resource.Annotations.OfType<ContainerMountAnnotation>());
        Assert.Equal(ContainerMountType.Volume, mount.Type);
        Assert.Equal("/data", mount.Target);
        Assert.False(mount.IsReadOnly);
    }

    [Fact]
    public void WithDataBindMount_mounts_data()
    {
        var builder = DistributedApplication.CreateBuilder();

        var resource = builder.AddZeroFactor("keycloak").WithDataBindMount("./zf-data").Resource;

        var mount = Assert.Single(resource.Annotations.OfType<ContainerMountAnnotation>());
        Assert.Equal(ContainerMountType.BindMount, mount.Type);
        Assert.Equal("/data", mount.Target);
    }

    [Fact]
    public void WithRealmImport_copies_files_to_the_Keycloak_import_directory()
    {
        var builder = DistributedApplication.CreateBuilder();

        var resource = builder.AddZeroFactor("keycloak").WithRealmImport("fixtures").Resource;

        var files = Assert.Single(resource.Annotations.OfType<ContainerFileSystemCallbackAnnotation>());
        Assert.Equal("/opt/keycloak/data/import", files.DestinationPath);
        Assert.Equal(1654, files.DefaultOwner);
    }
}
