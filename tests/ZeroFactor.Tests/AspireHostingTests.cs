using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;

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
        Assert.Equal("ghcr.io", image.Registry);
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
