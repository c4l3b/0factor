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
        Assert.Equal(8080, endpoint.TargetPort);

        var image = Assert.Single(resource.Annotations.OfType<ContainerImageAnnotation>());
        Assert.Equal("ghcr.io", image.Registry);
        Assert.Equal("c4l3b/0factor", image.Image);
        Assert.Equal(typeof(ZeroFactorResource).Assembly.GetName().Version!.ToString(3), image.Tag);

        Assert.Single(resource.Annotations.OfType<HealthCheckAnnotation>());
        Assert.IsAssignableFrom<IResourceWithServiceDiscovery>(resource);
    }

    [Fact]
    public void Port_is_optional()
    {
        var builder = DistributedApplication.CreateBuilder();

        var endpoint = Assert.Single(builder.AddZeroFactor("keycloak").Resource.Annotations.OfType<EndpointAnnotation>());

        Assert.Null(endpoint.Port);
        Assert.Equal(8080, endpoint.TargetPort);
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
