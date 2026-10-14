using System.Reflection;
using Aspire.Hosting.ApplicationModel;

namespace Aspire.Hosting;

/// <summary>
/// Extension methods for adding 0factor to an <see cref="IDistributedApplicationBuilder"/>.
/// Mirrors <c>Aspire.Hosting.Keycloak</c> so swapping <c>AddKeycloak</c> for <c>AddZeroFactor</c> is one line.
/// </summary>
public static class ZeroFactorResourceBuilderExtensions
{
    internal const string Registry = "ghcr.io";
    internal const string Image = "c4l3b/0factor";
    // The image is published on the same v* tag as this package, so the tag is the package version.
    internal static readonly string Tag = typeof(ZeroFactorResource).Assembly
        .GetCustomAttributes<AssemblyMetadataAttribute>().Single(a => a.Key == "ZeroFactorImageTag").Value!;
    internal const int ContainerUser = 1654; // non-root `app` user of the chiseled base image

    private const int DefaultContainerPort = 8080;
    private const string DataDirectory = "/data";
    private const string ImportDirectory = "/opt/keycloak/data/import"; // same as Keycloak

    /// <summary>
    /// Adds a 0factor container to the application model. Drop-in for <c>AddKeycloak</c>.
    /// </summary>
    /// <param name="builder">The <see cref="IDistributedApplicationBuilder"/>.</param>
    /// <param name="name">The name of the resource.</param>
    /// <param name="port">The host port. Use a stable port so browser cookies and the token issuer survive restarts.</param>
    /// <returns>The resource builder.</returns>
    [AspireExport]
    public static IResourceBuilder<ZeroFactorResource> AddZeroFactor(this IDistributedApplicationBuilder builder, string name, int? port = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(name);

        return builder.AddResource(new ZeroFactorResource(name))
            .WithImage(Image)
            .WithImageRegistry(Registry)
            .WithImageTag(Tag)
            .WithIconName("PersonLock")
            .WithHttpEndpoint(port: port, targetPort: DefaultContainerPort, name: ZeroFactorResource.PrimaryEndpointName)
            .WithHttpHealthCheck("/health");
    }

    /// <summary>
    /// Adds a named volume for the data folder (<c>/data</c>, holding <c>0factor.json</c>).
    /// </summary>
    /// <param name="builder">The resource builder.</param>
    /// <param name="name">The volume name. Defaults to one generated from the application and resource names.</param>
    /// <returns>The resource builder.</returns>
    [AspireExport]
    public static IResourceBuilder<ZeroFactorResource> WithDataVolume(this IResourceBuilder<ZeroFactorResource> builder, string? name = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.WithVolume(name ?? VolumeNameGenerator.Generate(builder, "data"), DataDirectory, false);
    }

    /// <summary>
    /// Adds a bind mount for the data folder (<c>/data</c>, holding <c>0factor.json</c>).
    /// </summary>
    /// <param name="builder">The resource builder.</param>
    /// <param name="source">The host directory to mount.</param>
    /// <returns>The resource builder.</returns>
    [AspireExport]
    public static IResourceBuilder<ZeroFactorResource> WithDataBindMount(this IResourceBuilder<ZeroFactorResource> builder, string source)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(source);
        return builder.WithBindMount(source, DataDirectory, false);
    }

    /// <summary>
    /// Copies Keycloak realm-export files into <c>/opt/keycloak/data/import</c>, the same as Keycloak's <c>WithRealmImport</c>.
    /// </summary>
    /// <param name="builder">The resource builder.</param>
    /// <param name="import">A directory of realm-export JSON files, or a single file. Relative to the AppHost directory.</param>
    /// <returns>The resource builder.</returns>
    [AspireExportIgnore(Reason = "Parameter name 'import' is a reserved keyword in TypeScript. Use the internal ATS-compatible overload instead.")]
    public static IResourceBuilder<ZeroFactorResource> WithRealmImport(this IResourceBuilder<ZeroFactorResource> builder, string import)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(import);

        var importFullPath = Path.GetFullPath(import, builder.ApplicationBuilder.AppHostDirectory);
        return builder.WithContainerFiles(ImportDirectory, importFullPath, defaultOwner: ContainerUser);
    }

    [AspireExport("withRealmImport")]
    internal static IResourceBuilder<ZeroFactorResource> WithRealmImportInternal(this IResourceBuilder<ZeroFactorResource> builder, string importPath)
        => builder.WithRealmImport(importPath);
}
