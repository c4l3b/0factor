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

    /// <summary>Adds a 0factor container, with an unproxied endpoint when a host port is supplied.</summary>
    /// <param name="builder">The application builder.</param>
    /// <param name="name">The resource name.</param>
    /// <param name="port">The optional host port.</param>
    /// <returns>The resource builder.</returns>
    [AspireExport]
    public static IResourceBuilder<ZeroFactorResource> AddZeroFactor(this IDistributedApplicationBuilder builder, string name, int? port = null)
        => builder.AddZeroFactor(name, port, isProxied: port is null);

    /// <summary>
    /// Adds a 0factor container to the application model. Drop-in for <c>AddKeycloak</c>.
    /// </summary>
    /// <param name="builder">The <see cref="IDistributedApplicationBuilder"/>.</param>
    /// <param name="name">The name of the resource.</param>
    /// <param name="port">The host port. Use a stable port so browser cookies and the token issuer survive restarts.</param>
    /// <param name="isProxied">Whether to proxy the endpoint.</param>
    /// <returns>The resource builder.</returns>
    [AspireExport("addZeroFactorWithProxy")]
    public static IResourceBuilder<ZeroFactorResource> AddZeroFactor(this IDistributedApplicationBuilder builder, string name, int? port, bool isProxied)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(name);

        var resource = builder.AddResource(new ZeroFactorResource(name))
            .WithImage(Image)
            .WithImageRegistry(Registry)
            .WithImageTag(Tag)
            .WithIconName("PersonLock")
            .WithHttpEndpoint(port: port, targetPort: DefaultContainerPort, name: ZeroFactorResource.PrimaryEndpointName, isProxied: isProxied)
            .WithHttpHealthCheck("/health")
            .WithUrlForEndpoint(ZeroFactorResource.PrimaryEndpointName, ep => new() { Url = "/_0factor/", DisplayText = "Users" });

        // Issuers must use the browser-facing address, even when resolved inside the provider container.
        return resource.WithEnvironment("ZF_HOSTNAME", resource.GetEndpoint(ZeroFactorResource.PrimaryEndpointName, KnownNetworkIdentifiers.LocalhostNetwork));
    }

    /// <summary>Returns the realm issuer using the host endpoint, resolved after port allocation.</summary>
    /// <param name="builder">The 0factor resource builder.</param>
    /// <param name="realm">The realm name.</param>
    /// <returns>The issuer URL expression.</returns>
    [AspireExport]
    public static ReferenceExpression GetIssuer(this IResourceBuilder<ZeroFactorResource> builder, string realm)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(realm);
        var endpoint = builder.GetEndpoint(ZeroFactorResource.PrimaryEndpointName, KnownNetworkIdentifiers.LocalhostNetwork);
        return ReferenceExpression.Create($"{endpoint}/realms/{Uri.EscapeDataString(realm)}");
    }

    /// <summary>References 0factor and injects the realm issuer as ConnectionStrings__{resource name}.</summary>
    /// <typeparam name="T">The consuming resource type.</typeparam>
    /// <param name="builder">The consuming resource builder.</param>
    /// <param name="oidc">The 0factor resource builder.</param>
    /// <param name="realm">The realm name.</param>
    /// <returns>The consuming resource builder.</returns>
    public static IResourceBuilder<T> WithReference<T>(this IResourceBuilder<T> builder, IResourceBuilder<ZeroFactorResource> oidc, string realm)
        where T : IResourceWithEnvironment
    {
        ArgumentNullException.ThrowIfNull(builder);
        var issuer = oidc.GetIssuer(realm);
        var escapedRealm = Uri.EscapeDataString(realm);
        oidc.WithUrls(context =>
        {
            if (context.GetEndpoint(ZeroFactorResource.PrimaryEndpointName) is not { } endpoint) return;
            (string Path, string Label)[] links =
            [
                ($"/_0factor/realms/{escapedRealm}", $"{realm} users"),
                ($"/realms/{escapedRealm}/.well-known/openid-configuration", $"{realm} discovery")
            ];
            foreach (var (path, label) in links)
            {
                var existing = context.Urls.FirstOrDefault(u => u.Url == endpoint.Url + path
                    || (u.Url == path && u.Endpoint?.EndpointName == endpoint.EndpointName));
                if (existing is null)
                    context.Urls.Add(new() { Url = endpoint.Url + path, DisplayText = label, Endpoint = endpoint });
                else if (string.IsNullOrWhiteSpace(existing.DisplayText))
                    existing.DisplayText = label;
            }
        });
        return builder.WithReference(oidc).WithEnvironment($"ConnectionStrings__{oidc.Resource.Name}", issuer);
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
