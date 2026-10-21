using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Aspire.Hosting.ApplicationModel;

namespace Aspire.Hosting;

/// <summary>
/// Extension methods for adding 0factor to an <see cref="IDistributedApplicationBuilder"/>.
/// Mirrors <c>Aspire.Hosting.Keycloak</c> so swapping <c>AddKeycloak</c> for <c>AddZeroFactor</c> is one line.
/// </summary>
public static class ZeroFactorResourceBuilderExtensions
{
    internal const string Registry = "docker.io";
    internal const string Image = "c4l3b/0factor";
    // The image is published on the same v* tag as this package, so the tag is the package version.
    internal static readonly string Tag = typeof(ZeroFactorResource).Assembly
        .GetCustomAttributes<AssemblyMetadataAttribute>().Single(a => a.Key == "ZeroFactorImageTag").Value!;
    internal const int ContainerUser = 1654; // non-root `app` user of the chiseled base image

    private const int DefaultContainerPort = 8080;
    private const string DataDirectory = "/data";
    private const string ImportDirectory = "/opt/keycloak/data/import"; // same as Keycloak

    /// <summary>
    /// Adds a 0factor container with an unproxied endpoint. Without a port, the host port is derived from the
    /// AppHost directory and resource name: stable across restarts, and different for each AppHost on the machine.
    /// </summary>
    /// <param name="builder">The application builder.</param>
    /// <param name="name">The resource name.</param>
    /// <param name="port">The optional host port.</param>
    /// <returns>The resource builder.</returns>
    [AspireExport]
    public static IResourceBuilder<ZeroFactorResource> AddZeroFactor(this IDistributedApplicationBuilder builder, string name, int? port = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(name);
        return builder.AddZeroFactor(name, port ?? StablePort(builder.AppHostDirectory, name), isProxied: false);
    }

    // ponytail: hash into 20000-29999 with no free-port check; a rare collision fails container start, fixed by passing a port.
    private static int StablePort(string appHostDirectory, string name)
        => 20000 + (int)(BinaryPrimitives.ReadUInt32BigEndian(SHA256.HashData(Encoding.UTF8.GetBytes($"{appHostDirectory}\n{name}"))) % 10000);

    /// <summary>
    /// Adds a 0factor container to the application model. Drop-in for <c>AddKeycloak</c>.
    /// </summary>
    /// <param name="builder">The <see cref="IDistributedApplicationBuilder"/>.</param>
    /// <param name="name">The name of the resource.</param>
    /// <param name="port">The host port. When null, Aspire allocates one, which can change on every run.</param>
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
        resource.WithEnvironment("ZF_HOSTNAME", resource.GetEndpoint(ZeroFactorResource.PrimaryEndpointName, KnownNetworkIdentifiers.LocalhostNetwork));

#pragma warning disable ASPIRECERTIFICATES001 // experimental in Aspire 13.4
        // HTTPS like Aspire's Keycloak: when Aspire has a trusted developer certificate (or one is configured), Kestrel serves it
        // on the same container port, replacing the image's ASPNETCORE_HTTP_PORTS listener. Otherwise plain HTTP as before.
        resource.WithHttpsCertificateConfiguration(ctx =>
        {
            const string endpoint = "Kestrel__Endpoints__https__";
            ctx.EnvironmentVariables[endpoint + "Url"] = $"https://*:{DefaultContainerPort}";
            if (ctx.Password is null)
            {
                ctx.EnvironmentVariables[endpoint + "Certificate__Path"] = ctx.CertificatePath;
                ctx.EnvironmentVariables[endpoint + "Certificate__KeyPath"] = ctx.KeyPath;
            }
            else
            {
                ctx.EnvironmentVariables[endpoint + "Certificate__Path"] = ctx.PfxPath;
                ctx.EnvironmentVariables[endpoint + "Certificate__Password"] = ctx.Password;
            }
            return Task.CompletedTask;
        });
        if (builder.ExecutionContext.IsRunMode)
            resource.SubscribeHttpsEndpointsUpdate(_ => resource.WithEndpoint(ZeroFactorResource.PrimaryEndpointName, ep => ep.UriScheme = "https"));
#pragma warning restore ASPIRECERTIFICATES001
        return resource;
    }

    /// <summary>
    /// Keeps 0factor on plain HTTP even when Aspire has a trusted developer certificate. Same name and effect as Aspire's
    /// <c>WithoutHttpsCertificate</c>, without its experimental-API warning.
    /// </summary>
    /// <param name="builder">The resource builder.</param>
    /// <returns>The resource builder.</returns>
    [AspireExportIgnore(Reason = "Aspire exports the generic WithoutHttpsCertificate.")]
    public static IResourceBuilder<ZeroFactorResource> WithoutHttpsCertificate(this IResourceBuilder<ZeroFactorResource> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
#pragma warning disable ASPIRECERTIFICATES001
        return ResourceBuilderExtensions.WithoutHttpsCertificate(builder);
#pragma warning restore ASPIRECERTIFICATES001
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
