namespace Aspire.Hosting.ApplicationModel;

/// <summary>
/// A 0factor container: a mock OIDC provider that is URL- and token-compatible with Keycloak.
/// </summary>
/// <param name="name">The name of the resource.</param>
[AspireExport(ExposeProperties = true)]
public sealed class ZeroFactorResource(string name) : ContainerResource(name), IResourceWithServiceDiscovery
{
    /// <summary>
    /// The primary endpoint name, <c>http</c>: the same as Keycloak's, so <c>https+http://{name}</c> resolves identically.
    /// </summary>
    public const string PrimaryEndpointName = "http";
}
