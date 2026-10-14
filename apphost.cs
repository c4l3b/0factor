#:sdk Aspire.AppHost.Sdk@13.6.1

// Dev-only AppHost: `aspire run` from the repo root. Not shipped in the image or the NuGet package.
var builder = DistributedApplication.CreateBuilder(args);

builder.AddProject("zerofactor", "./src/ZeroFactor/ZeroFactor.csproj")
    .WithEnvironment("ZF_DATA_DIR", Path.Combine(builder.AppHostDirectory, ".data"))
    .WithHttpHealthCheck("/health");

builder.Build().Run();
