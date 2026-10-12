var builder = DistributedApplication.CreateBuilder(args);

// The one-line swap. Everything else is what a Keycloak AppHost already has.
// var keycloak = builder.AddKeycloak("keycloak", 8080)
var keycloak = builder.AddZeroFactor("keycloak", 8080)
    .WithRealmImport("./Realms")
    .WithDataVolume();

var api = builder.AddProject<Projects.Api>("api")
    .WithReference(keycloak)
    .WaitFor(keycloak);

builder.AddProject<Projects.Web>("web")
    .WithExternalHttpEndpoints()
    .WithReference(keycloak)
    .WithReference(api)
    .WaitFor(keycloak);

builder.Build().Run();
