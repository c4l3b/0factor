var builder = DistributedApplication.CreateBuilder(args);

var auth = builder.AddZeroFactor("auth")
    .WithImageTag("latest") // The source package version may not have a published image yet.
    .WithDataVolume();

builder.AddProject<Projects.BasicWeb>("web")
    .WithReference(auth, realm: "basic-sample")
    .WaitFor(auth);

builder.Build().Run();
