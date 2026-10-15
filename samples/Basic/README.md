# Basic ASP.NET Core sample

A home page with a **Log in** button. Sign in through 0factor, then the home page shows your email and your name, if you entered one. It uses standard ASP.NET Core cookie and OpenID Connect handlers, with no realm import or preconfigured clients.

From the repository root, with .NET 10, the Aspire CLI and Docker running:

```bash
aspire run --apphost samples/Basic/AppHost/BasicAppHost.csproj
```

Open the **web** endpoint from the Aspire dashboard and click **Log in**. Enter a new email and fill in the optional first and last name fields, or select an existing user. After signing in, you're returned to the home page with your profile.

Click **Sign out** to end both the web app session and the 0factor session and return to the home page.

- [AppHost/AppHost.cs](AppHost/AppHost.cs) adds 0factor and supplies the web app's issuer with `.WithReference(auth, realm: "basic-sample")`.
- [Web/Program.cs](Web/Program.cs) reads `ConnectionStrings__auth` and configures cookie and OIDC authentication.
- [Web/Pages/Index.cshtml](Web/Pages/Index.cshtml) renders the anonymous and signed-in home page.

The AppHost references the hosting package's source in this repository and explicitly uses the latest published container image, since the source package version may not be published yet. In your own AppHost, install `ZeroFactor.Aspire.Hosting` from NuGet and omit `.WithImageTag("latest")` to use the package's matching image version. Users and signing keys persist in a Docker volume, and the realm is created on its first request.

This sample runs over local HTTP and adjusts the OIDC nonce and correlation cookies accordingly. Use it only for local development.
