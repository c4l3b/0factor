using Microsoft.AspNetCore.HttpOverrides;
using ZeroFactor;

var builder = WebApplication.CreateSlimBuilder(args);

// Opened before Build so a corrupt data file or realm import fails startup loudly.
var config = builder.Configuration;
var fields = config["ZF_REGISTRATION_FIELDS"] is { Length: > 0 } json
    ? System.Text.Json.JsonSerializer.Deserialize(json, StoreJsonContext.Default.ListRegistrationField)
    : null;
var store = Store.Open(config["ZF_DATA_DIR"] ?? "/data", config.GetValue<bool>("ZF_STRICT"), fields);
store.Import(config["ZF_IMPORT_DIR"] ?? "/opt/keycloak/data/import");
builder.Services.AddSingleton(store);
builder.Services.AddSingleton<AuthCodes>();

// Issuer follows X-Forwarded-Proto/Host/Prefix from any proxy: a dev tool behind whatever reverse proxy the developer runs.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.All;
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Clear();
});

var app = builder.Build();
app.UseForwardedHeaders();

// Explicit IResult: the request delegate generator cannot see types made by the RazorSlices generator.
app.MapGet("/", IResult () => ZeroFactor.Slices.Hello.Create());
app.MapGet("/health", () => "Healthy");
app.MapDiscovery();
app.MapAuthorize();
app.MapRegister();
app.MapToken();
app.MapIntrospection();

app.Run();

public partial class Program;

public record LayoutModel(string Title);
