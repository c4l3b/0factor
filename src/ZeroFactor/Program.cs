using ZeroFactor;

var builder = WebApplication.CreateSlimBuilder(args);

// Opened before Build so a corrupt data file or realm import fails startup loudly.
var config = builder.Configuration;
var store = Store.Open(config["ZF_DATA_DIR"] ?? "/data", config.GetValue<bool>("ZF_STRICT"));
store.Import(config["ZF_IMPORT_DIR"] ?? "/opt/keycloak/data/import");
builder.Services.AddSingleton(store);

var app = builder.Build();

// Explicit IResult: the request delegate generator cannot see types made by the RazorSlices generator.
app.MapGet("/", IResult () => ZeroFactor.Slices.Hello.Create());
app.MapGet("/health", () => "Healthy");

app.Run();

public partial class Program;

public record LayoutModel(string Title);
