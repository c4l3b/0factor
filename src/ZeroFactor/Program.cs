var builder = WebApplication.CreateSlimBuilder(args);

var app = builder.Build();

// Explicit IResult: the request delegate generator cannot see types made by the RazorSlices generator.
app.MapGet("/", IResult () => ZeroFactor.Slices.Hello.Create());
app.MapGet("/health", () => "Healthy");

app.Run();

public partial class Program;

public record LayoutModel(string Title);
