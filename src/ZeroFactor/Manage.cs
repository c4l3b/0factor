namespace ZeroFactor;

public record RealmsModel(List<Realm> Realms);
public record RealmModel(Realm Realm, string Url, string DiscoveryUrl, string? Message, string? EditedId, Dictionary<string, string> Values,
    Dictionary<string, string> Errors);

/// <summary>
/// Management pages under <c>/_0factor/</c> (Keycloak owns <c>/admin/</c>): list realms, edit a user's roles, claims and agent
/// notes, delete users. No auth and no confirm steps: this is dev data.
/// </summary>
public static class Manage
{
    // Explicit IResult: the request delegate generator cannot see types made by the RazorSlices generator.
    public static void MapManage(this WebApplication app)
    {
        app.MapGet("/", (HttpRequest request) => Results.Redirect($"{request.PathBase}/_0factor/"));
        app.MapGet("/_0factor/", IResult (Store store) => Slices.Realms.Create(new RealmsModel(store.Realms)));
        app.MapGet("/_0factor/realms/{realm}", IResult (string realm, string? saved, string? deleted, HttpContext context, Store store) =>
            Find(store, realm) is { } r
                ? Page(context, r, saved is null ? deleted is null ? null : $"Deleted {deleted}." : $"Saved {saved}.", null, [], [])
                : Authorize.Error("Realm does not exist.", StatusCodes.Status404NotFound));
        app.MapPost("/_0factor/realms/{realm}/users/{id}", Save);
        app.MapPost("/_0factor/realms/{realm}/users/{id}/delete", Delete);
    }

    static async Task<IResult> Save(string realm, string id, HttpContext context, Store store)
    {
        if (Find(store, realm) is not { } r || FindUser(r, id) is not { } user)
            return Authorize.Error("User not found.", StatusCodes.Status404NotFound);
        var form = await context.Request.ReadFormAsync();
        var values = form.Keys.ToDictionary(k => k, k => form[k].ToString().Trim());
        var errors = new Dictionary<string, string>();
        var edited = new User();
        Register.ReadRolesClaimsNotes(r, values, edited, errors);
        if (errors.Count > 0) return Page(context, r, null, id, values, errors);

        store.Update(_ =>
        {
            (user.RealmRoles, user.ClientRoles, user.Claims, user.AgentNotes) = (edited.RealmRoles, edited.ClientRoles, edited.Claims, edited.AgentNotes);
            r.EnsureRoles(user);
        });
        return Results.Redirect(Url(context, r) + QueryString.Create("saved", user.Email ?? user.Username));
    }

    static IResult Delete(string realm, string id, HttpContext context, Store store)
    {
        if (Find(store, realm) is not { } r || FindUser(r, id) is not { } user)
            return Authorize.Error("User not found.", StatusCodes.Status404NotFound);
        store.Update(_ => r.Users.Remove(user));
        return Results.Redirect(Url(context, r) + QueryString.Create("deleted", user.Email ?? user.Username));
    }

    /// <summary>The edit form's current values for <paramref name="user"/>, in the registration page's input format.</summary>
    internal static Dictionary<string, string> Values(User user) => new()
    {
        ["realmRoles"] = string.Join(", ", user.RealmRoles),
        ["clientRoles"] = string.Join(", ", user.ClientRoles.SelectMany(c => c.Value.Select(role => $"{c.Key}:{role}"))),
        ["claims"] = user.Claims?.ToJsonString() ?? "",
        ["agentNotes"] = user.AgentNotes ?? "",
    };

    // Routing decodes the path except %2F, and imported ids can contain '/'.
    static User? FindUser(Realm realm, string id) =>
        realm.Users.Find(u => u.Id == id.Replace("%2F", "/", StringComparison.OrdinalIgnoreCase));

    static Realm? Find(Store store, string name) => store.Realms.Find(r => r.Name == name);

    static string Url(HttpContext context, Realm realm) => $"{context.Request.PathBase}/_0factor/realms/{Uri.EscapeDataString(realm.Name)}";

    static IResult Page(HttpContext context, Realm realm, string? message, string? editedId, Dictionary<string, string> values,
        Dictionary<string, string> errors)
    {
        var page = Slices.RealmPage.Create(new RealmModel(realm, Url(context, realm), Discovery.Issuer(context.Request, realm.Name) + "/.well-known/openid-configuration",
            message, editedId, values, errors));
        if (errors.Count > 0) page.StatusCode = StatusCodes.Status400BadRequest;
        return page;
    }
}
