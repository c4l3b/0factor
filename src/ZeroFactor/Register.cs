using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZeroFactor;

public record RegisterModel(string Realm, string Action, string Auth, string Email, string LoginUrl, List<RegistrationField> Fields,
    bool AgentNotesRequired, List<string> RealmRoles, Dictionary<string, string> Values, Dictionary<string, string> Errors);

/// <summary>
/// Registration page shown when an unknown email signs in to a realm with <c>registrationAllowed</c>: the realm's configured
/// fields, free-entry roles and claims, and agent notes that the login page shows next to the user.
/// </summary>
public static class Register
{
    const string Required = "Please specify this field.";
    const int MaxIdLength = 255;

    public static void MapRegister(this WebApplication app) =>
        app.MapPost("/realms/{realm}/login-actions/registration", Submit);

    internal static IResult Page(HttpContext context, Realm realm, string signed, JsonObject auth, string email,
        Dictionary<string, string> values, Dictionary<string, string> errors)
    {
        var page = Slices.Register.Create(new RegisterModel(realm.Name,
            $"{context.Request.PathBase}/realms/{realm.Name}/login-actions/registration", signed, email,
            Authorize.RestartUrl(context, realm, auth), realm.Fields, realm.AgentNotesRequired,
            realm.Roles.Realm.Select(r => r.Name).ToList(), values, errors));
        if (errors.Count > 0) page.StatusCode = StatusCodes.Status400BadRequest;
        return page;
    }

    static async Task<IResult> Submit(string realm, HttpContext context, Store store, AuthCodes codes)
    {
        if (store.GetRealm(realm) is not { } r) return Authorize.Error("Realm does not exist.", StatusCodes.Status404NotFound);
        var form = await context.Request.ReadFormAsync();
        var signed = form["auth"].ToString();
        if (Authorize.ReadAuth(context, store, r, signed) is not { } auth)
            return Authorize.Error("Your login attempt timed out. Start again from the application.");
        if (!r.RegistrationAllowed) return Authorize.Error("Registration not allowed.");

        var email = form["email"].ToString().Trim().ToLowerInvariant();
        var values = form.Keys.ToDictionary(k => k, k => form[k].ToString().Trim());
        var errors = new Dictionary<string, string>();
        var user = new User { Username = email, Email = email, EmailVerified = true };

        if (values.GetValueOrDefault("userId") is { Length: > 0 } id)
        {
            if (id.Length > MaxIdLength) errors["userId"] = $"User ID can be at most {MaxIdLength} characters.";
            else if (id.Any(char.IsWhiteSpace)) errors["userId"] = "User ID can't contain spaces.";
            else if (r.Users.Exists(u => u.Id == id)) errors["userId"] = "User ID already exists.";
            else user.Id = id;
        }

        if (!email.Contains('@')) errors["email"] = "Invalid email address.";
        else if (Authorize.FindByEmail(r, email) is not null) errors["email"] = "Email already exists.";

        foreach (var field in r.Fields)
        {
            var value = values.GetValueOrDefault(field.Name, "");
            if (field.Type == "checkbox" && value != "") value = "true";
            if (value == "")
            {
                if (field.Required) errors[field.Name] = Required;
                continue;
            }
            if (Invalid(field, value) is { } message)
            {
                errors[field.Name] = message;
                continue;
            }
            switch (field.Name)
            {
                case "firstName": user.FirstName = value; break;
                case "lastName": user.LastName = value; break;
                default: user.Attributes[field.Name] = [value]; break;
            }
        }

        ReadRolesClaimsNotes(r, values, user, errors);

        if (errors.Count > 0) return Page(context, r, signed, auth, email, values, errors);
        store.AddUser(r, user);
        return Authorize.SignIn(context, store, codes, r, auth, user);
    }

    /// <summary>
    /// Reads the realm roles, client roles, extra claims and agent notes inputs shared by registration and the management
    /// page into <paramref name="user"/>, replacing what it had. Problems go into <paramref name="errors"/> by input name.
    /// </summary>
    internal static void ReadRolesClaimsNotes(Realm realm, Dictionary<string, string> values, User user, Dictionary<string, string> errors)
    {
        user.ClientRoles = [];
        user.RealmRoles = List(values.GetValueOrDefault("realmRoles"));
        foreach (var pair in List(values.GetValueOrDefault("clientRoles")))
        {
            var colon = pair.IndexOf(':');
            if (colon <= 0 || colon == pair.Length - 1)
            {
                errors["clientRoles"] = $"\"{pair}\" is not a client:role pair, e.g. store.api:orders.write.";
                break;
            }
            var (client, role) = (pair[..colon].Trim(), pair[(colon + 1)..].Trim());
            if (!user.ClientRoles.TryGetValue(client, out var roles)) user.ClientRoles[client] = roles = [];
            if (!roles.Contains(role)) roles.Add(role);
        }

        user.Claims = null;
        if (values.GetValueOrDefault("claims") is { Length: > 0 } claims)
        {
            try
            {
                user.Claims = JsonNode.Parse(claims) as JsonObject;
                if (user.Claims is null) errors["claims"] = "Claims must be a JSON object, e.g. {\"tenant_id\": \"acme\"}.";
                else if (User.Reserved(user.Claims) is { Count: > 0 } reserved)
                    errors["claims"] = $"Reserved claim names can't be set: {string.Join(", ", reserved)}. Use the role fields for roles.";
            }
            catch (JsonException e)
            {
                errors["claims"] = $"Invalid JSON: {e.Message}";
            }
        }

        user.AgentNotes = values.GetValueOrDefault("agentNotes") is { Length: > 0 } notes ? notes : null;
        if (user.AgentNotes is null && realm.AgentNotesRequired) errors["agentNotes"] = Required;
    }

    static string? Invalid(RegistrationField field, string value) => field.Type switch
    {
        "email" when !value.Contains('@') => "Invalid email address.",
        "number" when !double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out _) => "Enter a number.",
        "date" when !DateOnly.TryParseExact(value, "yyyy-MM-dd", out _) => "Enter a date as YYYY-MM-DD.",
        "select" when field.Options?.Contains(value) != true => "Choose one of the options.",
        _ => null,
    };

    static List<string> List(string? commaSeparated) =>
        (commaSeparated ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Distinct().ToList();
}
