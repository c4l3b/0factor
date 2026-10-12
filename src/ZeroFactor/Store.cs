using System.Text.Json;

namespace ZeroFactor;

/// <summary>
/// All realms, clients and users, kept in memory and persisted to one JSON file.
/// The whole file is rewritten atomically (temp file + move) on every change.
/// </summary>
public class Store
{
    // ponytail: one global lock and whole-file rewrites; dev-scale data. Per-realm locks if contention ever shows up.
    readonly Lock gate = new();
    readonly string path;
    readonly bool strict;
    readonly StoreData data;

    Store(string path, bool strict, StoreData data) => (this.path, this.strict, this.data) = (path, strict, data);

    /// <summary>Missing file → empty store. Unreadable file → throws and leaves the file untouched.</summary>
    public static Store Open(string dataDir, bool strict = false)
    {
        var path = Path.Combine(dataDir, "0factor.json");
        StoreData data;
        try
        {
            data = File.Exists(path)
                ? JsonSerializer.Deserialize(File.ReadAllText(path), StoreJsonContext.Default.StoreData) ?? throw new JsonException("File contains null.")
                : new StoreData();
        }
        catch (JsonException e)
        {
            throw new InvalidOperationException($"Cannot parse {path}: {e.Message} Fix or delete the file; it was not modified.", e);
        }
        return new Store(path, strict, data);
    }

    /// <summary>
    /// Re-syncs every <c>*.json</c> Keycloak realm export in <paramref name="importDir"/>: realm settings, roles and clients
    /// from the file replace stored ones; users are upserted by username; users that only exist in the store are kept.
    /// </summary>
    public void Import(string importDir)
    {
        if (!Directory.Exists(importDir)) return;
        var files = Directory.GetFiles(importDir, "*.json");
        if (files.Length == 0) return;

        lock (gate)
        {
            foreach (var file in files.Order())
            {
                Realm imported;
                try
                {
                    imported = JsonSerializer.Deserialize(File.ReadAllText(file), StoreJsonContext.Default.Realm)
                        ?? throw new JsonException("File contains null.");
                }
                catch (JsonException e)
                {
                    throw new InvalidOperationException($"Cannot parse realm import {file}: {e.Message}", e);
                }
                if (imported.Name == "") throw new InvalidOperationException($"Realm import {file} has no \"realm\" name.");
                Merge(imported);
            }
            Save();
        }
    }

    void Merge(Realm imported)
    {
        var existing = data.Realms.Find(r => r.Name == imported.Name);
        var fileUsers = imported.Users.Where(u => u.ServiceAccountClientId is null).ToList();

        imported.Lenient = imported.Clients.Count == 0;
        imported.SigningKey ??= existing?.SigningKey;
        imported.Users = existing?.Users ?? [];
        foreach (var user in fileUsers)
        {
            user.Username = (user.Username == "" ? user.Email ?? "" : user.Username).ToLowerInvariant();
            var stored = imported.FindUser(user.Username);
            if (stored is not null)
            {
                if (user.Id == "") user.Id = stored.Id;
                if (user.CreatedTimestamp == 0) user.CreatedTimestamp = stored.CreatedTimestamp;
                user.LastLoginAt ??= stored.LastLoginAt;
                imported.Users.Remove(stored);
            }
            Initialize(user);
            imported.Users.Add(user);
        }
        foreach (var user in imported.Users) imported.EnsureRoles(user);

        if (existing is null) data.Realms.Add(imported);
        else data.Realms[data.Realms.IndexOf(existing)] = imported;
    }

    static void Initialize(User user)
    {
        if (user.Id == "") user.Id = Guid.NewGuid().ToString();
        if (user.CreatedTimestamp == 0) user.CreatedTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }

    /// <summary>The named realm; unknown realms are auto-created (registration allowed) unless strict.</summary>
    public Realm? GetRealm(string name)
    {
        lock (gate)
        {
            var realm = data.Realms.Find(r => r.Name == name);
            if (realm is not null || strict) return realm;
            realm = new Realm { Name = name, RegistrationAllowed = true, Lenient = true };
            data.Realms.Add(realm);
            Save();
            return realm;
        }
    }

    /// <summary>The named client. In a lenient realm an unknown client is recorded and returned, unless strict.</summary>
    public Client? GetClient(Realm realm, string clientId)
    {
        lock (gate)
        {
            var client = realm.Clients.Find(c => c.ClientId == clientId);
            if (client is not null || !realm.Lenient || strict) return client;
            client = new Client { ClientId = clientId };
            realm.Clients.Add(client);
            Save();
            return client;
        }
    }

    /// <summary>Applies a change under the store lock and persists it.</summary>
    public void Update(Action<StoreData> change)
    {
        lock (gate)
        {
            change(data);
            Save();
        }
    }

    void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(data, StoreJsonContext.Default.StoreData));
        File.Move(temp, path, overwrite: true);
    }
}
