using System.Security.Cryptography;
using System.Text;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);
var db = Environment.GetEnvironmentVariable("DATABASE_URL");
var admin = Environment.GetEnvironmentVariable("NOX_ADMIN_TOKEN");
if (string.IsNullOrWhiteSpace(db)) throw new InvalidOperationException("DATABASE_URL is required.");
if (string.IsNullOrWhiteSpace(admin) || admin.Length < 32) throw new InvalidOperationException("NOX_ADMIN_TOKEN must contain at least 32 characters.");
// Supabase's URI-style PostgreSQL URLs are converted to an Npgsql connection string.
if (db.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase) || db.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase)) {
    var u = new Uri(db);
    var userInfo = u.UserInfo.Split(':', 2);
    db = new NpgsqlConnectionStringBuilder {
        Host = u.Host, Port = u.IsDefaultPort ? 5432 : u.Port,
        Username = Uri.UnescapeDataString(userInfo[0]),
        Password = userInfo.Length > 1 ? Uri.UnescapeDataString(userInfo[1]) : "",
        Database = Uri.UnescapeDataString(u.AbsolutePath.TrimStart('/')),
        SslMode = SslMode.Require
    }.ConnectionString;
}
builder.Services.AddNpgsqlDataSource(db);
var app = builder.Build();
// Render terminates TLS at its edge and forwards plain HTTP to this container.
// Do not expose this container directly to the public Internet.
app.Use(async (ctx,next) => { ctx.Response.Headers.CacheControl = "no-store"; await next(); });
static string Hash(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
static string Secret(int bytes) => Convert.ToHexString(RandomNumberGenerator.GetBytes(bytes));
static bool Authorized(HttpContext ctx,string secret) {
    var h = ctx.Request.Headers.Authorization.ToString();
    return h.StartsWith("Bearer ",StringComparison.Ordinal) &&
        CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(h[7..])),SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
}
await using (var scope=app.Services.CreateAsyncScope()) {
    var ds=scope.ServiceProvider.GetRequiredService<NpgsqlDataSource>();
    await using var cmd=ds.CreateCommand("""
    CREATE TABLE IF NOT EXISTS pairing_codes (code_hash TEXT PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL, used BOOLEAN NOT NULL DEFAULT FALSE);
    CREATE TABLE IF NOT EXISTS devices (device_id UUID PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, first_ip INET, last_ip INET, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_seen TIMESTAMPTZ);
    """);
    await cmd.ExecuteNonQueryAsync();
}
app.MapGet("/health",()=>Results.Ok(new { status="ok",version="1.0",remoteControl=false }));
app.MapPost("/admin/pairings",async(HttpContext ctx,NpgsqlDataSource ds)=>{
    if(!Authorized(ctx,admin!)) return Results.Unauthorized();
    var code=Secret(12);
    await using var cmd=ds.CreateCommand("INSERT INTO pairing_codes(code_hash,expires_at) VALUES (@hash,NOW()+INTERVAL '10 minutes')");
    cmd.Parameters.AddWithValue("hash",Hash(code)); await cmd.ExecuteNonQueryAsync();
    return Results.Ok(new { pairingCode=code,expiresInSeconds=600 });
});
app.MapPost("/devices/enroll",async(EnrollRequest req,HttpContext ctx,NpgsqlDataSource ds)=>{
    if(string.IsNullOrWhiteSpace(req.Name)||req.Name.Length>80||string.IsNullOrWhiteSpace(req.PairingCode)) return Results.BadRequest();
    var id=Guid.NewGuid(); var token=Secret(32);
    await using var conn=await ds.OpenConnectionAsync();
    await using var tx=await conn.BeginTransactionAsync();
    await using(var claim=new NpgsqlCommand("UPDATE pairing_codes SET used=TRUE WHERE code_hash=@hash AND NOT used AND expires_at>NOW() RETURNING code_hash",conn,tx)){
        claim.Parameters.AddWithValue("hash",Hash(req.PairingCode));
        if(await claim.ExecuteScalarAsync() is null){await tx.RollbackAsync();return Results.Unauthorized();}
    }
    await using(var insert=new NpgsqlCommand("INSERT INTO devices(device_id,name,token_hash,last_seen) VALUES (@id,@name,@token,NOW())",conn,tx)){
        insert.Parameters.AddWithValue("id",id);insert.Parameters.AddWithValue("name",req.Name.Trim());insert.Parameters.AddWithValue("token",Hash(token));await insert.ExecuteNonQueryAsync();
    }
    await tx.CommitAsync();
    return Results.Ok(new { deviceId=id,deviceToken=token });
});
app.MapPost("/devices/heartbeat",async(HttpContext ctx,NpgsqlDataSource ds)=>{
    var auth=ctx.Request.Headers.Authorization.ToString();
    if(!auth.StartsWith("Bearer ",StringComparison.Ordinal)||auth.Length>200) return Results.Unauthorized();
    await using var cmd=ds.CreateCommand("UPDATE devices SET last_seen=NOW() WHERE token_hash=@hash RETURNING device_id");
    cmd.Parameters.AddWithValue("hash",Hash(auth[7..]));
    var id=await cmd.ExecuteScalarAsync();
    return id is null?Results.Unauthorized():Results.Ok(new {deviceId=id});
});
app.MapGet("/admin/devices",async(HttpContext ctx,NpgsqlDataSource ds)=>{
    if(!Authorized(ctx,admin!)) return Results.Unauthorized();
    var rows=new List<object>();
    await using var cmd=ds.CreateCommand("SELECT device_id,name,created_at,last_seen FROM devices ORDER BY created_at DESC LIMIT 200");
    await using var reader=await cmd.ExecuteReaderAsync();
    while(await reader.ReadAsync()) rows.Add(new {deviceId=reader.GetGuid(0),name=reader.GetString(1),createdAt=reader.GetDateTime(2),lastSeen=reader.IsDBNull(3)?(DateTime?)null:reader.GetDateTime(3)});
    return Results.Ok(rows);
});
app.MapDelete("/admin/devices/{id:guid}",async(Guid id,HttpContext ctx,NpgsqlDataSource ds)=>{
    if(!Authorized(ctx,admin!)) return Results.Unauthorized();
    await using var cmd=ds.CreateCommand("DELETE FROM devices WHERE device_id=@id");
    cmd.Parameters.AddWithValue("id",id);
    return await cmd.ExecuteNonQueryAsync()==1?Results.NoContent():Results.NotFound();
});
app.Run();
record EnrollRequest(string Name,string PairingCode);
