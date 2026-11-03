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
app.MapGet("/health",()=>Results.Ok(new { status="ok",version="1.0",remoteControl=true }));
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

app.MapPost("/admin/devices/{id:guid}/actions", async (Guid id, RemoteActionRequest request, HttpContext ctx, NpgsqlDataSource ds) =>
{
    if (!Authorized(ctx,admin!)) return Results.Unauthorized();
    if (request.Action is not ("open_notepad" or "open_calculator" or "screen_info")) return Results.BadRequest();
    await using var cmd=ds.CreateCommand("""
      INSERT INTO remote_actions(device_id,action,expires_at)
      SELECT device_id,@action,NOW()+INTERVAL '90 seconds' FROM devices WHERE device_id=@id
      RETURNING action_id
      """);
    cmd.Parameters.AddWithValue("id",id);
    cmd.Parameters.AddWithValue("action",request.Action);
    var result=await cmd.ExecuteScalarAsync();
    return result is null ? Results.NotFound() : Results.Ok(new {actionId=result});
});
app.MapPost("/devices/actions/next", async (HttpContext ctx,NpgsqlDataSource ds) =>
{
    var bearer=ctx.Request.Headers.Authorization.ToString();
    if (!bearer.StartsWith("Bearer ",StringComparison.Ordinal)||bearer.Length>200) return Results.Unauthorized();
    await using var conn=await ds.OpenConnectionAsync();
    await using var tx=await conn.BeginTransactionAsync();
    await using var cmd=new NpgsqlCommand("""
      UPDATE remote_actions SET state='delivered'
      WHERE action_id=(
        SELECT a.action_id FROM remote_actions a
        JOIN devices d ON a.device_id=d.device_id
        WHERE d.token_hash=@hash AND a.state='pending' AND a.expires_at>NOW()
        ORDER BY a.created_at LIMIT 1 FOR UPDATE OF a SKIP LOCKED
      ) RETURNING action_id,action
      """,conn,tx);
    cmd.Parameters.AddWithValue("hash",Hash(bearer[7..]));
    await using var rd=await cmd.ExecuteReaderAsync();
    object? result=null;
    if(await rd.ReadAsync()) result=new {actionId=rd.GetGuid(0),action=rd.GetString(1)};
    await rd.CloseAsync();
    await tx.CommitAsync();
    return result is null?Results.NoContent():Results.Ok(result);
});
app.MapPost("/devices/actions/{id:guid}/result",async(Guid id,RemoteActionResult result,HttpContext ctx,NpgsqlDataSource ds)=>{
    var bearer=ctx.Request.Headers.Authorization.ToString();
    if(!bearer.StartsWith("Bearer ",StringComparison.Ordinal)||bearer.Length>200) return Results.Unauthorized();
    if(result.Status is not ("completed" or "denied" or "failed")) return Results.BadRequest();
    await using var cmd=ds.CreateCommand("""
      UPDATE remote_actions a SET state=@state,finished_at=NOW()
      FROM devices d WHERE a.action_id=@id AND a.device_id=d.device_id
      AND d.token_hash=@hash AND a.state='delivered'
      """);
    cmd.Parameters.AddWithValue("id",id);
    cmd.Parameters.AddWithValue("hash",Hash(bearer[7..]));
    cmd.Parameters.AddWithValue("state",result.Status);
    return await cmd.ExecuteNonQueryAsync()==1?Results.NoContent():Results.NotFound();
});
app.MapGet("/admin/devices/{id:guid}/actions",async(Guid id,HttpContext ctx,NpgsqlDataSource ds)=>{
    if(!Authorized(ctx,admin!)) return Results.Unauthorized();
    var rows=new List<object>();
    await using var cmd=ds.CreateCommand("SELECT action_id,action,state,created_at,finished_at FROM remote_actions WHERE device_id=@id ORDER BY created_at DESC LIMIT 30");
    cmd.Parameters.AddWithValue("id",id);
    await using var rd=await cmd.ExecuteReaderAsync();
    while(await rd.ReadAsync()) rows.Add(new {actionId=rd.GetGuid(0),action=rd.GetString(1),state=rd.GetString(2),createdAt=rd.GetDateTime(3),finishedAt=rd.IsDBNull(4)?(DateTime?)null:rd.GetDateTime(4)});
    return Results.Ok(rows);
});


app.MapGet("/control", (HttpContext ctx) =>
{
    ctx.Response.Headers.ContentSecurityPolicy = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
    ctx.Response.Headers.XContentTypeOptions = "nosniff";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    return Results.Content("""
<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nox Remote AI | Cloud-Steuerung</title>
<style>
body{font:16px system-ui;background:#111525;color:#f4f2ff;max-width:680px;margin:48px auto;padding:0 18px}
h1{color:#bda9ff}label{display:block;margin:18px 0 7px}input,select,button{box-sizing:border-box;padding:12px;border-radius:10px;border:1px solid #6e668c;font:inherit}
input,select{background:#252a3e;color:white;width:100%}button{background:#7e5ed8;color:white;cursor:pointer;margin:12px 8px 0 0}
button:disabled{opacity:.5;cursor:default}small{color:#bdb8d2}#status{white-space:pre-wrap;padding:12px;background:#22273a;border-radius:10px;margin-top:16px}
</style></head><body><h1>Nox Remote AI 🐾</h1><p>Cloud-Teststeuerung. Aktionen werden nur bei einer lokal freigegebenen Sitzung ausgeführt.</p>
<label for="token">Admin-Token (nur hier eingeben, niemals im Chat teilen)</label><input id="token" type="password" autocomplete="off" spellcheck="false">
<button id="load">Verbundene Geräte laden</button><label for="device">Gerät auswählen</label><select id="device"><option value="">Erst Geräte laden</option></select>
<label for="action">Testaktion</label><select id="action"><option value="open_notepad">Windows-Editor öffnen</option><option value="open_calculator">Rechner öffnen</option><option value="screen_info">Bildschirmauflösung lokal anzeigen</option></select>
<button id="send" disabled>Testbefehl senden</button><button id="check" disabled>Letzten Status prüfen</button>
<div id="status" role="status">Bereit. Der Token wird nicht gespeichert.</div>
<p><small>Nur HTTPS verwenden. Admin-Token bleibt im Arbeitsspeicher dieser Seite und wird ausschließlich für autorisierte Anfragen an denselben Server verwendet. Tab schließen, um ihn zu verwerfen.</small></p>
<script>
const $=id=>document.getElementById(id);
const status=message=>$('status').textContent=message;
async function api(path,method='GET',body){
 const token=$('token').value.trim();
 if(!token){throw Error('Bitte Admin-Token eingeben.')}
 const response=await fetch(path,{method,headers:{'Authorization':'Bearer '+token,...(body?{'Content-Type':'application/json'}:{})},body:body?JSON.stringify(body):undefined,cache:'no-store'});
 if(!response.ok)throw Error('Serverfehler '+response.status+(response.status===401?' (Token prüfen)':''));
 return response.status===204?null:response.json();
}
$('load').onclick=async()=>{
 try{status('Lade Geräte …');const devices=await api('/admin/devices');const select=$('device');select.replaceChildren();
 for(const d of devices){const opt=document.createElement('option');opt.value=d.deviceId;opt.textContent=d.name+' ('+d.deviceId.slice(0,8)+')';select.append(opt);}
 $('send').disabled=!devices.length;$('check').disabled=!devices.length;
 status(devices.length?devices.length+' Gerät(e) geladen. Wähle eine Testaktion.':'Noch kein Gerät registriert.');
 }catch(e){status(e.message);}
};
$('send').onclick=async()=>{
 const id=$('device').value;if(!id)return;
 const action=$('action').value;
 if(!confirm('Testaktion '+action+' an das ausgewählte Gerät senden?'))return;
 try{const r=await api('/admin/devices/'+encodeURIComponent(id)+'/actions','POST',{action});status('Befehl eingereiht: '+r.actionId+'\nPrüfe die Freigabe auf deinem PC.');}
 catch(e){status(e.message);}
};
$('check').onclick=async()=>{
 try{const r=await api('/admin/devices/'+encodeURIComponent($('device').value)+'/actions');status(r.length?r.slice(0,5).map(a=>a.action+': '+a.state).join('\n'):'Noch keine Aktionen.');}
 catch(e){status(e.message);}
};
</script></body></html>
""", "text/html; charset=utf-8");
});

app.Run();
record EnrollRequest(string Name,string PairingCode);

record RemoteActionRequest(string Action);
record RemoteActionResult(string Status);
