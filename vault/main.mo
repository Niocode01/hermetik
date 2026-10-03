// vault — 1 canister por usuario: backup opaco del vault + log auditable (hash-chain SHA-256).
// - El canister NUNCA ve plaintext: el blob llega ya cifrado (PBKDF2+AES-GCM cliente).
// - Ingress ICP ~2 MiB => el backup (<=12 MiB) se sube en chunks de <=1 MiB.
// - Roles: admin (dueño, bootstrap SOLO por controller + recuperación por
//   upgrade con arg), writers (gateway).
// - Stores separados: backups / log. Cada commit_backup anota un evento en el log (solo hash+versión).
import Time "mo:base/Time";
import Array "mo:base/Array";
import Text "mo:base/Text";
import Principal "mo:base/Principal";
import Nat "mo:base/Nat";
import Int "mo:base/Int";
import Blob "mo:base/Blob";
import Debug "mo:base/Debug";
import Nat64 "mo:base/Nat64";
import Nat8 "mo:base/Nat8";
import Nat16 "mo:base/Nat16";
import Iter "mo:base/Iter";
import IC "mo:base/ExperimentalInternetComputer";

persistent actor Vault {

  let MAX_CHUNK : Nat = 1_048_576;          // 1 MiB por chunk
  let MAX_BACKUP : Nat = 12_582_912;        // 12 MiB total
  let KEEP_VERSIONS : Nat = 3;              // versiones de backup retenidas
  let CHUNK_CAP : Nat = 1000;               // entradas de log por chunk
  let ANON : Principal = Principal.fromText("aaaaa-aa");

  type LogEntry = {
    index : Nat; timestamp_ns : Int; agent_id : Text; action_type : Text;
    action_hash : Text; caller_hash : Text; prev_hash : Text; entry_hash : Text;
    metadata : Text; caller : Principal;
  };
  type Backup = { version : Nat; ts_ns : Int; size : Nat; sha : Text; chunks : [Blob] };
  type Upload = { owner : Principal; total : Nat; received : [Blob] };
  type BackupMeta = { version : Nat; ts_ns : Int; size : Nat; sha : Text; chunk_count : Nat };

  // ---- estado ----
  var admin : Principal = ANON;
  var admin_initialized : Bool = false;
  var writers : [Principal] = [];
  /// Allowlist de AUDITORES EXTERNOS. Pueden leer el LOG (evidencia PoC) pero
  /// NUNCA el backup. Es una frontera distinta de `writers` a proposito: un
  /// auditor no escribe y no toca datos del usuario.
  var auditors : [Principal] = [];
  var read_token : Text = "";
  /// Segundo Bearer SOLO para metadatos de backup (`/backup/version`,
  /// `/backup/meta`). Sin este token separado, el `read_token` del log
  /// abriría también el backup y colapsaría la frontera Candid
  /// (run-2, H5: `requireBackupReader` es solo-dueño, pero HTTP servía
  /// metadatos con el mismo Bearer que abre el log a los auditores).
  var backup_token : Text = "";
  var frozen : Bool = false;

  var log_chunks : [[LogEntry]] = [];
  var next_index : Nat = 0;

  var backups : [Backup] = [];
  var next_version : Nat = 1;
  var upload : ?Upload = null;

  // ---- auth ----
  func isAdmin(c : Principal) : Bool { admin_initialized and Principal.equal(c, admin) };
  func isWriter(c : Principal) : Bool {
    for (w in writers.vals()) { if (Principal.equal(w, c)) { return true } };
    false
  };
  func isAuditor(c : Principal) : Bool {
    for (a in auditors.vals()) { if (Principal.equal(a, c)) { return true } };
    false
  };
  func requireWriter(c : Principal) { if (not (isAdmin(c) or isWriter(c))) { Debug.trap("Unauthorized: not writer") } };
  /// Frontera del LOG: dueno, writer de confianza o auditor de la allowlist.
  func requireLogReader(c : Principal) {
    if (not (isAdmin(c) or isWriter(c) or isAuditor(c))) {
      Debug.trap("Unauthorized: not owner or auditor")
    }
  };
  /// Frontera del BACKUP: SOLO el dueno (admin). Un auditor jamas lee aqui.
  func requireBackupReader(c : Principal) {
    if (not isAdmin(c)) { Debug.trap("Unauthorized: backup is owner-only") }
  };
  func requireAdmin(c : Principal) { if (not isAdmin(c)) { Debug.trap("Unauthorized: not admin") } };
  func notFrozen() { if (frozen) { Debug.trap("Canister is frozen") } };

  // Bootstrap: SOLO un controller del canister puede convertirse en admin.
  // Cierra el H-admin de run-1/run-2 (primero-en-llegar ganaba el control):
  // llamada cruda al management canister (`canister_status`) y exigencia de
  // que `msg.caller` esté en `settings.controllers`. Un tercero sin ser
  // controller recibe trap aunque llegue primero. La ventana de carrera
  // queda limitada a los controllers legítimos (el desplegador), que es
  // exactamente quien debe ser admin.
  //
  // Recuperación: si el admin se pierde, un controller reinstala o hace
  // upgrade (los upgrades los ejecutan solo controllers): el estado
  // persistente sobrevive, y si se pierde, el bootstrap de controller lo
  // restaura. No hay vía para no-controllers (run-2, H-admin).
  //
  // Nota: `canister_status` solo revela controllers al propio canister o a
  // sus controllers; aquí el llamante ES el canister, así que siempre ve
  // la lista. La respuesta se decodifica por Candid con el tipo mínimo.
  type DefiniteCanisterSettings = {
    controllers : ?[Principal];
  };
  type CanisterStatusResult = {
    status : { #running; #stopping; #stopped };
    settings : DefiniteCanisterSettings;
  };
  func isController(c : Principal) : async Bool {
    let mgmt = Principal.fromText("aaaaa-aa");
    let arg = to_candid ({ canister_id = Principal.fromActor(Vault) });
    let raw = await IC.call(mgmt, "canister_status", arg);
    let res : ?CanisterStatusResult = from_candid (raw);
    switch (res) {
      case null { false };
      case (?r) {
        switch (r.settings.controllers) {
          case null { false };
          case (?ctrls) {
            for (ctrl in ctrls.vals()) {
              if (Principal.equal(ctrl, c)) { return true };
            };
            false
          };
        };
      };
    };
  };
  public shared (msg) func admin_bootstrap() : async Principal {
    if (admin_initialized) { Debug.trap("Already bootstrapped") };
    if (not Principal.equal(admin, ANON)) { Debug.trap("Already bootstrapped") };
    let ok = await isController(msg.caller);
    if (not ok) {
      Debug.trap("admin_bootstrap: solo un controller del canister puede ser admin")
    };
    admin := msg.caller; admin_initialized := true; writers := [msg.caller];
    msg.caller
  };
  /// Recuperación post-upgrade: si el estado llega sin admin (reinstalación
  /// o upgrade con estado borrado), el siguiente `admin_bootstrap` de un
  /// controller restaura el admin. Los upgrades los ejecutan solo
  /// controllers, así que la recuperación vive fuera del estado del
  /// canister, donde debe estar (run-2, H-admin).
  system func postupgrade() {
    // Intencionadamente vacío: el estado persistente sobrevive al upgrade
    // y `admin_bootstrap` sigue cerrado por `isController`. Si el estado
    // se pierde, el bootstrap de controller lo restaura.
  };
  public shared (msg) func admin_add_writer(p : Principal) : async Bool {
    requireAdmin(msg.caller);
    if (isWriter(p)) { return false };
    writers := Array.append(writers, [p]); true
  };
  public shared (msg) func admin_remove_writer(p : Principal) : async Bool {
    requireAdmin(msg.caller);
    if (Principal.equal(p, admin)) { Debug.trap("cannot remove admin") };
    writers := Array.filter<Principal>(writers, func(x) { not Principal.equal(x, p) }); true
  };
  public shared query (msg) func admin_list_writers() : async [Principal] { requireAdmin(msg.caller); writers };
  /// Anade un auditor externo. Solo admin. El auditor NO puede ser admin
  /// (seria confundir las fronteras: leer y gobernar son cosas distintas).
  public shared (msg) func admin_add_auditor(p : Principal) : async Bool {
    requireAdmin(msg.caller);
    if (isAuditor(p)) { return false };
    auditors := Array.append(auditors, [p]); true
  };
  public shared (msg) func admin_remove_auditor(p : Principal) : async Bool {
    requireAdmin(msg.caller);
    auditors := Array.filter<Principal>(auditors, func(x) { not Principal.equal(x, p) }); true
  };
  public shared query (msg) func admin_list_auditors() : async [Principal] { requireAdmin(msg.caller); auditors };
  /// Un principal puede preguntar si es auditor (util para que la UI decida
  /// que ensenar sin filtrar la lista completa).
  public shared query (msg) func am_i_auditor() : async Bool { isAuditor(msg.caller) };
  public shared (msg) func admin_set_read_token(t : Text) : async () { requireAdmin(msg.caller); read_token := t };
  /// Fija el Bearer de metadatos de backup. Solo admin. Debe ser DISTINTO
  /// del `read_token`: si coinciden, las rutas de backup lo rechazan
  /// (ver `authorizedBackup`).
  public shared (msg) func admin_set_backup_token(t : Text) : async () { requireAdmin(msg.caller); backup_token := t };
  public shared (msg) func admin_freeze() : async Bool { requireAdmin(msg.caller); frozen := true; true };
  public shared query (msg) func admin_get_admin() : async Text { requireAdmin(msg.caller); Principal.toText(admin) };

  // ---- SHA-256 (idéntico al audit-log de producción s7oui) ----
  func add32(a : Nat64, b : Nat64) : Nat64 {
    (a +% b) & 0xffff_ffff;
  };

  func rotateRight32(value : Nat64, amount : Nat64) : Nat64 {
    ((value >> amount) | (value << (32 - amount))) & 0xffff_ffff;
  };

  func sha256(input : Text) : Text {
    let source = Blob.toArray(Text.encodeUtf8(input));
    let bitLength : Nat64 = Nat64.fromNat(source.size()) *% 8;
    let paddedLength = ((source.size() + 9 + 63) / 64) * 64;
    let bytes = Array.init<Nat8>(paddedLength, 0);
    var i : Nat = 0;
    while (i < source.size()) {
      bytes[i] := source[i];
      i += 1;
    };
    bytes[source.size()] := 0x80;
    i := 0;
    while (i < 8) {
      bytes[paddedLength - 1 - i] := Nat8.fromNat(
        Nat64.toNat((bitLength >> Nat64.fromNat(i * 8)) & 0xff)
      );
      i += 1;
    };

    let k : [Nat64] = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    var h0 : Nat64 = 0x6a09e667;
    var h1 : Nat64 = 0xbb67ae85;
    var h2 : Nat64 = 0x3c6ef372;
    var h3 : Nat64 = 0xa54ff53a;
    var h4 : Nat64 = 0x510e527f;
    var h5 : Nat64 = 0x9b05688c;
    var h6 : Nat64 = 0x1f83d9ab;
    var h7 : Nat64 = 0x5be0cd19;
    var offset : Nat = 0;
    while (offset < paddedLength) {
      let w = Array.init<Nat64>(64, 0);
      i := 0;
      while (i < 16) {
        let p = offset + i * 4;
        w[i] := (Nat64.fromNat(Nat8.toNat(bytes[p])) << 24) |
          (Nat64.fromNat(Nat8.toNat(bytes[p + 1])) << 16) |
          (Nat64.fromNat(Nat8.toNat(bytes[p + 2])) << 8) |
          Nat64.fromNat(Nat8.toNat(bytes[p + 3]));
        i += 1;
      };
      while (i < 64) {
        let x = w[i - 15];
        let y = w[i - 2];
        let s0 = rotateRight32(x, 7) ^ rotateRight32(x, 18) ^ (x >> 3);
        let s1 = rotateRight32(y, 17) ^ rotateRight32(y, 19) ^ (y >> 10);
        w[i] := add32(add32(add32(w[i - 16], s0), w[i - 7]), s1);
        i += 1;
      };
      var a = h0; var b = h1; var c = h2; var d = h3;
      var e = h4; var f = h5; var g = h6; var h = h7;
      i := 0;
      while (i < 64) {
        let s1 = rotateRight32(e, 6) ^ rotateRight32(e, 11) ^ rotateRight32(e, 25);
        let ch = (e & f) ^ (((^e) & 0xffff_ffff) & g);
        let temp1 = add32(add32(add32(add32(h, s1), ch), k[i]), w[i]);
        let s0 = rotateRight32(a, 2) ^ rotateRight32(a, 13) ^ rotateRight32(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = add32(s0, maj);
        h := g; g := f; f := e; e := add32(d, temp1);
        d := c; c := b; b := a; a := add32(temp1, temp2);
        i += 1;
      };
      h0 := add32(h0, a); h1 := add32(h1, b); h2 := add32(h2, c); h3 := add32(h3, d);
      h4 := add32(h4, e); h5 := add32(h5, f); h6 := add32(h6, g); h7 := add32(h7, h);
      offset += 64;
    };

    var out : Text = "";
    for (word in [h0, h1, h2, h3, h4, h5, h6, h7].vals()) {
      var shift : Nat = 28;
      loop {
        out #= hexDigit(Nat64.toNat((word >> Nat64.fromNat(shift)) & 0x0f));
        if (shift == 0) { break };
        shift -= 4;
      };
    };
    out;
  };


  func hexDigit(n : Nat) : Text {
    Text.fromChar(switch (n) {
      case (0) { '0' }; case (1) { '1' }; case (2) { '2' }; case (3) { '3' };
      case (4) { '4' }; case (5) { '5' }; case (6) { '6' }; case (7) { '7' };
      case (8) { '8' }; case (9) { '9' }; case (10) { 'a' }; case (11) { 'b' };
      case (12) { 'c' }; case (13) { 'd' }; case (14) { 'e' }; case _ { 'f' };
    });
  };

  func hashPayload(e : LogEntry) : Text {
    Nat.toText(e.index) # "|" # Int.toText(e.timestamp_ns) # "|" #
    encodeField(e.agent_id) # encodeField(e.action_type) # encodeField(e.action_hash) #
    encodeField(e.metadata) # encodeField(e.caller_hash) # encodeField(e.prev_hash);
  };

  func encodeField(value : Text) : Text {
    Nat.toText(Text.encodeUtf8(value).size()) # ":" # value;
  };

  // ---- Chunked storage helpers ----


  // ---- log ----
  func getEntry(i : Nat) : ?LogEntry {
    if (i >= next_index) { return null };
    let c = i / CHUNK_CAP;
    if (c >= log_chunks.size()) { return null };
    let ch = log_chunks[c];
    let o = i % CHUNK_CAP;
    if (o < ch.size()) { ?ch[o] } else { null }
  };
  func appendEntry(e : LogEntry) {
    let c = e.index / CHUNK_CAP;
    if (c >= log_chunks.size()) { log_chunks := Array.append(log_chunks, [[e]]) }
    else {
      let n = log_chunks.size();
      log_chunks := Array.tabulate<[LogEntry]>(n, func(k) { if (k == c) { Array.append(log_chunks[k], [e]) } else { log_chunks[k] } });
    };
  };
  func addEntry(caller : Principal, agent : Text, typ : Text, ah : Text, meta : Text) : Nat {
    let index = next_index;
    let prev : Text = if (index == 0) { "genesis" } else {
      switch (getEntry(index - 1)) { case (?e) { e.entry_hash }; case null { Debug.trap("Chain gap") } }
    };
    let u : LogEntry = { index; timestamp_ns = Time.now(); agent_id = agent; action_type = typ; action_hash = ah;
      caller_hash = Principal.toText(caller); prev_hash = prev; entry_hash = ""; metadata = meta; caller };
    appendEntry({ u with entry_hash = sha256(hashPayload(u)) });
    next_index += 1;
    index
  };

  public shared (msg) func log_action(agent : Text, typ : Text, ah : Text, meta : Text) : async Nat {
    requireWriter(msg.caller); notFrozen();
    addEntry(msg.caller, agent, typ, ah, meta)
  };
  public shared (msg) func log_batch(b : [(Text, Text, Text, Text)]) : async [Nat] {
    requireWriter(msg.caller); notFrozen();
    Array.map<(Text, Text, Text, Text), Nat>(b, func(x) { addEntry(msg.caller, x.0, x.1, x.2, x.3) })
  };
  /// Verificación de la cadena. Legible por dueno y auditores (es la primitiva
  /// con la que un auditor comprueba que no se ha alterado nada).
  /// C7.6.4 — el acceso al almacen de evidencia aplica control por rol y CADA
  /// LECTURA escribe su propio registro (quien, que, cuando).
  ///
  /// Es `update`, no `query`: una query no puede escribir, y una auditoria sin
  /// rastro de quien la hizo es justo lo que la norma prohibe. El coste de un
  /// update es el precio de que auditar deje huella.
  public shared (msg) func log_read_access(what : Text) : async Nat {
    requireLogReader(msg.caller);
    addEntry(msg.caller, "auditor", "evidence_read", what, "role=" # roleOf(msg.caller))
  };

  func roleOf(c : Principal) : Text {
    if (isAdmin(c)) { "owner" }
    else if (isWriter(c)) { "writer" }
    else if (isAuditor(c)) { "auditor" }
    else { "none" }
  };

  /// Verificacion de la cadena. Legible por dueno y auditores: es la primitiva
  /// con la que un auditor comprueba que no se ha alterado nada.
  public shared query (msg) func verify_chain_authorized() : async (Bool, Text, Nat, Nat) {
    requireLogReader(msg.caller);
    let (ok, bad) = verifyChain();
    (ok, bad, 0, next_index)
  };

  // Núcleo de verificación de la cadena (reutilizado por la query pública y por http_request).
  func verifyChain() : (Bool, Text) {
    var i : Nat = 0;
    while (i < next_index) {
      switch (getEntry(i)) {
        case null { return (false, Nat.toText(i)) };
        case (?e) {
          if (e.entry_hash != sha256(hashPayload(e))) { return (false, Nat.toText(i)) };
          let want : Text = if (i == 0) { "genesis" } else {
            switch (getEntry(i - 1)) { case (?p) { p.entry_hash }; case null { "" } } };
          if (e.prev_hash != want) { return (false, Nat.toText(i)) };
        };
      };
      i += 1;
    };
    (true, "")
  };

  /// `verify_chain` (publica, sin auth) se ELIMINÓ en el fix de run-2 (H6):
  /// era un oráculo público de integridad + tamaño del log. La vía
  /// autorizada es `verify_chain_authorized` (dueño ∪ auditores).
  /// Se conserva `get_total_count` pública solo porque los tests la usan
  /// como contador de progreso, no como prueba de integridad.
  public shared query func verify_chain() : async (Bool, Text, Nat, Nat) {
    Debug.trap("verify_chain publica eliminada (run-2 H6): usar verify_chain_authorized")
  };
  // ---- Consultas certificadas: las query puras NO lo son. Para que el gateway
  // (o cualquier lector no confiable) pueda confiar en lo que lee, exponemos los
  // mismos datos por `http_request` (update => respuesta certificable por el subnet).
  // Todo lo que pasa por aquí exige el `read_token` en el header Authorization.
  func safeEq(a : Text, b : Text) : Bool {
    if (a.size() != b.size()) { return false };
    let x = Blob.toArray(Text.encodeUtf8(a));
    let y = Blob.toArray(Text.encodeUtf8(b));
    var diff : Nat8 = 0;
    var i : Nat = 0;
    while (i < x.size()) { diff := diff | (x[i] ^ y[i]); i += 1 };
    diff == 0
  };

  func jsonEscape(t : Text) : Text {
    var out : Text = "";
    for (c in t.chars()) {
      if (c == '\"') { out #= "\\\"" }
      else if (c == '\\') { out #= "\\\\" }
      else if (c == '\n' or c == '\r' or c == '\t') { out #= " " }
      else { out #= Text.fromChar(c) }
    };
    out
  };

  func jsonHeader() : [HeaderField] {
    [
      ("content-type", "application/json"),
      // CORS: el frontend lee el log desde su propio origen.
      ("access-control-allow-origin", "*")
    ]
  };

  func jsonBody(status : Nat, body : Text) : HttpResponse {
    { status_code = Nat16.fromNat(status); headers = jsonHeader(); body = Text.encodeUtf8(body); upgrade = null }
  };

  func bearer(req : HttpRequest) : Text {
    for ((name, value) in req.headers.vals()) {
      if (Text.toLowercase(name) == "authorization") {
        if (Text.startsWith(value, #text "Bearer ")) {
          return Text.trimStart(value, #text "Bearer ")
        }
      }
    };
    ""
  };

  func authorized(req : HttpRequest) : Bool {
    read_token != "" and safeEq(bearer(req), read_token)
  };

  /// Gate de las rutas de backup: exige el `backup_token`, que debe estar
  /// fijado Y ser distinto del `read_token`. Si el admin los deja iguales
  /// (o deja el backup sin fijar), las rutas de backup responden 401:
  /// fail-closed, nunca se colapsa la frontera (run-2, H5).
  func authorizedBackup(req : HttpRequest) : Bool {
    backup_token != "" and read_token != backup_token
      and safeEq(bearer(req), backup_token)
  };

  type HeaderField = (Text, Text);
  type HttpRequest = { method : Text; url : Text; headers : [HeaderField]; body : Blob; certificate_version : ?Nat16 };
  type HttpResponse = { status_code : Nat16; headers : [HeaderField]; body : Blob; upgrade : ?Bool };

  /// Endpoint HTTP ligero (para el gateway). Rutas:
  ///   GET /log/count            -> { count }            (Bearer: read_token)
  ///   GET /log/recent?n=NN      -> { entries: [...] }  (Bearer: read_token)
  ///   GET /log/entry?i=NN       -> { entry } | 404      (Bearer: read_token)
  ///   GET /chain/verify         -> { ok, bad_index, total } (Bearer: read_token)
  ///   GET /backup/version       -> { version }          (Bearer: backup_token)
  ///   GET /backup/meta          -> { backups: [...] }   (Bearer: backup_token)
  /// Los tokens son DISTINTOS: el del log (compartido con auditores) nunca
  /// abre el backup (run-2, H5). Si coinciden o el de backup no está fijado,
  /// las rutas de backup responden 401.
  public shared (msg) func http_request(req : HttpRequest) : async HttpResponse {
    let url = req.url;
    if (req.method == "OPTIONS") { return jsonBody(204, "") };
    // Rutas de backup: gate PROPIO con backup_token (nunca el read_token).
    // Van ANTES del gate general: si pasaran por authorized(), el token del
    // log las abriría y la frontera colapsaría (run-2, H5).
    if (url == "/backup/version") {
      if (not authorizedBackup(req)) {
        return jsonBody(401, "{\"error\":\"unauthorized\"}");
      };
      let v = if (backups.size() == 0) { 0 } else { backups[backups.size() - 1].version };
      return jsonBody(200, "{\"version\":" # Nat.toText(v) # "}");
    };
    if (url == "/backup/meta" or url == "/backup/list") {
      if (not authorizedBackup(req)) {
        return jsonBody(401, "{\"error\":\"unauthorized\"}");
      };
      var items : Text = "";
      var first = true;
      for (b in backups.vals()) {
        if (not first) { items #= "," };
        items #= "{\"version\":" # Nat.toText(b.version) #
          ",\"ts\":" # Int.toText(b.ts_ns) #
          ",\"size\":" # Nat.toText(b.size) #
          ",\"sha\":\"" # jsonEscape(b.sha) # "\"" #
          ",\"chunks\":" # Nat.toText(b.chunks.size()) # "}";
        first := false;
      };
      return jsonBody(200, "{\"backups\":[" # items # "]}");
    };
    if (not authorized(req)) {
      return jsonBody(401, "{\"error\":\"unauthorized\"}");
    };
    if (url == "/log/count" or url == "/log/total") {
      return jsonBody(200, "{\"count\":" # Nat.toText(next_index) # "}");
    };
    if (Text.startsWith(url, #text "/log/recent")) {
      let n = switch (Iter.toArray(Text.split(url, #char '='))) {
        case (arr) {
          if (arr.size() >= 2) { switch (Nat.fromText(Text.trim(arr[arr.size() - 1], #char '&'))) { case (?v) { v }; case null { 50 } } }
          else { 50 }
        }
      };
      let cap = if (n > 200) { 200 } else { n };
      let start : Nat = if (next_index > cap) { next_index - cap } else { 0 };
      var items : Text = "";
      var i : Nat = start;
      var first = true;
      while (i < next_index) {
        switch (getEntry(i)) {
          case (?e) {
            if (not first) { items #= "," };
            items #= "{\"index\":" # Nat.toText(e.index) #
              ",\"ts\":" # Int.toText(e.timestamp_ns) #
              ",\"agent\":\"" # jsonEscape(e.agent_id) # "\"" #
              ",\"type\":\"" # jsonEscape(e.action_type) # "\"" #
              ",\"hash\":\"" # jsonEscape(e.entry_hash) # "\"" #
              ",\"prev\":\"" # jsonEscape(e.prev_hash) # "\"" #
              ",\"meta\":\"" # jsonEscape(e.metadata) # "\"}";
            first := false
          };
          case null {}
        };
        i += 1;
      };
      return jsonBody(200, "{\"entries\":[" # items # "],\"total\":" # Nat.toText(next_index) # "}");
    };
    if (Text.startsWith(url, #text "/log/entry")) {
      let idx = switch (Iter.toArray(Text.split(url, #char '='))) {
        case (arr) { if (arr.size() >= 2) { Nat.fromText(arr[arr.size() - 1]) } else { null } }
      };
      switch (idx) {
        case (?i) {
          switch (getEntry(i)) {
            case (?e) {
              return jsonBody(200, "{\"entry\":{\"index\":" # Nat.toText(e.index) #
                ",\"ts\":" # Int.toText(e.timestamp_ns) #
                ",\"agent\":\"" # jsonEscape(e.agent_id) # "\"" #
                ",\"type\":\"" # jsonEscape(e.action_type) # "\"" #
                ",\"hash\":\"" # jsonEscape(e.entry_hash) # "\"" #
                ",\"prev\":\"" # jsonEscape(e.prev_hash) # "\"" #
                ",\"meta\":\"" # jsonEscape(e.metadata) # "\"}}")
            };
            case null { return jsonBody(404, "{\"error\":\"not found\"}") }
          }
        };
        case null { return jsonBody(400, "{\"error\":\"bad index\"}") }
      }
    };
    if (Text.startsWith(url, #text "/chain/verify")) {
      let r = verifyChain();
      let (ok, bad) = r;
      return jsonBody(200, "{\"ok\":" # (if (ok) { "true" } else { "false" }) #
        ",\"bad_index\":\"" # bad # "\",\"total\":" # Nat.toText(next_index) # "}");
    };
    if (url == "/health") { return jsonBody(200, "{\"ok\":true}") };
    jsonBody(404, "{\"error\":\"not found\"}")
  };

  public shared query func get_total_count() : async Nat { next_index };
  public shared query (msg) func get_entry(i : Nat) : async ?LogEntry { requireLogReader(msg.caller); getEntry(i) };
  public shared query (msg) func get_recent_entries(limit : Nat) : async [LogEntry] {
    requireLogReader(msg.caller);
    let n = if (limit > 200) { 200 } else { limit };
    let start : Nat = if (next_index > n) { next_index - n } else { 0 };
    Array.tabulate<LogEntry>(next_index - start, func(k) { switch (getEntry(start + k)) { case (?e) e; case null Debug.trap("gap") } })
  };

  // ---- backup (subida por chunks; el blob es opaco/cifrado) ----
  public shared (msg) func backup_begin(total_chunks : Nat) : async () {
    requireWriter(msg.caller); notFrozen();
    if (total_chunks == 0 or total_chunks * MAX_CHUNK > MAX_BACKUP + MAX_CHUNK) { Debug.trap("bad total_chunks") };
    upload := ?{ owner = msg.caller; total = total_chunks; received = [] };
  };
  public shared (msg) func backup_put(idx : Nat, chunk : Blob) : async () {
    requireWriter(msg.caller); notFrozen();
    if (chunk.size() > MAX_CHUNK or chunk.size() == 0) { Debug.trap("bad chunk size") };
    switch (upload) {
      case null { Debug.trap("no upload in progress") };
      case (?u) {
        if (not Principal.equal(u.owner, msg.caller)) { Debug.trap("upload owned by other caller") };
        if (idx != u.received.size() or idx >= u.total) { Debug.trap("out-of-order chunk") };
        upload := ?{ u with received = Array.append(u.received, [chunk]) };
      };
    };
  };
  // sha = SHA-256 hex del blob completo calculado por el cliente (integridad; se registra en el log).
  public shared (msg) func backup_commit(sha : Text) : async Nat {
    requireWriter(msg.caller); notFrozen();
    switch (upload) {
      case null { Debug.trap("no upload in progress") };
      case (?u) {
        if (not Principal.equal(u.owner, msg.caller)) { Debug.trap("upload owned by other caller") };
        if (u.received.size() != u.total) { Debug.trap("incomplete upload") };
        var size : Nat = 0;
        for (c in u.received.vals()) { size += c.size() };
        if (size > MAX_BACKUP) { upload := null; Debug.trap("backup too large") };
        let v = next_version; next_version += 1;
        let b : Backup = { version = v; ts_ns = Time.now(); size; sha; chunks = u.received };
        let all = Array.append(backups, [b]);
        backups := if (all.size() > KEEP_VERSIONS) { Array.tabulate<Backup>(KEEP_VERSIONS, func(k) { all[all.size() - KEEP_VERSIONS + k] }) } else { all };
        upload := null;
        ignore addEntry(msg.caller, "hermetik-vault", "vault_backup", sha, "v=" # Nat.toText(v) # ";size=" # Nat.toText(size));
        v
      };
    };
  };
  public shared (msg) func backup_abort() : async () { requireWriter(msg.caller); upload := null };

  func meta(b : Backup) : BackupMeta { { version = b.version; ts_ns = b.ts_ns; size = b.size; sha = b.sha; chunk_count = b.chunks.size() } };
  public shared query (msg) func get_backup_version() : async Nat {
    requireBackupReader(msg.caller);
    if (backups.size() == 0) { 0 } else { backups[backups.size() - 1].version }
  };
  public shared query (msg) func list_backups() : async [BackupMeta] {
    requireBackupReader(msg.caller); Array.map<Backup, BackupMeta>(backups, meta)
  };
  // version 0 = la última
  public shared query (msg) func get_backup_chunk(version : Nat, idx : Nat) : async ?Blob {
    requireBackupReader(msg.caller);
    for (b in backups.vals()) {
      if (b.version == version or (version == 0 and next_version > 1 and b.version == next_version - 1)) {
        return if (idx < b.chunks.size()) { ?b.chunks[idx] } else { null };
      };
    };
    null
  };
}
