//! F26-B: persistent Boss Runtime IPC client for the outer Secrets systemd process.
//!
//! Staged but NOT ACTIVATED until the module's installed entrypoint is migrated
//! to `runtime/neebles-secrets` and the Qt launch lifecycle is adapted. This
//! avoids two competing runtime registrations and preserves existing Open.
//!
//! Invariant: this module must run ONLY in the outer broker process. The
//! internal bwrap KeePassXC worker never sees /run/neebles/modules.sock.
use serde_json::{json, Value};
use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const MODULE: &str = "neebles-secrets";
const SOCKET: &str = "/run/neebles/modules.sock";
const ENTRYPOINT: &str = "runtime/neebles-secrets";
const MAX_INCOMING: usize = 64 * 1024; // Health-only envelope, never secret bulk data.
const FRAME_STALL_TIMEOUT: Duration = Duration::from_secs(15);
const SOCKET_POLL: Duration = Duration::from_millis(500);
const RECONNECT_DELAY: Duration = Duration::from_millis(1500);

fn eligible_manifest(manifest: &Value, version: &str) -> bool {
    manifest.get("name").and_then(Value::as_str) == Some(MODULE)
        && manifest.get("version").and_then(Value::as_str) == Some(version)
        && manifest.get("entrypoint").and_then(Value::as_str) == Some(ENTRYPOINT)
}

/// A hard gate: the Boss process verifier checks `/proc/<peer>/exe` against
/// the installed entrypoint. Never attempt provider registration from a
/// process belonging to the old Qt entrypoint.
fn installed_provider_ready() -> Result<bool, String> {
    let exe = std::env::current_exe().map_err(|e| format!("Secrets executable: {e}"))?;
    let root = exe.parent().and_then(Path::parent).ok_or("Secrets module root unavailable")?;
    let document = fs::read(root.join("manifest.json"))
        .map_err(|e| format!("Secrets installed manifest unavailable: {e}"))?;
    let manifest: Value = serde_json::from_slice(&document)
        .map_err(|_| "Secrets installed manifest invalid JSON".to_string())?;
    Ok(eligible_manifest(&manifest, env!("CARGO_PKG_VERSION")))
}

fn verify_boss(message: &Value, kind: &str, session: &str) -> Result<(), String> {
    if message.get("type").and_then(Value::as_str) == Some("error") {
        return Err("Boss rejected Secrets persistent runtime session".into());
    }
    if message.get("type").and_then(Value::as_str) != Some(kind)
        || message.get("module").and_then(Value::as_str) != Some(MODULE)
        || message.get("session_id").and_then(Value::as_str) != Some(session)
        || (kind == "registered" && message.get("protocol").and_then(Value::as_u64) != Some(1))
    {
        return Err(format!("Boss persistent runtime expected {kind} with verified identity"));
    }
    Ok(())
}

/// No locks are held across IPC reads. A partial frame is never discarded and
/// reread as a fresh header. Idle reads can stop within SOCKET_POLL.
fn read_bytes(stream: &mut UnixStream, mut buf: &mut [u8], alive: &AtomicBool) -> Result<bool, String> {
    let mut last_progress = Instant::now();
    let mut frame_started = false;
    while !buf.is_empty() {
        if !alive.load(Ordering::Acquire) { return Ok(false); }
        match stream.read(buf) {
            Ok(0) => return Err("Boss IPC disconnected".into()),
            Ok(n) => { buf = &mut buf[n..]; frame_started = true; last_progress = Instant::now(); }
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                if frame_started && last_progress.elapsed() > FRAME_STALL_TIMEOUT { return Err("Boss IPC frame stalled".into()); }
            }
            Err(_) => return Err("Boss IPC read failure".into()),
        }
    }
    Ok(true)
}

fn read_message(stream: &mut UnixStream, alive: &AtomicBool) -> Result<Option<Value>, String> {
    let mut len = [0u8; 4];
    if !read_bytes(stream, &mut len, alive)? { return Ok(None); }
    let length = u32::from_be_bytes(len) as usize;
    if length == 0 || length > MAX_INCOMING { return Err("Boss IPC oversized frame".into()); }
    let mut payload = vec![0u8; length];
    if !read_bytes(stream, &mut payload, alive)? { return Ok(None); }
    let msg: Value = serde_json::from_slice(&payload)
        .map_err(|_| "Boss IPC invalid JSON".to_string())?;
    if !msg.is_object() { return Err("Boss IPC invalid message".into()); }
    Ok(Some(msg))
}

fn handle_message(msg: &Value, session: &str) -> Result<(Option<Value>, bool), String> {
    if msg.get("module").and_then(Value::as_str) != Some(MODULE)
        || msg.get("session_id").and_then(Value::as_str) != Some(session)
    {
        return Err("Boss IPC message identity mismatch".into());
    }
    match msg.get("type").and_then(Value::as_str) {
        Some("invoke") => {
            // F26-H: reserve vault routes but do not advertise or perform them.
            // Scope is derived only from Boss-injected authenticated context;
            // a client-supplied module field never authorizes KDBX access.
            let endpoint = msg.get("endpoint").and_then(Value::as_str);
            let response = if endpoint == Some(super::boss_vault_bridge::STATUS_ENDPOINT) {
                // A provider without its private worker channel is unavailable,
                // never a reason to accept or retry a mutating request.
                super::boss_vault_bridge::authorized_request_status(msg,session,None)?
             } else if endpoint == Some(super::boss_vault_bridge::REQUEST_ENDPOINT) {
                super::boss_vault_bridge::authorized_request(msg,session,None)?
            } else if endpoint == Some("secrets.vault.exists.v1") {
                super::boss_scope::staged_vault_reply(msg, session)?
            } else {
                super::boss_health::persistent_health_response(msg, session)?
            };
            Ok((Some(response), false))
        },
        Some("ping") => Ok((Some(json!({"type":"pong","module":MODULE,"session_id":session})), false)),
        Some("shutdown") => Ok((Some(json!({"type":"shutdown_ack","module":MODULE,"session_id":session})), true)),
        Some("event") | Some("notification_closed") => Ok((None, false)),
        Some("error") => Err("Boss reported an IPC runtime error".into()),
        _ => Err("Unsupported Boss IPC message type".into()),
    }
}

#[derive(PartialEq, Eq)]
enum SessionEnd { Reconnect, Shutdown }

fn session_at(socket: &Path, alive: &AtomicBool, broker_control: Option<&UnixDatagram>) -> Result<SessionEnd, String> {
    let mut stream = UnixStream::connect(socket).map_err(|_| "Boss module socket unavailable".to_string())?;
    stream.set_read_timeout(Some(SOCKET_POLL)).map_err(|_| "cannot set Boss read timeout")?;
    stream.set_write_timeout(Some(Duration::from_secs(3))).map_err(|_| "cannot set Boss write timeout")?;
    let id = super::uuid_v4()?;
    super::rpc_write(&mut stream, &json!({
        "type":"register", "protocol":1, "module":MODULE, "session_id":id,
        "endpoints":{"commands":[super::boss_health::ENDPOINT,super::boss_vault_bridge::ENDPOINT,super::boss_vault_bridge::STATUS_ENDPOINT,super::boss_vault_bridge::REQUEST_ENDPOINT]}
    }))?;
    let reply = read_message(&mut stream, alive)?.ok_or("Provider interrupted before registration")?;
    verify_boss(&reply, "registered", &id)?;
    while alive.load(Ordering::Acquire) {
        let Some(msg) = read_message(&mut stream, alive)? else { break; };
        // Vault existence is declared + advertised, but Boss requires an
        // installed per-consumer grant before forwarding; writes stay disabled.
        // Recheck Boss-injected identity before passing the private FD.
        let (reply, shutdown) = if msg.get("type").and_then(Value::as_str) == Some("invoke")
            && msg.get("endpoint").and_then(Value::as_str) == Some("secrets.vault.exists.v1")
        {
            match broker_control {
                Some(control) => (Some(super::boss_vault_bridge::authorized_exists(&msg, &id, control)?), false),
                None => handle_message(&msg, &id)?,
            }
        } else if msg.get("type").and_then(Value::as_str) == Some("invoke")
            && msg.get("endpoint").and_then(Value::as_str) == Some(super::boss_vault_bridge::STATUS_ENDPOINT)
        {
            (Some(super::boss_vault_bridge::authorized_request_status(&msg,&id,broker_control)?),false)
        } else if msg.get("type").and_then(Value::as_str) == Some("invoke")
            && msg.get("endpoint").and_then(Value::as_str) == Some(super::boss_vault_bridge::REQUEST_ENDPOINT)
        {
            (Some(super::boss_vault_bridge::authorized_request(&msg,&id,broker_control)?),false)
        } else { handle_message(&msg, &id)? };
        if let Some(reply) = reply { super::rpc_write(&mut stream, &reply)?; }
        if shutdown { return Ok(SessionEnd::Shutdown); }
    }
    let _ = super::rpc_write(&mut stream, &json!({
        "type":"unregister", "module":MODULE,"session_id":id,"reason":"provider_exit"
    }));
    Ok(SessionEnd::Reconnect)
}

// Production always connects to the fixed Boss socket. Tests pass an isolated
// temporary Unix socket to exercise the same wire implementation end to end.
fn session(alive: &AtomicBool, control: &UnixDatagram) -> Result<SessionEnd, String> {
    session_at(Path::new(SOCKET), alive, Some(control))
}

/// Separate from `register_service` variable publication. Future F26-C wires
/// this worker only after the installed manifest and Qt lifecycle are migrated
/// atomically. Never call it from the inner KeePassXC process.
pub(super) fn run(alive: Arc<AtomicBool>, control: UnixDatagram) {
    match installed_provider_ready() {
        Ok(true) => {}
        Ok(false) => { eprintln!("NEEBLES Secrets: persistent provider not enabled for installed entrypoint"); return; }
        Err(_) => { eprintln!("NEEBLES Secrets: persistent provider identity preflight failed"); return; }
    }
    let mut previous_error: Option<String> = None;
    while alive.load(Ordering::Acquire) {
        match session(&alive, &control) {
            Ok(SessionEnd::Shutdown) => break,
            Ok(SessionEnd::Reconnect) => { previous_error = None; }
            Err(error) => {
                if previous_error.as_deref() != Some(error.as_str()) {
                    eprintln!("NEEBLES Secrets provider: {error}");
                    previous_error = Some(error);
                }
            }
        }
        let start = Instant::now();
        while alive.load(Ordering::Acquire) && start.elapsed() < RECONNECT_DELAY {
            thread::sleep(Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registered_identity_is_strict() {
        let good=json!({"type":"registered","protocol":1,"module":MODULE,"session_id":"abc"});
        assert!(verify_boss(&good,"registered","abc").is_ok());
        assert!(verify_boss(&good,"registered","wrong").is_err());
        assert!(verify_boss(&json!({"type":"registered","protocol":2,"module":MODULE,"session_id":"abc"}),"registered","abc").is_err());
    }
    #[test]
    fn accepts_only_daemon_entrypoint_with_matching_version() {
        let good=json!({"name":MODULE,"version":"1.0.5","entrypoint":ENTRYPOINT});
        assert!(eligible_manifest(&good,"1.0.5"));
        assert!(!eligible_manifest(&good,"1.0.4"));
        let mut ui=good.clone(); ui["entrypoint"]=json!("runtime/neebles-secrets-ui");
        assert!(!eligible_manifest(&ui,"1.0.5"));
    }
    #[test]
    fn response_scope_and_no_secret_leakage() {
        let call=json!({"type":"invoke","id":"job-1","module":MODULE,"session_id":"s","contract":"commands","endpoint":"secrets.health.v1","args":[],"payload":null,"context":{"caller":"FORGED"}});
        let (reply,stop)=handle_message(&call,"s").unwrap();
        assert!(!stop);
        let reply=reply.unwrap();
        assert_eq!(reply["result"]["scope"],"persistent_daemon");
        assert!(!reply.to_string().contains("FORGED"));
        assert!(!reply.to_string().contains("master_key"));
        assert!(handle_message(&call,"foreign").is_err());
    }
    #[test]
    fn shutdown_and_ping_do_not_expose_state() {
        let ping=json!({"type":"ping","module":MODULE,"session_id":"s"});
        assert_eq!(handle_message(&ping,"s").unwrap().0.unwrap()["type"],"pong");
        let shut=json!({"type":"shutdown","module":MODULE,"session_id":"s"});
        let (ack,stop)=handle_message(&shut,"s").unwrap();
        assert!(stop);
        assert_eq!(ack.unwrap()["type"],"shutdown_ack");
    }
    // F26-G: full protocol exchange using a local fake Boss socket.
    // No systemd, installed Boss, /opt or KDBX access; exercises the same
    // framing and session code as the persistent provider.
    fn mock_listener(label: &str) -> (std::path::PathBuf, std::os::unix::net::UnixListener) {
        use std::os::unix::net::UnixListener;
        use std::time::{SystemTime, UNIX_EPOCH};
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "neebles-f26g-{}-{}-{}.sock", label, std::process::id(), nonce
        ));
        (path.clone(), UnixListener::bind(&path).expect("bind isolated mock Boss socket"))
    }

    #[test]
    fn mock_boss_full_wire_roundtrip() {
        use std::time::Duration;
        let (path, listener) = mock_listener("roundtrip");
        let alive = Arc::new(AtomicBool::new(true));
        let worker_flag = Arc::clone(&alive);
        let client_path = path.clone();
        let client = thread::spawn(move || session_at(&client_path, &worker_flag, None));
        let (mut wire, _) = listener.accept().expect("provider must connect");
        wire.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        wire.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

        let register = crate::rpc_read(&mut wire).expect("read register");
        assert_eq!(register["type"], "register");
        assert_eq!(register["protocol"], 1);
        assert_eq!(register["module"], MODULE);
        assert_eq!(register["endpoints"]["commands"], json!(["secrets.health.v1", "secrets.vault.exists.v1", "secrets.vault.request_status.v1", "secrets.vault.request.v1"]));
        let id = register["session_id"].as_str().unwrap();
        assert!(!id.is_empty());
        let identity = id.to_owned();
        crate::rpc_write(&mut wire, &json!({
            "type":"registered", "protocol":1, "module":MODULE,"session_id":identity
        })).unwrap();

        crate::rpc_write(&mut wire, &json!({
            "type":"invoke", "id":"request-1", "module":MODULE, "session_id":identity,
            "contract":"commands", "endpoint":"secrets.health.v1",
            "lifecycle":"runtime", "state_mode":"preserve",
            "args":[], "payload":null, "context":{"caller":"FORGED_IDENTITY"}
        })).unwrap();
        let result = crate::rpc_read(&mut wire).expect("read response");
        assert_eq!(result["type"], "response");
        assert_eq!(result["id"], "request-1");
        assert_eq!(result["session_id"], identity);
        assert_eq!(result["ok"], true);
        assert_eq!(result["result"]["scope"], "persistent_daemon");
        assert!(!result.to_string().contains("FORGED_IDENTITY"));
        assert!(!result.to_string().contains("master_key"));

        crate::rpc_write(&mut wire, &json!({
            "type":"ping", "module":MODULE,"session_id":identity
        })).unwrap();
        let pong = crate::rpc_read(&mut wire).expect("read pong");
        assert_eq!(pong["type"], "pong");
        assert_eq!(pong["session_id"], identity);

        crate::rpc_write(&mut wire, &json!({
            "type":"shutdown", "module":MODULE,"session_id":identity
        })).unwrap();
        let ack = crate::rpc_read(&mut wire).expect("read shutdown ack");
        assert_eq!(ack["type"], "shutdown_ack");
        assert_eq!(ack["session_id"], identity);
        assert!(matches!(client.join().unwrap(), Ok(SessionEnd::Shutdown)));
        drop(wire);
        drop(listener);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn mock_boss_rejects_foreign_registration() {
        use std::time::Duration;
        let (path, listener) = mock_listener("reject");
        let alive = Arc::new(AtomicBool::new(true));
        let worker_flag = Arc::clone(&alive);
        let client_path = path.clone();
        let client = thread::spawn(move || session_at(&client_path, &worker_flag, None));
        let (mut wire, _) = listener.accept().unwrap();
        wire.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let registration = crate::rpc_read(&mut wire).unwrap();
        assert_eq!(registration["type"], "register");
        crate::rpc_write(&mut wire, &json!({
            "type":"registered", "protocol":1,
            "module":"foreign-module", "session_id":registration["session_id"]
        })).unwrap();
        let result = client.join().unwrap();
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("verified identity"));
        drop(wire);
        drop(listener);
        std::fs::remove_file(&path).unwrap();
    }


#[test]
fn boss_mock_vault_exists_roundtrip_uses_scoped_worker_fd() {
    use std::time::Duration;
    let (path, listener) = mock_listener("scoped-read");
    let (broker, worker) = UnixDatagram::pair().unwrap();
    let alive = Arc::new(AtomicBool::new(true));
    let child_alive = Arc::clone(&alive);
    let client_path = path.clone();
    let client = thread::spawn(move || session_at(&client_path, &child_alive, Some(&broker)));
    let worker_thread = thread::spawn(move || {
        let (mut stream, peer) = crate::ipc_bridge::recv_connection(&worker).unwrap();
        assert_eq!(peer.as_deref(), Some("neebles-connect"));
        let call = crate::rpc_read(&mut stream).unwrap();
        assert_eq!(call, json!({"op":"vault.exists","module":"neebles-connect"}));
        crate::rpc_write(&mut stream, &json!({
            "ok":true,"data":{"module":"neebles-connect","exists":true,"locked":true,
            "private_marker":"DO_NOT_FORWARD"}
        })).unwrap();
    });
    let (mut wire, _) = listener.accept().unwrap();
    wire.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    wire.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let registration = crate::rpc_read(&mut wire).unwrap();
    assert_eq!(registration["endpoints"]["commands"],
        json!(["secrets.health.v1", "secrets.vault.exists.v1", "secrets.vault.request_status.v1", "secrets.vault.request.v1"]));
    let id = registration["session_id"].as_str().unwrap().to_string();
    crate::rpc_write(&mut wire, &json!({
        "type":"registered","protocol":1,"module":MODULE,"session_id":id
    })).unwrap();
    crate::rpc_write(&mut wire, &json!({
        "type":"invoke","id":"exists-1","module":MODULE,"session_id":id,
        "contract":"commands","endpoint":"secrets.vault.exists.v1",
        "args":[],"payload":null,
        "context":{"caller":"FORGED","neebles_authenticated_module":"neebles-connect",
                   "neebles_authenticated_session":"consumer-1"}
    })).unwrap();
    let result = crate::rpc_read(&mut wire).unwrap();
    assert_eq!(result["type"], "response");
    assert_eq!(result["id"], "exists-1");
    assert_eq!(result["ok"], true);
    assert_eq!(result["result"], json!({"exists":true,"locked":true}));
    assert!(!result.to_string().contains("DO_NOT_FORWARD"));
    assert!(!result.to_string().contains("FORGED"));
    crate::rpc_write(&mut wire, &json!({
        "type":"shutdown","module":MODULE,"session_id":id
    })).unwrap();
    assert_eq!(crate::rpc_read(&mut wire).unwrap()["type"], "shutdown_ack");
    worker_thread.join().unwrap();
    assert!(matches!(client.join().unwrap(), Ok(SessionEnd::Shutdown)));
    drop(wire);
    drop(listener);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn boss_mock_cross_vault_denied_before_worker_handoff() {
    use std::time::Duration;
    let (path, listener) = mock_listener("scoped-deny");
    let (broker, worker) = UnixDatagram::pair().unwrap();
    worker.set_nonblocking(true).unwrap();
    let alive = Arc::new(AtomicBool::new(true));
    let child_alive = Arc::clone(&alive);
    let client_path = path.clone();
    let client = thread::spawn(move || session_at(&client_path, &child_alive, Some(&broker)));
    let (mut wire, _) = listener.accept().unwrap();
    wire.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let registration = crate::rpc_read(&mut wire).unwrap();
    let id = registration["session_id"].as_str().unwrap().to_string();
    crate::rpc_write(&mut wire, &json!({
        "type":"registered","protocol":1,"module":MODULE,"session_id":id
    })).unwrap();
    crate::rpc_write(&mut wire, &json!({
        "type":"invoke","id":"denied-1","module":MODULE,"session_id":id,
        "contract":"commands","endpoint":"secrets.vault.exists.v1",
        "args":[],"payload":{"module_id":"neebles-other"},
        "context":{"neebles_authenticated_module":"neebles-connect",
                   "neebles_authenticated_session":"consumer-1"}
    })).unwrap();
    let result = crate::rpc_read(&mut wire).unwrap();
    assert_eq!(result["ok"], false);
    assert_eq!(result["code"], 403);
    assert_eq!(result["result"], Value::Null);
    assert!(crate::ipc_bridge::recv_connection(&worker).is_err());
    crate::rpc_write(&mut wire, &json!({
        "type":"shutdown","module":MODULE,"session_id":id
    })).unwrap();
    assert_eq!(crate::rpc_read(&mut wire).unwrap()["type"], "shutdown_ack");
    assert!(matches!(client.join().unwrap(), Ok(SessionEnd::Shutdown)));
    drop(wire);
    drop(listener);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn boss_mock_status_roundtrip_with_authenticated_worker_and_no_write() {
    use std::time::Duration;
    let (path, listener) = mock_listener("request-status");
    let (broker, worker) = UnixDatagram::pair().unwrap();
    let alive = Arc::new(AtomicBool::new(true));
    let child_alive = Arc::clone(&alive);
    let client_path = path.clone();
    let client = thread::spawn(move || session_at(&client_path, &child_alive, Some(&broker)));
    let worker_thread = thread::spawn(move || {
        let (mut stream, peer) = crate::ipc_bridge::recv_connection(&worker).unwrap();
        assert_eq!(peer.as_deref(),Some("neebles-connect"));
        let call = crate::rpc_read(&mut stream).unwrap();
        assert_eq!(call["op"],"vault.request_status");
        assert_eq!(call["module"],"neebles-connect");
        assert_eq!(call["request_id"],"9a3e5c7d-22a0-4f12-9c34-831aa23ad504");
        crate::rpc_write(&mut stream,&json!({"ok":true,"data":{
            "module":"neebles-connect","request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504",
            "state":"succeeded","internal_path":"NEVER_LEAK"}})).unwrap();
    });
    let (mut wire,_) = listener.accept().unwrap();
    wire.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    wire.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let registration=crate::rpc_read(&mut wire).unwrap();
    assert!(registration["endpoints"]["commands"].as_array().unwrap().iter().any(|v|v.as_str()==Some("secrets.vault.request_status.v1")));
    assert!(registration["endpoints"]["commands"].as_array().unwrap().iter().any(|v|v.as_str()==Some("secrets.vault.request.v1")));
    let id=registration["session_id"].as_str().unwrap().to_string();
    crate::rpc_write(&mut wire,&json!({"type":"registered","protocol":1,"module":MODULE,"session_id":id})).unwrap();
    crate::rpc_write(&mut wire,&json!({
        "type":"invoke","id":"status-1","module":MODULE,"session_id":id,
        "contract":"commands","endpoint":"secrets.vault.request_status.v1","args":[],
        "payload":{"request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504"},
        "context":{"neebles_authenticated_module":"neebles-connect",
                   "neebles_authenticated_session":"consumer-1"}
    })).unwrap();
    let reply=crate::rpc_read(&mut wire).unwrap();
    assert_eq!(reply["ok"],true);
    assert_eq!(reply["result"],json!({"state":"succeeded"}));
    assert!(!reply.to_string().contains("NEVER_LEAK"));
    crate::rpc_write(&mut wire,&json!({"type":"shutdown","module":MODULE,"session_id":id})).unwrap();
    assert_eq!(crate::rpc_read(&mut wire).unwrap()["type"],"shutdown_ack");
    worker_thread.join().unwrap();
    assert!(matches!(client.join().unwrap(),Ok(SessionEnd::Shutdown)));
    drop(wire);drop(listener);std::fs::remove_file(path).unwrap();
}


#[test]
fn boss_mock_durable_write_once_and_reconciliation_are_distinct_operations() {
    use std::time::Duration;
    let (path,listener)=mock_listener("durable-request");
    let (broker,worker)=UnixDatagram::pair().unwrap();
    let alive=Arc::new(AtomicBool::new(true));
    let client_alive=Arc::clone(&alive);
    let client_path=path.clone();
    let client=thread::spawn(move || session_at(&client_path,&client_alive,Some(&broker)));
    let worker_thread=thread::spawn(move || {
        let (mut write_wire,peer)=crate::ipc_bridge::recv_connection(&worker).unwrap();
        assert_eq!(peer.as_deref(),Some("neebles-connect"));
        let first=crate::rpc_read(&mut write_wire).unwrap();
        assert_eq!(first,json!({"op":"vault.request_id","module":"neebles-connect",
            "request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504"}));
        crate::rpc_write(&mut write_wire,&json!({"ok":true,"data":{
            "module":"neebles-connect","request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504",
            "pending":true,"exists":false,"replayed":false,"private":"DO_NOT_ECHO"}})).unwrap();
        let (mut status_wire,peer)=crate::ipc_bridge::recv_connection(&worker).unwrap();
        assert_eq!(peer.as_deref(),Some("neebles-connect"));
        let second=crate::rpc_read(&mut status_wire).unwrap();
        assert_eq!(second["op"],"vault.request_status");
        assert_eq!(second["request_id"],first["request_id"]);
        crate::rpc_write(&mut status_wire,&json!({"ok":true,"data":{
            "module":"neebles-connect","request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504",
            "state":"pending"}})).unwrap();
    });
    let (mut wire,_)=listener.accept().unwrap();
    wire.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    wire.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let registration=crate::rpc_read(&mut wire).unwrap();
    assert_eq!(registration["endpoints"]["commands"].as_array().unwrap().len(),4);
    let id=registration["session_id"].as_str().unwrap().to_string();
    crate::rpc_write(&mut wire,&json!({"type":"registered","protocol":1,"module":MODULE,"session_id":id})).unwrap();
    for (endpoint,result) in [
        ("secrets.vault.request.v1",json!({"state":"pending","replayed":false})),
        ("secrets.vault.request_status.v1",json!({"state":"pending"}))
    ] {
        crate::rpc_write(&mut wire,&json!({"type":"invoke","id":"job-one","module":MODULE,
            "session_id":id,"contract":"commands","endpoint":endpoint,"args":[],
            "payload":{"request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504"},
            "context":{"neebles_authenticated_module":"neebles-connect",
                       "neebles_authenticated_session":"consumer-1"}})).unwrap();
        let reply=crate::rpc_read(&mut wire).unwrap();
        assert_eq!(reply["ok"],true);
        assert_eq!(reply["result"],result);
        assert!(!reply.to_string().contains("DO_NOT_ECHO"));
    }
    crate::rpc_write(&mut wire,&json!({"type":"shutdown","module":MODULE,"session_id":id})).unwrap();
    assert_eq!(crate::rpc_read(&mut wire).unwrap()["type"],"shutdown_ack");
    worker_thread.join().unwrap();
    assert!(matches!(client.join().unwrap(),Ok(SessionEnd::Shutdown)));
    drop(wire);drop(listener);std::fs::remove_file(path).unwrap();
}

    #[test]
    fn rejects_oversized_frame_without_allocating() {
        use std::os::unix::net::UnixStream;
        use std::io::Write;
        let (mut sender,mut receiver)=UnixStream::pair().unwrap();
        sender.write_all(&((MAX_INCOMING+1) as u32).to_be_bytes()).unwrap();
        let alive=AtomicBool::new(true);
        assert!(read_message(&mut receiver,&alive).unwrap_err().contains("oversized"));
    }


    // F26-W: REAL candidate VaultController and real KeePassXC inside a
    // disposable Bubblewrap world, but simulated Boss transport. NO installed
    // Boss sockets, service registrations, installed vaults or host HOME mount.
    #[test]
    #[ignore = "F26-W: disposable Bubblewrap with genuine KeePassXC only"]
    fn f26w_real_boss_wire_to_encrypted_vault_worker_and_reconcile() {
        use std::sync::{mpsc, Mutex};
        assert_eq!(std::env::var("NEEBLES_F26W_SANDBOX").unwrap(), "disposable-only");
        assert_eq!(std::env::var("XDG_DATA_HOME").unwrap(), "/qa-data");
        assert!(Path::new("/qa-data").is_dir());
        // Never operate outside an isolated test environment, even if invoked
        // with the --ignored flag by accident on the host.
        let module = "neebles-connect";
        let request_id = "55555555555555555555555555555555";
        let (path, listener) = mock_listener("real-kdbx-worker");
        let (broker, worker) = UnixDatagram::pair().unwrap();
        let alive = Arc::new(AtomicBool::new(true));
        let client_alive = Arc::clone(&alive);
        let client_path = path.clone();
        let client = thread::spawn(move || session_at(&client_path, &client_alive, Some(&broker)));
        let (unlocked_tx, unlocked_rx) = mpsc::channel();
        let secret = format!("f26w-{}-{}", crate::uuid_v4().unwrap(), crate::uuid_v4().unwrap());
        let worker_thread = thread::spawn(move || {
            let state = Arc::new(Mutex::new(crate::vault::VaultController::new().unwrap()));
            // 1. request, 2. pending status, 3. succeeded status,
            // 4. idempotent replay, 5. non-mutating existence check.
            for ordinal in 0..5 {
                let (mut stream, peer) = crate::ipc_bridge::recv_connection(&worker).unwrap();
                assert_eq!(peer.as_deref(), Some("neebles-connect"));
                let message = crate::rpc_read(&mut stream).unwrap();
                assert_eq!(message["module"], module);
                match ordinal {
                    0 | 3 => assert_eq!(message["op"], "vault.request_id"),
                    1 | 2 => assert_eq!(message["op"], "vault.request_status"),
                    4 => assert_eq!(message["op"], "vault.exists"),
                    _ => unreachable!(),
                }
                let answer = crate::handle(&message, peer.as_deref(), &state);
                assert_eq!(answer["ok"], true, "worker refused legitimate request");
                crate::rpc_write(&mut stream, &answer).unwrap();
                if ordinal == 1 {
                    // This is a local stand-in for a trusted Secrets desktop
                    // unlock. Boss never receives the Master Key.
                    state.lock().unwrap().setup(&secret).unwrap();
                    unlocked_tx.send(()).unwrap();
                }
            }
            let data = state.lock().unwrap();
            assert_eq!(data.request_status_with_id(module, request_id).unwrap()["state"], "succeeded");
            assert_eq!(data.request_status_with_id("neebles-db", request_id).unwrap()["state"], "not_found");
        });
        let (mut wire, _) = listener.accept().unwrap();
        wire.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        wire.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
        let register = crate::rpc_read(&mut wire).unwrap();
        assert_eq!(register["type"], "register");
        assert_eq!(register["module"], MODULE);
        assert_eq!(register["endpoints"]["commands"].as_array().unwrap().len(), 4);
        let session = register["session_id"].as_str().unwrap().to_owned();
        crate::rpc_write(&mut wire, &json!({
            "type":"registered", "protocol":1, "module":MODULE, "session_id":session
        })).unwrap();
        let invoke = |endpoint:&str, reqid:&str, payload:Value, context:Value| json!({
            "type":"invoke", "id":reqid, "module":MODULE, "session_id":session,
            "contract":"commands", "endpoint":endpoint, "args":[],
            "payload":payload, "context":context
        });
        let owner = json!({"neebles_authenticated_module":module,
                           "neebles_authenticated_session":"synthetic-consumer-session"});
        // Invalid scope must be rejected locally, before any FD is delegated.
        crate::rpc_write(&mut wire, &invoke("secrets.vault.request.v1", "denied-1",
            json!({"request_id":request_id}),json!({"neebles_authenticated_module":"neebles-secrets",
                                                     "neebles_authenticated_session":"forged"}))).unwrap();
        assert_eq!(crate::rpc_read(&mut wire).unwrap()["code"], 403);
        crate::rpc_write(&mut wire, &invoke("secrets.vault.request.v1", "write-1",
            json!({"request_id":request_id}),owner.clone())).unwrap();
        let pending = crate::rpc_read(&mut wire).unwrap();
        assert_eq!(pending["ok"], true);
        assert_eq!(pending["result"], json!({"state":"pending","replayed":false}));
        crate::rpc_write(&mut wire, &invoke("secrets.vault.request_status.v1", "status-1",
            json!({"request_id":request_id}),owner.clone())).unwrap();
        assert_eq!(crate::rpc_read(&mut wire).unwrap()["result"],json!({"state":"pending"}));
        unlocked_rx.recv_timeout(Duration::from_secs(110)).unwrap();
        crate::rpc_write(&mut wire, &invoke("secrets.vault.request_status.v1", "status-2",
            json!({"request_id":request_id}),owner.clone())).unwrap();
        assert_eq!(crate::rpc_read(&mut wire).unwrap()["result"],json!({"state":"succeeded"}));
        let target = Path::new("/qa-data/neebles-secrets/vaults/vault-neebles-connect.kdbx");
        let before = std::fs::read(target).unwrap();
        assert!(before.len()>128);
        crate::rpc_write(&mut wire, &invoke("secrets.vault.request.v1", "write-replayed",
            json!({"request_id":request_id}),owner.clone())).unwrap();
        assert_eq!(crate::rpc_read(&mut wire).unwrap()["result"],
            json!({"state":"succeeded","replayed":true}));
        assert_eq!(std::fs::read(target).unwrap(),before);
        crate::rpc_write(&mut wire, &invoke("secrets.vault.exists.v1", "exists-1",
            Value::Null,owner.clone())).unwrap();
        let exists = crate::rpc_read(&mut wire).unwrap();
        assert_eq!(exists["result"],json!({"exists":true,"locked":false}));
        // A malicious payload cannot substitute another module's namespace.
        crate::rpc_write(&mut wire, &invoke("secrets.vault.request.v1", "denied-2",
            json!({"request_id":request_id,"module_id":"neebles-db"}),owner)).unwrap();
        assert_eq!(crate::rpc_read(&mut wire).unwrap()["code"],403);
        assert_eq!(std::fs::read(target).unwrap(),before);
        assert!(!Path::new("/qa-data/neebles-secrets/vaults/vault-neebles-db.kdbx").exists());
        crate::rpc_write(&mut wire, &json!({
            "type":"shutdown","module":MODULE,"session_id":session
        })).unwrap();
        assert_eq!(crate::rpc_read(&mut wire).unwrap()["type"],"shutdown_ack");
        worker_thread.join().unwrap();
        assert!(matches!(client.join().unwrap(),Ok(SessionEnd::Shutdown)));
        drop(wire);
        drop(listener);
        std::fs::remove_file(path).unwrap();
    }

    // F26-Y: the real Secrets Rust provider session, not a Python frame emulator,
    // registers with the actual Boss 2.0.8 module_ipc server. The compiled
    // Rust test ELF is installed ONLY in an ephemeral Bubblewrap fixture at
    // the canonical module entrypoint; no daemon or real KDBX is launched.
    #[test]
    #[ignore = "F26-Y: authentic Boss IPC in disposable Bubblewrap only"]
    fn f26y_authentic_boss_accepts_secrets_rust_provider() {
        assert_eq!(std::env::var("NEEBLES_F26Y_SANDBOX").expect("sandbox guard required"), "disposable-only");
        assert_eq!(std::env::var("NEEBLES_MODULES_SOCKET").expect("sandbox socket required"), "/qa/modules.sock");
        assert_eq!(std::env::var("NEEBLES_ROOT").expect("sandbox root required"), "/qa/root");
        assert!(!Path::new("/run/neebles").exists());
        let boss_socket = Path::new("/qa/modules.sock");
        assert!(boss_socket.exists(), "isolated authentic Boss listener missing");
        let alive = Arc::new(AtomicBool::new(true));
        let for_session = Arc::clone(&alive);
        let handle = thread::spawn(move || session_at(boss_socket, &for_session, None));
        // The harness sends duplicate/undeclared/foreign registrations while
        // this genuine provider is connected. No write request is dispatched.
        thread::sleep(Duration::from_secs(9));
        alive.store(false, Ordering::Release);
        let result = handle.join().expect("Secrets provider thread panicked");
        assert!(matches!(result, Ok(SessionEnd::Reconnect)),
            "the genuine Secrets provider did not complete a Boss session");
    }
}
