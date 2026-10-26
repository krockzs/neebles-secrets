//! Independent Boss 2.0.4 service publisher.
//!
//! Runs only in the outer systemd-user ExecStart process, outside bwrap.
//! The inner vault daemon never sees /run/neebles or the administrative socket.
//! Only two public booleans cross this boundary; no master password or KDBX bytes.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const MODULE: &str = "neebles-secrets";
const UNIT: &str = "neebles-neebles-secrets-daemon.service";
const BOSS_IPC: &str = "/run/neebles/modules.sock";
const POLL: Duration = Duration::from_millis(750);

fn private_flags(master: bool, unlocked: bool) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "master_key".to_string(),
            if master { "true" } else { "false" }.to_string(),
        ),
        (
            "unblock".to_string(),
            if master && unlocked { "true" } else { "false" }.to_string(),
        ),
    ])
}

// A malformed/absent status MUST revoke prior truth, never retain stale unlock.
fn flags_from_status(reply: &Value) -> BTreeMap<String, String> {
    if reply.get("ok").and_then(Value::as_bool) != Some(true) {
        return private_flags(false, false);
    }
    let Some(data) = reply.get("data") else {
        return private_flags(false, false);
    };
    let vars = data.get("boss_variables");
    let installed = data.get("installed").and_then(Value::as_bool) == Some(true);
    let initialized = data.get("initialized").and_then(Value::as_bool) == Some(true);
    let unlocked = data.get("locked").and_then(Value::as_bool) == Some(false);
    let master = installed
        && initialized
        && vars
            .and_then(|v| v.get("master_key"))
            .and_then(Value::as_str)
            == Some("true");
    let unblocked = master
        && unlocked
        && vars.and_then(|v| v.get("unblock")).and_then(Value::as_str) == Some("true");
    private_flags(master, unblocked)
}

fn current_flags() -> BTreeMap<String, String> {
    let response = super::request(&json!({"op":"vault.status"}));
    match response {
        Ok(value) => flags_from_status(&value),
        Err(_) => private_flags(false, false),
    }
}

fn require_ack(value: &Value, kind: &str, session: &str) -> Result<(), String> {
    if value.get("type").and_then(Value::as_str) == Some("error") {
        let reason = value
            .get("error")
            .and_then(|v| v.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("Boss rejected service request");
        return Err(format!("Boss publisher rejected: {reason}"));
    }
    if value.get("type").and_then(Value::as_str) != Some(kind)
        || value.get("module").and_then(Value::as_str) != Some(MODULE)
        || value.get("session_id").and_then(Value::as_str) != Some(session)
    {
        return Err(format!(
            "unexpected Boss publisher response (expected {kind})"
        ));
    }
    if kind == "registered" && value.get("protocol").and_then(Value::as_u64) != Some(1) {
        return Err("unsupported Boss publisher protocol".to_string());
    }
    Ok(())
}

fn exchange(stream: &mut UnixStream, out: &Value, kind: &str, session: &str) -> Result<(), String> {
    super::rpc_write(stream, out)?;
    let incoming = super::rpc_read(stream)?;
    require_ack(&incoming, kind, session)
}

fn publish_session(alive: &AtomicBool) -> Result<(), String> {
    let mut stream = UnixStream::connect(BOSS_IPC)
        .map_err(|e| format!("Boss module socket unavailable: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| format!("publisher read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| format!("publisher write timeout: {e}"))?;
    let session = super::uuid_v4()?;
    exchange(
        &mut stream,
        &json!({
            "type":"register_service", "protocol":1, "module":MODULE,
            "session_id":session, "unit":UNIT
        }),
        "registered",
        &session,
    )?;

    let mut last: Option<BTreeMap<String, String>> = None;
    while alive.load(Ordering::Acquire) {
        let flags = current_flags();
        if last.as_ref() != Some(&flags) {
            exchange(
                &mut stream,
                &json!({
                    "type":"variables_publish", "module":MODULE,
                    "session_id":session, "variables":flags
                }),
                "variables_published",
                &session,
            )?;
            last = Some(flags);
        }
        // Ping detects Boss restarts even when status has not changed.
        exchange(
            &mut stream,
            &json!({
                "type":"ping", "module":MODULE, "session_id":session
            }),
            "pong",
            &session,
        )?;
        let mut elapsed = Duration::ZERO;
        while elapsed < POLL && alive.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(75));
            elapsed += Duration::from_millis(75);
        }
    }
    let _ = super::rpc_write(
        &mut stream,
        &json!({
            "type":"unregister", "module":MODULE,
            "session_id":session, "reason":"service_exit"
        }),
    );
    Ok(())
}

pub(super) fn run(alive: Arc<AtomicBool>) {
    let mut previous_error: Option<String> = None;
    while alive.load(Ordering::Acquire) {
        match publish_session(&alive) {
            Ok(()) => previous_error = None,
            Err(error) => {
                if previous_error.as_deref() != Some(error.as_str()) {
                    eprintln!("NEEBLES Secrets Boss publication: {error}");
                    previous_error = Some(error);
                }
            }
        }
        // Wait/retry without losing the independent KeePass daemon or Master Key.
        for _ in 0..10 {
            if !alive.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_or_malformed_status_fails_closed() {
        for value in [json!({}), json!({"ok":false}), json!({"ok":true,"data":{}})] {
            let vars = flags_from_status(&value);
            assert_eq!(vars["master_key"], "false");
            assert_eq!(vars["unblock"], "false");
        }
    }
    #[test]
    fn only_initialized_and_unlocked_service_can_publish_true() {
        let state = json!({"ok":true,"data":{
            "installed":true,"initialized":true,"locked":false,
            "boss_variables":{"master_key":"true","unblock":"true"}
        }});
        let vars = flags_from_status(&state);
        assert_eq!(vars["master_key"], "true");
        assert_eq!(vars["unblock"], "true");
        let mut locked = state.clone();
        locked["data"]["locked"] = json!(true);
        assert_eq!(flags_from_status(&locked)["unblock"], "false");
        let mut absent = state.clone();
        absent["data"]["installed"] = json!(false);
        assert_eq!(flags_from_status(&absent)["master_key"], "false");
    }
    #[test]
    fn rejects_foreign_or_unexpected_boss_responses() {
        assert!(require_ack(
            &json!({"type":"registered","protocol":1,"module":MODULE,"session_id":"ok"}),
            "registered",
            "ok"
        )
        .is_ok());
        assert!(require_ack(
            &json!({"type":"registered","protocol":1,"module":"other","session_id":"ok"}),
            "registered",
            "ok"
        )
        .is_err());
        assert!(require_ack(
            &json!({"type":"pong","module":MODULE,"session_id":"old"}),
            "pong",
            "ok"
        )
        .is_err());
    }
}
