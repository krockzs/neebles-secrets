//! F26-A: non-sensitive Boss protocol probe. No KDBX, Master Key or local broker access.
//! This handler can be reused by the future persistent provider session.
use serde_json::{json, Value};

pub(super) const ENDPOINT: &str = "secrets.health.v1";
const MODULE: &str = "neebles-secrets";

fn failure(id: &str, session: &str, code: i32, kind: &str) -> Value {
    json!({
        "type":"response", "id":id, "module":MODULE, "session_id":session,
        "contract":"commands", "endpoint":ENDPOINT, "ok":false,
        "code":code, "result":null,
        "error":{"kind":kind,"message":"unsupported or invalid health invocation","details":null}
    })
}

/// Accept only an authenticated in-session Invoke. The caller's identity is
/// enforced by Boss on the inbound connection, never from `context.caller`.
/// Returning no secret, vault state or environment-dependent diagnostics is intentional.
pub(super) fn health_response(msg: &Value, session: &str) -> Result<Value, String> {
    if msg.get("type").and_then(Value::as_str) != Some("invoke")
        || msg.get("module").and_then(Value::as_str) != Some(MODULE)
        || msg.get("session_id").and_then(Value::as_str) != Some(session)
    { return Err("foreign or invalid Boss invocation identity".into()); }
    let id = msg.get("id").and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control))
        .ok_or("invalid Boss invocation ID")?;
    if msg.get("contract").and_then(Value::as_str) != Some("commands")
        || msg.get("endpoint").and_then(Value::as_str) != Some(ENDPOINT)
    { return Ok(failure(id, session, 404, "endpoint_not_found")); }
    let no_args = msg.get("args").and_then(Value::as_array).is_some_and(|a| a.is_empty());
    let no_payload = msg.get("payload").is_none_or(Value::is_null);
    if !no_args || !no_payload {
        return Ok(failure(id, session, 400, "invalid_arguments"));
    }
    Ok(json!({
        "type":"response", "id":id, "module":MODULE, "session_id":session,
        "contract":"commands", "endpoint":ENDPOINT,
        "ok":true, "code":0, "error":null,
        "result":{
            "protocol":1,
            "capability":"secrets.health.v1",
            "available":true,
            "scope":"ui_runtime_only",
            "sensitive_data":false
        }
    }))
}

/// Identical non-sensitive health contract, with explicit persistent-provider scope.
/// This does not expose vault state or authorize arbitrary secret operations.
pub(super) fn persistent_health_response(msg: &Value, session: &str) -> Result<Value, String> {
    let mut response = health_response(msg, session)?;
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        response["result"]["scope"] = json!("persistent_daemon");
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn call() -> Value {json!({"type":"invoke","id":"inv-1","module":MODULE,"session_id":"s-1", "contract":"commands", "endpoint":ENDPOINT,"args":[],"payload":null,"context":{"caller":"FORGED"}})}
    #[test] fn safe_health_no_vault_or_caller_echo() {
        let r=health_response(&call(),"s-1").unwrap();
        assert_eq!(r["ok"],true);
        assert_eq!(r["id"],"inv-1");
        assert_eq!(r["result"]["scope"],"ui_runtime_only");
        let s=r.to_string();
        assert!(!s.contains("FORGED"));
        assert!(!s.contains("master_key"));
        assert!(!s.contains("vault-general"));
    }
    #[test] fn refuses_foreign_sessions_and_modules() {
        assert!(health_response(&call(),"foreign").is_err());
        let mut r=call();r["module"]=json!("neebles-connect");
        assert!(health_response(&r,"s-1").is_err());
    }
    #[test] fn refuses_unknown_endpoints_and_payloads() {
        let mut r=call();r["endpoint"]=json!("vault.read");
        assert_eq!(health_response(&r,"s-1").unwrap()["code"],404);
        let mut r=call();r["payload"]=json!({"key":"secret"});
        assert_eq!(health_response(&r,"s-1").unwrap()["code"],400);
        let mut r=call();r["args"]=json!(["extra"]);
        assert_eq!(health_response(&r,"s-1").unwrap()["code"],400);
    }
    #[test] fn persistent_response_stays_non_sensitive() {
        let good = persistent_health_response(&call(), "s-1").unwrap();
        assert_eq!(good["result"]["scope"], "persistent_daemon");
        assert!(!good.to_string().contains("FORGED"));
        assert!(!good.to_string().contains("master_key"));
        let mut bad = call(); bad["payload"] = json!({"password":"SHOULD_NOT_ECHO"});
        let denied = persistent_health_response(&bad, "s-1").unwrap();
        assert_eq!(denied["code"], 400);
        assert!(!denied.to_string().contains("SHOULD_NOT_ECHO"));
    }
    #[test] fn rejects_missing_or_invalid_ids() {
        let mut r=call();r.as_object_mut().unwrap().remove("id");
        assert!(health_response(&r,"s-1").is_err());
        let mut r=call();r["id"]=json!("bad\n");
        assert!(health_response(&r,"s-1").is_err());
    }
}
