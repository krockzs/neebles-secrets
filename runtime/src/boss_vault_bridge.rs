//! F26-J: Boss-validated identity -> anonymous SCM_RIGHTS -> KDBX worker.
//!
//! The exterior daemon does not possess the Master Key or open the KDBX.
//! A Boss invocation passes a scope guard before an FD can be transferred.
//! Read-only vault.exists, request_status and idempotent request are contract
//! endpoints. Boss installed grants remain independently mandatory; no worker
//! secrets are held in this daemon. Never retry a forwarded mutation.
use serde_json::{json, Value};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::time::Duration;

pub(super) const ENDPOINT: &str = "secrets.vault.exists.v1";
pub(super) const STATUS_ENDPOINT: &str = "secrets.vault.request_status.v1";
pub(super) const REQUEST_ENDPOINT: &str = "secrets.vault.request.v1";
const PROVIDER: &str = "neebles-secrets";

fn reply(id: &str, session: &str, ok: bool, code: u16, result: Value, error: &str) -> Value {
    let error_data = if ok { Value::Null } else {
        json!({"kind":error,"message":"Secrets vault status unavailable","details":null})
    };
    json!({"type":"response", "id":id,"module":PROVIDER,"session_id":session,
        "contract":"commands","endpoint":ENDPOINT,"ok":ok,"code":code,
        "result":result,"error":error_data})
}

// Never accept a caller name here: it comes only from the reserved Boss context
// after the provider session and strict envelope have been verified.
pub(super) fn authorized_exists(invocation: &Value, provider_session: &str,
    control: &UnixDatagram) -> Result<Value, String>
{
    if invocation.get("endpoint").and_then(Value::as_str) != Some(ENDPOINT) {
        return Err("not a vault.exists endpoint".into());
    }
    let guarded = super::boss_scope::staged_vault_reply(invocation, provider_session)?;
    if guarded.get("code").and_then(Value::as_u64) != Some(503) {
        return Ok(guarded); // invalid scope/envelope: 403 without touching the FD channel
    }
    let id = invocation.get("id").and_then(Value::as_str).ok_or("missing Boss id")?;
    let caller = super::boss_scope::authenticated_consumer(invocation, provider_session)
        .map_err(|_| "invalid Boss consumer identity")?;

    // Only the outer daemon can send this identity over the inherited private
    // SOCK_DGRAM pair. The isolated worker still checks `peer == module`.
    // No call to the filesystem-visible secrets.sock, and no JSON peer override.
    let outcome = (|| -> Result<Value, String> {
        let (mut client, worker_end) = UnixStream::pair()
            .map_err(|_| "isolated vault channel unavailable")?;
        client.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "isolated vault timeout unavailable")?;
        client.set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "isolated vault timeout unavailable")?;
        super::ipc_bridge::send_connection(control, &worker_end, Some(caller))
            .map_err(|_| "isolated vault handoff unavailable")?;
        drop(worker_end);
        super::rpc_write(&mut client, &json!({"op":"vault.exists","module":caller}))
            .map_err(|_| "isolated vault request unavailable")?;
        let worker = super::rpc_read(&mut client)
            .map_err(|_| "isolated vault response unavailable")?;
        if worker.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err("vault status not available".into());
        }
        let data = worker.get("data").ok_or("invalid vault response")?;
        if data.get("module").and_then(Value::as_str) != Some(caller) {
            return Err("unexpected vault identity in worker reply".into());
        }
        let exists = data.get("exists").and_then(Value::as_bool)
            .ok_or("invalid vault existence response")?;
        let locked = data.get("locked").and_then(Value::as_bool)
            .ok_or("invalid vault lock response")?;
        // Deliberately never relay arbitrary KDBX worker fields or errors.
        Ok(json!({"exists":exists,"locked":locked}))
    })();
    Ok(match outcome {
        Ok(data) => reply(id, provider_session, true, 0, data, ""),
        Err(_) => reply(id, provider_session, false, 503, Value::Null, "vault_unavailable"),
    })
}


// F26-O: non-mutating reconciliation of a durable request. A caller never
// supplies a module identity; Boss' reserved context binds it to an owner.
// The id grammar is shared with the worker's durable Journal implementation.
fn durable_envelope<'a>(invocation: &'a Value, provider_session: &str, endpoint: &str)
    -> Result<(&'a str, &'a str, &'a str), String>
{
    let id = invocation.get("id").and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 128 && !v.chars().any(char::is_control))
        .ok_or("invalid Boss request id")?;
    if invocation.get("endpoint").and_then(Value::as_str) != Some(endpoint) {
        return Err("wrong durable vault endpoint".into());
    }
    let caller = super::boss_scope::authenticated_consumer(invocation, provider_session)
        .map_err(|_| "invalid Boss authenticated consumer")?;
    if invocation.get("contract").and_then(Value::as_str) != Some("commands")
        || !invocation.get("args").and_then(Value::as_array).is_some_and(Vec::is_empty)
    {
        return Err("invalid request status envelope".into());
    }
    let payload = invocation.get("payload").and_then(Value::as_object)
        .filter(|p| p.len() == 1)
        .ok_or("invalid request status payload")?;
    let request_id = payload.get("request_id").and_then(Value::as_str)
        .filter(|v| super::vault_request_journal::valid_request_id(v))
        .ok_or("invalid durable request id")?;
    Ok((id, caller, request_id))
}

fn status_response(id: &str, session: &str, ok: bool, code: u16,
    result: Value, kind: &str) -> Value
{
    json!({"type":"response","id":id,"module":PROVIDER,
        "session_id":session,"contract":"commands","endpoint":STATUS_ENDPOINT,
        "ok":ok,"code":code,"result":result,
        "error":if ok {Value::Null} else {json!({
            "kind":kind,"message":"Secrets request status unavailable","details":null
        })}
    })
}

/// Guarded read-only status. Does not use the status result as permission to
/// retry a mutating request: reconciliation, not dispatch, is the sole purpose.
pub(super) fn authorized_request_status(invocation: &Value, provider_session: &str,
    control: Option<&UnixDatagram>) -> Result<Value, String>
{
    // A malformed Boss response identity/id is a session protocol error; an
    // invalid caller/payload is a sanitised refusal without worker handoff.
    let id = invocation.get("id").and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 128 && !v.chars().any(char::is_control))
        .ok_or("invalid Boss request id")?;
    let (_, caller, request_id) = match durable_envelope(invocation, provider_session, STATUS_ENDPOINT) {
        Ok(values) => values,
        Err(_) => return Ok(status_response(id,provider_session,false,403,Value::Null,"vault_scope_denied")),
    };
    let Some(control) = control else {
        return Ok(status_response(id,provider_session,false,503,Value::Null,"vault_unavailable"));
    };
    let outcome = (|| -> Result<Value, String> {
        let (mut client, worker_end) = UnixStream::pair()
            .map_err(|_| "isolated vault channel unavailable")?;
        client.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "isolated vault timeout unavailable")?;
        client.set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "isolated vault timeout unavailable")?;
        super::ipc_bridge::send_connection(control, &worker_end, Some(caller))
            .map_err(|_| "isolated vault handoff unavailable")?;
        drop(worker_end);
        super::rpc_write(&mut client, &json!({
            "op":"vault.request_status", "module":caller, "request_id":request_id
        })).map_err(|_| "isolated vault status query unavailable")?;
        let worker = super::rpc_read(&mut client)
            .map_err(|_| "isolated vault status reply unavailable")?;
        if worker.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err("worker rejected request status".into());
        }
        let data = worker.get("data").ok_or("worker status absent")?;
        if data.get("module").and_then(Value::as_str) != Some(caller)
            || data.get("request_id").and_then(Value::as_str) != Some(request_id)
        { return Err("worker status identity mismatch".into()); }
        let state = data.get("state").and_then(Value::as_str)
            .filter(|value| matches!(*value,"pending"|"succeeded"|"not_found"))
            .ok_or("invalid worker status state")?;
        // Never relay arbitrary worker data, paths or internal error messages.
        Ok(json!({"state":state}))
    })();
    Ok(match outcome {
        Ok(data) => status_response(id,provider_session,true,0,data,""),
        Err(_) => status_response(id,provider_session,false,503,Value::Null,"vault_unavailable"),
    })
}

// F26-P: a durable, idempotent *intention* to provision the caller's own vault.
// The worker records request_id before any KeePass operation. The outer daemon
// transfers one FD at most; once handed off, a timeout is ambiguous and MUST
// be reconciled via request_status, never replayed automatically.
fn request_response(id: &str, session: &str, ok: bool, code: u16,
    result: Value, kind: &str) -> Value
{
    json!({"type":"response","id":id,"module":PROVIDER,
        "session_id":session,"contract":"commands","endpoint":REQUEST_ENDPOINT,
        "ok":ok,"code":code,"result":result,
        "error":if ok {Value::Null} else {json!({
            "kind":kind,"message":"Secrets vault request unavailable",
            "details":null
        })}
    })
}

pub(super) fn authorized_request(invocation: &Value, provider_session: &str,
    control: Option<&UnixDatagram>) -> Result<Value, String>
{
    let id = invocation.get("id").and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 128 && !v.chars().any(char::is_control))
        .ok_or("invalid Boss request id")?;
    let (_, caller, request_id) = match durable_envelope(invocation, provider_session, REQUEST_ENDPOINT) {
        Ok(values) => values,
        Err(_) => return Ok(request_response(id,provider_session,false,403,Value::Null,"vault_scope_denied")),
    };
    let Some(control) = control else {
        return Ok(request_response(id,provider_session,false,503,Value::Null,"vault_unavailable"));
    };
    // No loop, retry, or fallback after send_connection. The worker is the
    // sole owner of the journal, mutation and recovery after a partial write.
    let outcome = (|| -> Result<Value, String> {
        let (mut client, worker_end) = UnixStream::pair()
            .map_err(|_| "isolated vault channel unavailable")?;
        client.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "isolated vault timeout unavailable")?;
        client.set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "isolated vault timeout unavailable")?;
        super::ipc_bridge::send_connection(control, &worker_end, Some(caller))
            .map_err(|_| "isolated vault handoff unavailable")?;
        drop(worker_end);
        super::rpc_write(&mut client, &json!({
            "op":"vault.request_id", "module":caller, "request_id":request_id
        })).map_err(|_| "isolated vault request unavailable")?;
        let worker = super::rpc_read(&mut client)
            .map_err(|_| "isolated vault response unavailable")?;
        if worker.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err("worker rejected vault request".into());
        }
        let data = worker.get("data").ok_or("worker request data absent")?;
        if data.get("module").and_then(Value::as_str) != Some(caller)
            || data.get("request_id").and_then(Value::as_str) != Some(request_id)
        { return Err("worker request identity mismatch".into()); }
        let pending = data.get("pending").and_then(Value::as_bool)
            .ok_or("worker request missing pending")?;
        let exists = data.get("exists").and_then(Value::as_bool)
            .ok_or("worker request missing exists")?;
        let replayed = data.get("replayed").and_then(Value::as_bool)
            .ok_or("worker request missing replayed")?;
        if !pending && !exists { return Err("worker request contradictory result".into()); }
        // Never relay worker paths, KDBX contents, or internal errors.
        Ok(json!({"state":if pending {"pending"} else {"succeeded"},"replayed":replayed}))
    })();
    Ok(match outcome {
        Ok(data) => request_response(id,provider_session,true,0,data,""),
        Err(_) => request_response(id,provider_session,false,503,Value::Null,"vault_unavailable"),
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn call() -> Value {
        json!({"type":"invoke","id":"exists-1","module":PROVIDER,
            "session_id":"provider-1","contract":"commands",
            "endpoint":ENDPOINT,"args":[],"payload":null,
            "context":{"caller":"FORGED","module_id":"general",
                "neebles_authenticated_module":"neebles-connect",
                "neebles_authenticated_session":"consumer-1"}})
    }
    #[test]
    fn authenticated_fd_handoff_returns_only_boolean_status() {
        let (broker, worker) = UnixDatagram::pair().unwrap();
        let child = thread::spawn(move || {
            let (mut stream, peer) = super::super::ipc_bridge::recv_connection(&worker).unwrap();
            assert_eq!(peer.as_deref(), Some("neebles-connect"));
            let message=crate::rpc_read(&mut stream).unwrap();
            assert_eq!(message, json!({"op":"vault.exists","module":"neebles-connect"}));
            crate::rpc_write(&mut stream, &json!({"ok":true,
                "data":{"module":"neebles-connect","exists":true,"locked":false,
                    "private_marker":"DO_NOT_FORWARD"}})).unwrap();
        });
        let status=authorized_exists(&call(), "provider-1", &broker).unwrap();
        child.join().unwrap();
        assert_eq!(status["ok"],true);
        assert_eq!(status["result"],json!({"exists":true,"locked":false}));
        assert!(!status.to_string().contains("DO_NOT_FORWARD"));
        assert!(!status.to_string().contains("FORGED"));
    }
    #[test]
    fn forged_cross_vault_and_malformed_requests_do_not_forward_fds() {
        let (broker, worker) = UnixDatagram::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        let mut forged=call();
        forged["payload"]=json!({"module_id":"neebles-other"});
        let denied=authorized_exists(&forged,"provider-1",&broker).unwrap();
        assert_eq!(denied["code"],403);
        forged=call();
        forged["args"]=json!(["invalid"]);
        assert_eq!(authorized_exists(&forged,"provider-1",&broker).unwrap()["code"],403);
        assert!(super::super::ipc_bridge::recv_connection(&worker).is_err());
    }
    #[test]
    fn worker_identity_mismatch_fails_closed() {
        let (broker, worker) = UnixDatagram::pair().unwrap();
        let child=thread::spawn(move || {
            let (mut stream, _) = super::super::ipc_bridge::recv_connection(&worker).unwrap();
            let _=crate::rpc_read(&mut stream).unwrap();
            crate::rpc_write(&mut stream,&json!({"ok":true,
                "data":{"module":"neebles-other","exists":true,"locked":false,
                    "password":"NEVER_ECHO"}})).unwrap();
        });
        let status=authorized_exists(&call(),"provider-1",&broker).unwrap();
        child.join().unwrap();
        assert_eq!(status["code"],503);
        assert_eq!(status["result"],Value::Null);
        assert!(!status.to_string().contains("NEVER_ECHO"));
    }
    #[test]
    fn no_worker_response_returns_sanitized_unavailability() {
        let (broker, worker) = UnixDatagram::pair().unwrap();
        let child=thread::spawn(move || {
            let (mut stream, _) = super::super::ipc_bridge::recv_connection(&worker).unwrap();
            let _=crate::rpc_read(&mut stream).unwrap();
            drop(stream);
        });
        let status=authorized_exists(&call(),"provider-1",&broker).unwrap();
        child.join().unwrap();
        assert_eq!(status["code"],503);
        assert_eq!(status["error"]["kind"],"vault_unavailable");
    }
    fn status_call() -> Value {
        json!({"type":"invoke","id":"status-call-1","module":PROVIDER,
            "session_id":"provider-1","contract":"commands",
            "endpoint":STATUS_ENDPOINT,"args":[],
            "payload":{"request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504"},
            "context":{"caller":"FORGED","neebles_authenticated_module":"neebles-connect",
                "neebles_authenticated_session":"consumer-1"}})
    }
    #[test]
    fn status_broker_fd_is_read_only_and_does_not_leak_worker_metadata() {
        let (broker,worker)=UnixDatagram::pair().unwrap();
        let child=thread::spawn(move || {
            let (mut wire,peer)=crate::ipc_bridge::recv_connection(&worker).unwrap();
            assert_eq!(peer.as_deref(),Some("neebles-connect"));
            let input=crate::rpc_read(&mut wire).unwrap();
            assert_eq!(input,json!({"op":"vault.request_status",
                "module":"neebles-connect",
                "request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504"}));
            crate::rpc_write(&mut wire,&json!({"ok":true,"data":{
                "module":"neebles-connect","request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504",
                "state":"pending","password":"DO_NOT_RELAY"}})).unwrap();
        });
        let response=authorized_request_status(&status_call(),"provider-1",Some(&broker)).unwrap();
        child.join().unwrap();
        assert_eq!(response["ok"],true);
        assert_eq!(response["result"],json!({"state":"pending"}));
        assert!(!response.to_string().contains("DO_NOT_RELAY"));
        assert!(!response.to_string().contains("FORGED"));
    }
    #[test]
    fn status_denies_forged_and_malformed_requests_before_fd_handoff() {
        let (broker,worker)=UnixDatagram::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        for payload in [
            json!({"request_id":"short"}),
            json!({"request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504","module_id":"neebles-other"}),
            json!({"request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504","password":"SECRET"}),
            json!(null),
        ] {
            let mut call=status_call();call["payload"]=payload;
            let answer=authorized_request_status(&call,"provider-1",Some(&broker)).unwrap();
            assert_eq!(answer["code"],403);
            assert_eq!(answer["result"],Value::Null);
            assert!(!answer.to_string().contains("SECRET"));
        }
        let mut call=status_call();
        call["context"]["neebles_authenticated_module"]=json!("neebles-other");
        call["payload"]["module_id"]=json!("neebles-connect");
        assert_eq!(authorized_request_status(&call,"provider-1",Some(&broker)).unwrap()["code"],403);
        let mut call=status_call();
        call["context"].as_object_mut().unwrap().remove("neebles_authenticated_module");
        assert_eq!(authorized_request_status(&call,"provider-1",Some(&broker)).unwrap()["code"],403);
        assert!(crate::ipc_bridge::recv_connection(&worker).is_err());
    }
    #[test]
    fn status_worker_identity_and_unknown_state_fail_closed() {
        for (data,expect_success) in [
            (json!({"module":"neebles-other","request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504","state":"succeeded"}), false),
            (json!({"module":"neebles-connect","request_id":"forged","state":"succeeded"}),false),
            (json!({"module":"neebles-connect","request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504","state":"unknown"}),false),
            (json!({"module":"neebles-connect","request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504","state":"not_found"}),true),
        ] {
            let (broker,worker)=UnixDatagram::pair().unwrap();
            let child=thread::spawn(move || {
                let (mut wire,_)=crate::ipc_bridge::recv_connection(&worker).unwrap();
                let _=crate::rpc_read(&mut wire).unwrap();
                crate::rpc_write(&mut wire,&json!({"ok":true,"data":data})).unwrap();
            });
            let answer=authorized_request_status(&status_call(),"provider-1",Some(&broker)).unwrap();
            child.join().unwrap();
            assert_eq!(answer["ok"],expect_success);
            if !expect_success { assert_eq!(answer["code"],503); assert!(answer["result"].is_null()); }
            else {assert_eq!(answer["result"],json!({"state":"not_found"}));}
        }
        let answer=authorized_request_status(&status_call(),"provider-1",None).unwrap();
        assert_eq!(answer["code"],503);
    }


    fn request_call() -> Value {
        let mut call=status_call();
        call["endpoint"]=json!(REQUEST_ENDPOINT);
        call["id"]=json!("request-call-1");
        call
    }
    #[test]
    fn durable_request_is_scoped_and_sanitized() {
        let (broker,worker)=UnixDatagram::pair().unwrap();
        let child=thread::spawn(move || {
            let (mut wire,peer)=crate::ipc_bridge::recv_connection(&worker).unwrap();
            assert_eq!(peer.as_deref(),Some("neebles-connect"));
            assert_eq!(crate::rpc_read(&mut wire).unwrap(),json!({
                "op":"vault.request_id", "module":"neebles-connect",
                "request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504"
            }));
            crate::rpc_write(&mut wire,&json!({"ok":true,"data":{
                "module":"neebles-connect", "request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504",
                "pending":true,"exists":false,"replayed":false,
                "private_marker":"NO_SECRET_EXPOSURE"}})).unwrap();
        });
        let answer=authorized_request(&request_call(),"provider-1",Some(&broker)).unwrap();
        child.join().unwrap();
        assert_eq!(answer["ok"],true);
        assert_eq!(answer["endpoint"],REQUEST_ENDPOINT);
        assert_eq!(answer["result"],json!({"state":"pending","replayed":false}));
        assert!(!answer.to_string().contains("NO_SECRET_EXPOSURE"));
        assert!(!answer.to_string().contains("FORGED"));
    }
    #[test]
    fn durable_request_rejects_bad_scope_before_any_handoff() {
        let (broker,worker)=UnixDatagram::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        for payload in [json!(null), json!({"request_id":"bad"}),
            json!({"request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504","module_id":"neebles-other"}),
            json!({"request_id":"9a3e5c7d-22a0-4f12-9c34-831aa23ad504","password":"LEAK"})]
        {
            let mut call=request_call();call["payload"]=payload;
            let response=authorized_request(&call,"provider-1",Some(&broker)).unwrap();
            assert_eq!(response["code"],403);
            assert!(response["result"].is_null());
            assert!(!response.to_string().contains("LEAK"));
        }
        let mut call=request_call();
        call["context"].as_object_mut().unwrap().remove("neebles_authenticated_module");
        assert_eq!(authorized_request(&call,"provider-1",Some(&broker)).unwrap()["code"],403);
        assert!(crate::ipc_bridge::recv_connection(&worker).is_err());
    }
    #[test]
    fn durable_request_ambiguous_worker_response_never_redispatches() {
        let (broker,worker)=UnixDatagram::pair().unwrap();
        let child=thread::spawn(move || {
            let (mut wire,_)=crate::ipc_bridge::recv_connection(&worker).unwrap();
            let request=crate::rpc_read(&mut wire).unwrap();
            assert_eq!(request["op"],"vault.request_id");
            drop(wire); // after dispatch: unknown journal/creation outcome
            worker.set_nonblocking(true).unwrap();
            assert!(crate::ipc_bridge::recv_connection(&worker).is_err());
        });
        let result=authorized_request(&request_call(),"provider-1",Some(&broker)).unwrap();
        child.join().unwrap();
        assert_eq!(result["code"],503);
        assert_eq!(result["result"],Value::Null);
        assert_eq!(result["error"]["kind"],"vault_unavailable");
        assert_eq!(authorized_request(&request_call(),"provider-1",None).unwrap()["code"],503);
    }
    #[test]
    fn durable_request_worker_result_must_match_and_be_consistent() {
        let base="9a3e5c7d-22a0-4f12-9c34-831aa23ad504";
        for data in [
            json!({"module":"neebles-other","request_id":base,"pending":false,"exists":true,"replayed":false}),
            json!({"module":"neebles-connect","request_id":"forged","pending":false,"exists":true,"replayed":false}),
            json!({"module":"neebles-connect","request_id":base,"pending":false,"exists":false,"replayed":false}),
            json!({"module":"neebles-connect","request_id":base,"pending":"no","exists":true,"replayed":false}),
        ] {
            let (broker,worker)=UnixDatagram::pair().unwrap();
            let child=thread::spawn(move || {
                let (mut wire,_)=crate::ipc_bridge::recv_connection(&worker).unwrap();
                let _=crate::rpc_read(&mut wire).unwrap();
                crate::rpc_write(&mut wire,&json!({"ok":true,"data":data})).unwrap();
            });
            let answer=authorized_request(&request_call(),"provider-1",Some(&broker)).unwrap();
            child.join().unwrap();
            assert_eq!(answer["code"],503);
            assert_eq!(answer["result"],Value::Null);
        }
    }
}
