//! Secrets 1.0.5: Boss metadata-only capability probe for the universal
//! structured vault engine. This is CONTROL PLANE only. Never carry record
//! payloads, schemas containing values, Master Key or passwords in Boss jobs.
//! Boss' installed per-consumer ipc_invoke_allow remains mandatory.
use serde_json::{json, Value};
use std::os::unix::net::UnixDatagram;

pub(super) const ENDPOINT: &str = "secrets.structure.capabilities.v1";
const PROVIDER: &str = "neebles-secrets";

fn response(id:&str, session:&str, code:u16, result:Value, kind:&str)->Value {
    let success=code==0;
    json!({"type":"response","id":id,"module":PROVIDER,
        "session_id":session,"contract":"commands","endpoint":ENDPOINT,
        "ok":success,"code":code,"result":result,
        "error":if success {Value::Null} else {json!({
            "kind":kind,"message":"Secrets structured vault unavailable","details":null
        })}})
}

/// Probe a worker only AFTER checking the Boss-authenticated context. The
/// connection is inherited FD-passing, not the filesystem-accessible broker.
/// A private data-plane client still authenticates its own ELF with SO_PEERCRED.
/// This probe grants no rights to read or write any record through Boss.
pub(super) fn authorized_capabilities(inv:&Value, session:&str,
    control:Option<&UnixDatagram>)->Result<Value,String> {
    let id=inv.get("id").and_then(Value::as_str)
        .filter(|x|!x.is_empty() && x.len()<=128 && !x.chars().any(char::is_control))
        .ok_or("invalid Boss structure capability request id")?;
    if inv.get("endpoint").and_then(Value::as_str)!=Some(ENDPOINT)
        || inv.get("contract").and_then(Value::as_str)!=Some("commands")
        || !inv.get("args").and_then(Value::as_array).is_some_and(Vec::is_empty)
        || inv.get("payload")!=Some(&Value::Null)
    {return Ok(response(id,session,403,Value::Null,"structure_scope_denied"));}
    let caller=match super::boss_scope::authenticated_consumer(inv,session) {
        Ok(caller)=>caller,
        Err(_)=>return Ok(response(id,session,403,Value::Null,"structure_scope_denied")),
    };
    let Some(control)=control else {
        return Ok(response(id,session,503,Value::Null,"structure_unavailable"));
    };
    // Reuse the verified vault.exists FD bridge. Substitute only the endpoint
    // of an internal local document; the caller identity is NEVER substituted.
    let mut internal=inv.clone();
    internal["endpoint"]=json!(super::boss_vault_bridge::ENDPOINT);
    internal["payload"]=Value::Null;
    let verdict=super::boss_vault_bridge::authorized_exists(&internal,session,control)?;
    if verdict["ok"]!=true {
        return Ok(response(id,session,503,Value::Null,"structure_unavailable"));
    }
    let data=&verdict["result"];
    let Some(exists)=data.get("exists").and_then(Value::as_bool) else {
        return Ok(response(id,session,503,Value::Null,"structure_unavailable"));
    };
    let Some(locked)=data.get("locked").and_then(Value::as_bool) else {
        return Ok(response(id,session,503,Value::Null,"structure_unavailable"));
    };
    // Strict allowlist: even a malicious/misconfigured worker cannot have its
    // secrets, paths, exception strings or arbitrary JSON relayed via Boss.
    Ok(response(id,session,0,json!({
        "api_version":1,"owner":caller,"vault_exists":exists,"locked":locked,
        "ready":exists && !locked,
        "storage":"encrypted_kdbx_v2",
        "control_plane":"boss_authenticated_metadata_only",
        "data_plane":"private_peer_authenticated_fd_worker",
        "require_replica":true,"schema_versions":true,"atomic_batch":true,
        "limits":{"document_bytes":98304,"private_frame_bytes":163840,
                  "page_size_max":100,"batch_operations_max":32}
    }),""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    fn call()->Value {
        json!({"type":"invoke","id":"structure-1","module":PROVIDER,
            "session_id":"provider-1","contract":"commands","endpoint":ENDPOINT,
            "args":[],"payload":null,"context":{
                "caller":"FORGED","neebles_authenticated_module":"neebles-connect",
                "neebles_authenticated_session":"consumer-1"}})
    }
    #[test]
    fn no_worker_no_capabilities_not_even_stale() {
        let msg=authorized_capabilities(&call(),"provider-1",None).unwrap();
        assert_eq!(msg["code"],503);
        assert!(msg["result"].is_null());
    }
    #[test]
    fn denies_forged_secret_payload_missing_origin_and_cross_vault_before_fd() {
        let (broker,worker)=UnixDatagram::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        for payload in [json!({"password":"EXFILTRATE"}),
                        json!({"module_id":"neebles-other"}),json!([])] {
            let mut forged=call();forged["payload"]=payload;
            let result=authorized_capabilities(&forged,"provider-1",Some(&broker)).unwrap();
            assert_eq!(result["code"],403);
            assert!(!result.to_string().contains("EXFILTRATE"));
        }
        let mut no_origin=call();
        no_origin["context"].as_object_mut().unwrap().remove("neebles_authenticated_session");
        assert_eq!(authorized_capabilities(&no_origin,"provider-1",Some(&broker)).unwrap()["code"],403);
        let mut wrong_provider=call(); wrong_provider["session_id"]=json!("other");
        assert_eq!(authorized_capabilities(&wrong_provider,"provider-1",Some(&broker)).unwrap()["code"],403);
        assert!(crate::ipc_bridge::recv_connection(&worker).is_err());
    }
    #[test]
    fn authentic_owner_worker_fd_and_allowlisted_boss_reply() {
        let (broker,worker)=UnixDatagram::pair().unwrap();
        let task=thread::spawn(move || {
            let (mut wire,owner)=crate::ipc_bridge::recv_connection(&worker).unwrap();
            assert_eq!(owner.as_deref(),Some("neebles-connect"));
            let input=crate::rpc_read(&mut wire).unwrap();
            assert_eq!(input,json!({"op":"vault.exists","module":"neebles-connect"}));
            crate::rpc_write(&mut wire,&json!({"ok":true,"data":{
                "module":"neebles-connect","exists":true,"locked":false,
                "password":"SECRET_NOT_IN_BOSS","private_path":"/private/hidden"
            }})).unwrap();
        });
        let result=authorized_capabilities(&call(),"provider-1",Some(&broker)).unwrap();
        task.join().unwrap();
        assert_eq!(result["code"],0);
        assert_eq!(result["result"]["owner"],"neebles-connect");
        assert_eq!(result["result"]["ready"],true);
        assert_eq!(result["result"]["limits"]["document_bytes"],98304);
        assert!(!result.to_string().contains("SECRET_NOT_IN_BOSS"));
        assert!(!result.to_string().contains("/private/hidden"));
        assert!(!result.to_string().contains("FORGED"));
    }
    #[test]
    fn locked_worker_remains_safe_and_never_claims_ready() {
        let (broker,worker)=UnixDatagram::pair().unwrap();
        let task=thread::spawn(move||{
            let (mut wire,owner)=crate::ipc_bridge::recv_connection(&worker).unwrap();
            assert_eq!(owner.as_deref(),Some("neebles-connect"));
            let _=crate::rpc_read(&mut wire).unwrap();
            crate::rpc_write(&mut wire,&json!({"ok":true,"data":{
                "module":"neebles-connect","exists":true,"locked":true
            }})).unwrap();
        });
        let result=authorized_capabilities(&call(),"provider-1",Some(&broker)).unwrap();
        task.join().unwrap();
        assert_eq!(result["result"]["ready"],false);
        assert_eq!(result["result"]["locked"],true);
    }
}
