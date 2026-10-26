//! F26-H: provider-side consumer scope for future governed vault endpoints.
//!
//! Boss 2.0.8 replaces the reserved context keys using the consumer's
//! authenticated runtime session. This module MUST be invoked only on the
//! provider's verified Boss socket; a standalone JSON document is not proof
//! of authentication. No KDBX operations, secret payloads or grants here.
use serde_json::{json, Value};
const PROVIDER: &str = "neebles-secrets";
const RESERVED: [&str; 2] = ["secrets.vault.exists.v1", "secrets.vault.request.v1"];

fn valid_module_id(input: &str) -> bool {
    // The IPC broker and VaultController both require this narrower KDBX
    // namespace, NOT just Boss' generic module ID lexical validation.
    // A caller unsupported by KDBX must be rejected before delegation.
    let bytes = input.as_bytes();
    (2..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && !input.ends_with('-')
        && !input.contains("--")
        && input != "general"
}

/// The caller is obtained only from Boss-injected reserved context keys.
/// The `module`, `caller`, and `requested_module` supplied by consumers never
/// establish ownership. Caller session presence is required but its proof
/// comes from Boss, which bound it to a registered Unix-socket connection.
pub(super) fn authenticated_consumer<'a>(
    invocation: &'a Value,
    provider_session: &str,
) -> Result<&'a str, &'static str> {
    if invocation.get("type").and_then(Value::as_str) != Some("invoke")
        || invocation.get("module").and_then(Value::as_str) != Some(PROVIDER)
        || invocation.get("session_id").and_then(Value::as_str) != Some(provider_session)
    {
        return Err("invalid_provider_session");
    }
    let context = invocation
        .get("context")
        .and_then(Value::as_object)
        .ok_or("missing_boss_origin")?;
    let module = context
        .get("neebles_authenticated_module")
        .and_then(Value::as_str)
        .ok_or("missing_boss_origin")?;
    let consumer_session = context
        .get("neebles_authenticated_session")
        .and_then(Value::as_str)
        .ok_or("missing_boss_origin")?;
    if !valid_module_id(module)
        || module == PROVIDER
        || consumer_session.is_empty()
        || consumer_session.len() > 128
        || consumer_session.chars().any(char::is_control)
    {
        return Err("invalid_boss_origin");
    }
    Ok(module)
}

/// Enforces per-module namespacing before any future broker delegation.
/// Personal vault-general is not a consumer namespace.
pub(super) fn authorize_vault_target<'a>(
    invocation: &'a Value,
    provider_session: &str,
    requested_module: Option<&str>,
) -> Result<&'a str, &'static str> {
    let caller = authenticated_consumer(invocation, provider_session)?;
    if let Some(target) = requested_module {
        if target != caller {
            return Err("vault_module_identity_mismatch");
        }
    }
    Ok(caller)
}

/// Intentionally not part of commands.json or runtime advertisement.
/// Boss will reject these endpoints at the contract resolver. The additional
/// response guard ensures an accidentally delivered request can never reach
/// the KDBX broker until a separate certified implementation exists.
pub(super) fn staged_vault_reply(
    invocation: &Value,
    provider_session: &str,
) -> Result<Value, String> {
    let id = invocation
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
        .ok_or("invalid invocation id")?;
    let endpoint = invocation
        .get("endpoint")
        .and_then(Value::as_str)
        .filter(|value| RESERVED.contains(value))
        .ok_or("endpoint not reserved")?;
    // A malformed envelope must never fall through to self-scoped access.
    // This is a staging guard; the final contract will validate endpoint-
    // specific inputs again before any KeePass worker operation.
    let args_valid = invocation.get("contract").and_then(Value::as_str) == Some("commands")
        && invocation
            .get("args")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
    let payload = invocation.get("payload").unwrap_or(&Value::Null);
    let payload_valid = invocation.get("payload").is_some()
        && (payload.is_null()
            || payload.as_object().is_some_and(|fields| {
                fields.len() == 1 && fields.get("module_id").and_then(Value::as_str).is_some()
            }));
    let requested = payload.get("module_id").and_then(Value::as_str);
    let authorization = if args_valid && payload_valid {
        authorize_vault_target(invocation, provider_session, requested)
    } else {
        Err("invalid_vault_request_envelope")
    };
    let (code, kind) = if authorization.is_ok() {
        (503, "vault_endpoint_not_active")
    } else {
        (403, "vault_scope_denied")
    };
    Ok(json!({
        "type":"response", "id":id, "module":PROVIDER,
        "session_id":provider_session, "contract":"commands",
        "endpoint":endpoint, "ok":false, "code":code,
        "result":null,
        "error":{"kind":kind,"message":"vault endpoint not available","details":null}
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Value {
        json!({"type":"invoke","id":"job-1","module":PROVIDER,"session_id":"provider-session",
            "contract":"commands","endpoint":"secrets.vault.request.v1","args":[],"payload":null,
            "context":{"caller":"FORGED_PERSONAL","module_id":"neebles-db",
                "neebles_authenticated_module":"neebles-connect",
                "neebles_authenticated_session":"caller-session"}})
    }
    #[test]
    fn derives_origin_from_boss_reserved_context_not_client_fields() {
        assert_eq!(
            authenticated_consumer(&input(), "provider-session"),
            Ok("neebles-connect")
        );
        assert_eq!(
            authorize_vault_target(&input(), "provider-session", None),
            Ok("neebles-connect")
        );
        assert_eq!(
            authorize_vault_target(&input(), "provider-session", Some("neebles-connect")),
            Ok("neebles-connect")
        );
    }
    #[test]
    fn rejects_cross_vault_and_personal_namespace() {
        assert_eq!(
            authorize_vault_target(&input(), "provider-session", Some("neebles-db")),
            Err("vault_module_identity_mismatch")
        );
        assert_eq!(
            authorize_vault_target(&input(), "provider-session", Some("vault-general")),
            Err("vault_module_identity_mismatch")
        );
        let mut forged = input();
        forged["context"]["neebles_authenticated_module"] = json!("neebles-secrets");
        assert_eq!(
            authenticated_consumer(&forged, "provider-session"),
            Err("invalid_boss_origin")
        );
    }
    #[test]
    fn requires_complete_authenticated_origin_and_provider_session() {
        let mut input = input();
        assert_eq!(
            authenticated_consumer(&input, "foreign"),
            Err("invalid_provider_session")
        );
        input["context"]
            .as_object_mut()
            .unwrap()
            .remove("neebles_authenticated_module");
        assert_eq!(
            authenticated_consumer(&input, "provider-session"),
            Err("missing_boss_origin")
        );
        input["context"]["neebles_authenticated_module"] = json!("../etc/passwd");
        assert_eq!(
            authenticated_consumer(&input, "provider-session"),
            Err("invalid_boss_origin")
        );
        input["context"]["neebles_authenticated_module"] = json!("neebles-connect");
        input["context"]["neebles_authenticated_session"] = json!("");
        assert_eq!(
            authenticated_consumer(&input, "provider-session"),
            Err("invalid_boss_origin")
        );
    }
    #[test]
    fn staged_vault_reply_fails_closed_without_secret_leakage() {
        let mut input = input();
        let inactive = staged_vault_reply(&input, "provider-session").unwrap();
        assert_eq!(inactive["code"], 503);
        assert_eq!(inactive["result"], Value::Null);
        assert!(!inactive.to_string().contains("FORGED_PERSONAL"));
        input["payload"] = json!({"module_id":"neebles-db", "password":"CONFIDENTIAL"});
        let rejected = staged_vault_reply(&input, "provider-session").unwrap();
        assert_eq!(rejected["code"], 403);
        assert!(!rejected.to_string().contains("CONFIDENTIAL"));
        input["context"]
            .as_object_mut()
            .unwrap()
            .remove("neebles_authenticated_session");
        assert_eq!(
            staged_vault_reply(&input, "provider-session").unwrap()["code"],
            403
        );
    }
    #[test]
    fn rejects_boss_valid_but_vault_invalid_ids_before_delegation() {
        let mut call = input();
        for invalid in ["db_01", "module.sub", "General", "general", "m--x", "m-"] {
            call["context"]["neebles_authenticated_module"] = json!(invalid);
            let result = staged_vault_reply(&call, "provider-session").unwrap();
            assert_eq!(result["code"], 403, "invalid vault module: {invalid}");
            assert_eq!(result["result"], Value::Null);
        }
    }
    #[test]
    fn malformed_reserved_envelopes_fail_closed() {
        let base = input();
        for (key, replacement) in [
            ("args", json!(["anything"])),
            ("args", json!({"anything": 1})),
            ("payload", json!(["anything"])),
            ("payload", json!({"module_id": 123})),
            (
                "payload",
                json!({"module_id": "neebles-connect", "password": "SENSITIVE"}),
            ),
            ("payload", json!({"unexpected": 1})),
            ("contract", json!("not-commands")),
        ] {
            let mut call = base.clone();
            call[key] = replacement;
            let result = staged_vault_reply(&call, "provider-session").unwrap();
            assert_eq!(result["code"], 403, "malformed: {key}");
            assert_eq!(result["result"], Value::Null);
            assert!(!result.to_string().contains("SENSITIVE"));
        }
        // A valid self-scoped envelope remains NOT ACTIVE (503).
        let reply = staged_vault_reply(&base, "provider-session").unwrap();
        assert_eq!(reply["code"], 503);
    }
    #[test]
    fn explicit_target_is_never_accepted_from_wrong_caller() {
        let mut call = input();
        call["payload"] = json!({"module_id":"neebles-connect"});
        assert_eq!(
            staged_vault_reply(&call, "provider-session").unwrap()["code"],
            503
        );
        call["payload"] = json!({"module_id":"neebles-secrets"});
        assert_eq!(
            staged_vault_reply(&call, "provider-session").unwrap()["code"],
            403
        );
    }
    #[test]
    fn mirrors_lexical_module_id_rules_without_path_traversal() {
        for allowed in ["neebles-connect", "db01", "module-sub", &"m".repeat(64)] {
            assert!(valid_module_id(allowed));
        }
        for denied in [
            "",
            ".",
            "..",
            "../../x",
            "some/module",
            "a b",
            "\n",
            "db_01",
            "module.sub",
            "General",
            "general",
            "m--x",
            "m-",
            "A1",
            "x",
            &"m".repeat(65),
        ] {
            assert!(!valid_module_id(denied), "unexpected KDBX module: {denied}");
        }
    }
}
