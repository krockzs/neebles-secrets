//! NEEBLES Secrets 1.0.3 — ephemeral, size-bounded batch generation.
//! Reuses Quick's CSPRNG and its unbiased password alphabet selection.
//! The UI owns batching across IPC calls. No disk/files/DB/KDBX writes.
use serde_json::{json, Value};

const MAX_ITEMS_PER_FRAME: u64 = 16;
const MAX_VALUE_BYTES_PER_FRAME: u64 = 8 * 1024;

fn upper_bound_per_value(input: &Value) -> Result<u64, String> {
    let kind = input
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("password");
    if kind == "uuid" {
        return Ok(36);
    }
    let length = input
        .get("length")
        .and_then(Value::as_u64)
        .unwrap_or(if kind == "password" { 24 } else { 32 });
    match kind {
        "password" if (8..=512).contains(&length) => Ok(length),
        "hex" | "salt" | "pepper" | "key" if (16..=512).contains(&length) => Ok(length * 2),
        "base64" | "base64url" if (16..=512).contains(&length) => Ok(4 * ((length + 2) / 3)),
        "password" | "hex" | "salt" | "pepper" | "key" | "base64" | "base64url" => {
            Err("batch_length_out_of_range".into())
        }
        _ => Err("unsupported_batch_kind".into()),
    }
}

pub(crate) fn generate_batch(input: &Value) -> Result<Value, String> {
    let count = input
        .get("count")
        .and_then(Value::as_u64)
        .ok_or("batch_count_required")?;
    if !(1..=MAX_ITEMS_PER_FRAME).contains(&count) {
        return Err("batch_count_out_of_range".into());
    }
    let max_bytes = upper_bound_per_value(input)?;
    if count
        .checked_mul(max_bytes)
        .is_none_or(|bytes| bytes > MAX_VALUE_BYTES_PER_FRAME)
    {
        return Err("batch_frame_budget_exceeded".into());
    }
    // Ensure that malformed password policies fail before creating results.
    let mut values = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let result = crate::generate(input)?;
        let value = result
            .get("value")
            .and_then(Value::as_str)
            .ok_or("batch_invalid_quick_response")?;
        values.push(value.to_owned());
    }
    Ok(json!({"generated":count,"values":values,"stored":false}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn yields_requested_passwords_without_persistence() {
        let result = generate_batch(&json!({"kind":"password","length":24,"count":7})).unwrap();
        assert_eq!(result["generated"], 7);
        assert_eq!(result["stored"], false);
        let values = result["values"].as_array().unwrap();
        assert_eq!(values.len(), 7);
        assert!(values.iter().all(|v| v.as_str().unwrap().len() == 24));
    }
    #[test]
    fn reuses_token_and_uuid_generators() {
        let result = generate_batch(&json!({"kind":"uuid","count":3})).unwrap();
        assert_eq!(result["values"].as_array().unwrap().len(), 3);
        let result = generate_batch(&json!({"kind":"hex","length":16,"count":4})).unwrap();
        assert!(result["values"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v.as_str().unwrap().len() == 32));
    }
    #[test]
    fn rejects_unbounded_counts_and_outputs() {
        for arg in [
            json!({"kind":"password","count":0}),
            json!({"kind":"password","count":17}),
            json!({"kind":"password","count":100000}),
            json!({"kind":"password","count":16,"length":512,"lowercase":false,"uppercase":false,"symbols":false,"numbers":false}),
            json!({"kind":"hex","count":16,"length":512}),
        ] {
            assert!(generate_batch(&arg).is_err());
        }
    }
    #[test]
    fn still_rejects_invalid_policy() {
        assert!(
            generate_batch(&json!({"kind":"password","count":1,"lowercase":false,
             "uppercase":false,"numbers":false,"symbols":false}))
            .is_err()
        );
    }
}
