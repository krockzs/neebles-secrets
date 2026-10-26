//! Versioned, module-scoped structured secrets. All persisted records are
//! encrypted *inside* the module's existing KDBX via vault_records; no sidecars.
//! This is a private worker API until Boss contracts/grants are certified.
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

const MAX_SCHEMAS: usize = 32;
const MAX_FIELDS: usize = 32;
// A document may span multiple protected KDBX chunk entries. The outer
// authenticated private IPC remains strictly bounded independently.
const MAX_DOCUMENT: usize = 96 * 1024;
const PAGE_MAX: usize = 100;

fn id_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=28).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|x| x.is_ascii_lowercase() || x.is_ascii_digit() || *x == b'-')
        && !s.ends_with('-')
        && !s.contains("--")
}
fn schema_key(id: &str) -> String {
    format!("s-schema-{id}")
}
fn entity_key(schema: &str, id: &str) -> String {
    format!("s-{:02}-{schema}-{id}", schema.len())
}

pub trait Records {
    fn read(&self, id: &str) -> Result<Option<Value>, String>;
    fn write(&mut self, id: &str, data: &Value) -> Result<(), String>;
    fn delete(&mut self, id: &str) -> Result<(), String>;
    fn ids(&self) -> Result<Vec<String>, String>;
}

pub struct Encrypted<'a> {
    path: &'a Path,
    master: &'a [u8],
}
impl<'a> Encrypted<'a> {
    pub fn new(path: &'a Path, master: &'a [u8]) -> Self {
        Self { path, master }
    }
}
impl Records for Encrypted<'_> {
    fn read(&self, id: &str) -> Result<Option<Value>, String> {
        match crate::vault_records::get(self.path, self.master, id) {
            Ok(data) => Ok(data.get("value").cloned()),
            Err(err) if err == "secret_not_found" => Ok(None),
            Err(err) => Err(err),
        }
    }
    fn write(&mut self, id: &str, data: &Value) -> Result<(), String> {
        crate::vault_records::put(self.path, self.master, id, data, false).map(|_| ())
    }
    fn delete(&mut self, id: &str) -> Result<(), String> {
        crate::vault_records::delete(self.path, self.master, id).map(|_| ())
    }
    fn ids(&self) -> Result<Vec<String>, String> {
        let reply = crate::vault_records::list(self.path, self.master)?;
        let ids = reply
            .get("ids")
            .and_then(Value::as_array)
            .ok_or("corrupt_record_inventory")?;
        ids.iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "corrupt_record_inventory".into())
            })
            .collect()
    }
}

// Only used while vault_records::transaction holds the directory lock and
// operates on its private encrypted transaction copy. Never on the live path.
struct EncryptedTxn<'a> {
    path: &'a Path,
    master: &'a [u8],
}
impl Records for EncryptedTxn<'_> {
    fn read(&self, id: &str) -> Result<Option<Value>, String> {
        Encrypted::new(self.path, self.master).read(id)
    }
    fn ids(&self) -> Result<Vec<String>, String> {
        Encrypted::new(self.path, self.master).ids()
    }
    fn write(&mut self, id: &str, v: &Value) -> Result<(), String> {
        crate::vault_records::put_in_transaction(self.path, self.master, id, v, false).map(|_| ())
    }
    fn delete(&mut self, id: &str) -> Result<(), String> {
        crate::vault_records::delete_in_transaction(self.path, self.master, id).map(|_| ())
    }
}

// Overlay tracks all logical writes, so validation sees previous operations
// in the same batch while the encrypted source remains unchanged.
struct Overlay<'a, R: Records> {
    base: &'a mut R,
    changes: BTreeMap<String, Option<Value>>,
}
impl<'a, R: Records> Overlay<'a, R> {
    fn new(base: &'a mut R) -> Self {
        Self {
            base,
            changes: BTreeMap::new(),
        }
    }
    fn flush(self) -> Result<(), String> {
        let Overlay { base, changes } = self;
        for (id, v) in changes {
            if let Some(value) = v {
                base.write(&id, &value)?;
            } else {
                base.delete(&id)?;
            }
        }
        Ok(())
    }
}
impl<R: Records> Records for Overlay<'_, R> {
    fn read(&self, id: &str) -> Result<Option<Value>, String> {
        match self.changes.get(id) {
            Some(v) => Ok(v.clone()),
            None => self.base.read(id),
        }
    }
    fn ids(&self) -> Result<Vec<String>, String> {
        let mut ids: BTreeSet<String> = self.base.ids()?.into_iter().collect();
        for (id, v) in &self.changes {
            if v.is_some() {
                ids.insert(id.clone());
            } else {
                ids.remove(id);
            }
        }
        Ok(ids.into_iter().collect())
    }
    fn write(&mut self, id: &str, v: &Value) -> Result<(), String> {
        self.changes.insert(id.into(), Some(v.clone()));
        Ok(())
    }
    fn delete(&mut self, id: &str) -> Result<(), String> {
        self.changes.insert(id.into(), None);
        Ok(())
    }
}

fn obj<'a>(v: &'a Value, code: &str) -> Result<&'a Map<String, Value>, String> {
    v.as_object().ok_or_else(|| code.to_owned())
}
fn only_fields(o: &Map<String, Value>, names: &[&str], code: &str) -> Result<(), String> {
    if o.keys().any(|k| !names.contains(&k.as_str())) {
        return Err(code.into());
    }
    Ok(())
}
fn check_schema(schema: &Value) -> Result<(), String> {
    let o = obj(schema, "invalid_schema")?;
    only_fields(
        o,
        &["id", "version", "require_replica", "fields", "unique"],
        "invalid_schema",
    )?;
    let id = o
        .get("id")
        .and_then(Value::as_str)
        .ok_or("invalid_schema_id")?;
    if !id_ok(id) {
        return Err("invalid_schema_id".into());
    }
    if !matches!(o.get("version").and_then(Value::as_u64), Some(1..=65535)) {
        return Err("invalid_schema_version".into());
    }
    if o.get("require_replica").and_then(Value::as_bool).is_none() {
        return Err("missing_replica_policy".into());
    }
    let fields = o
        .get("fields")
        .and_then(Value::as_object)
        .ok_or("invalid_schema_fields")?;
    if fields.is_empty() || fields.len() > MAX_FIELDS {
        return Err("invalid_schema_fields".into());
    }
    for (name, rule) in fields {
        if !id_ok(name) {
            return Err("invalid_schema_field".into());
        }
        let rule = obj(rule, "invalid_schema_field")?;
        only_fields(
            rule,
            &["type", "required", "max_length", "target_schema", "default"],
            "invalid_schema_field",
        )?;
        let kind = rule
            .get("type")
            .and_then(Value::as_str)
            .ok_or("invalid_schema_field_type")?;
        if !matches!(
            kind,
            "string" | "secret" | "integer" | "number" | "boolean" | "reference"
        ) {
            return Err("invalid_schema_field_type".into());
        }
        if let Some(required) = rule.get("required") {
            if !required.is_boolean() {
                return Err("invalid_required_field".into());
            }
        }
        if let Some(max) = rule.get("max_length") {
            if !matches!(kind, "string" | "secret") || !matches!(max.as_u64(), Some(1..=96_000)) {
                return Err("invalid_field_length".into());
            }
        }
        if kind == "reference" {
            if !rule
                .get("target_schema")
                .and_then(Value::as_str)
                .is_some_and(id_ok)
            {
                return Err("invalid_reference_target".into());
            }
        } else if rule.contains_key("target_schema") {
            return Err("invalid_reference_target".into());
        }
        if let Some(default) = rule.get("default") {
            if kind == "secret" || kind == "reference" || !value_type(default, kind, rule) {
                return Err("invalid_schema_default".into());
            }
        }
    }
    let mut seen = HashSet::<String>::new();
    let unique = o.get("unique").cloned().unwrap_or_else(|| json!([]));
    let constraints = unique.as_array().ok_or("invalid_unique_rule")?;
    if constraints.len() > 16 {
        return Err("invalid_unique_rule".into());
    }
    for group in constraints {
        let columns = group.as_array().ok_or("invalid_unique_rule")?;
        if columns.is_empty() || columns.len() > 4 {
            return Err("invalid_unique_rule".into());
        }
        let mut parts = Vec::new();
        for column in columns {
            let key = column.as_str().ok_or("invalid_unique_rule")?;
            if !fields.contains_key(key) || parts.contains(&key) {
                return Err("invalid_unique_rule".into());
            }
            parts.push(key);
        }
        let signature = parts.join("\0");
        if !seen.insert(signature) {
            return Err("invalid_unique_rule".into());
        }
    }
    Ok(())
}
fn value_type(value: &Value, kind: &str, rule: &Map<String, Value>) -> bool {
    match kind {
        "string" | "secret" => value.as_str().is_some_and(|s| {
            !s.contains('\0')
                && s.len()
                    <= rule
                        .get("max_length")
                        .and_then(Value::as_u64)
                        .unwrap_or(2048) as usize
        }),
        "reference" => value.as_str().is_some_and(id_ok),
        "integer" => value.as_i64().is_some(),
        "number" => value.as_f64().is_some(),
        "boolean" => value.is_boolean(),
        _ => false,
    }
}
fn normalize(schema: &Value, value: &Value) -> Result<Value, String> {
    let raw = obj(value, "invalid_entity_value")?;
    let fields = schema["fields"]
        .as_object()
        .ok_or("invalid_schema_fields")?;
    if raw.keys().any(|name| !fields.contains_key(name)) {
        return Err("unknown_entity_field".into());
    }
    let mut normalized = raw.clone();
    for (name, rule) in fields {
        if !normalized.contains_key(name) {
            if let Some(default) = rule.get("default") {
                normalized.insert(name.clone(), default.clone());
            }
        }
        if rule.get("required").and_then(Value::as_bool) == Some(true)
            && !normalized.contains_key(name)
        {
            return Err("missing_required_field".into());
        }
        if let Some(v) = normalized.get(name) {
            let kind = rule["type"].as_str().ok_or("invalid_schema_field_type")?;
            if !value_type(v, kind, rule.as_object().ok_or("invalid_schema_field")?) {
                return Err("invalid_field_value".into());
            }
        }
    }
    let document = Value::Object(normalized);
    if serde_json::to_vec(&document)
        .map_err(|_| "invalid_entity_value")?
        .len()
        > MAX_DOCUMENT
    {
        return Err("entity_too_large".into());
    }
    Ok(document)
}
fn schema(db: &impl Records, id: &str) -> Result<Value, String> {
    if !id_ok(id) {
        return Err("invalid_schema_id".into());
    }
    let definition = db.read(&schema_key(id))?.ok_or("schema_not_found")?;
    check_schema(&definition)?;
    if definition["id"] != id {
        return Err("corrupt_schema_record".into());
    }
    Ok(definition)
}
fn entries(db: &impl Records, schema_id: &str) -> Result<Vec<String>, String> {
    let prefix = format!("s-{:02}-{schema_id}-", schema_id.len());
    Ok(db
        .ids()?
        .into_iter()
        .filter(|key| key.starts_with(&prefix))
        .collect())
}
fn read_entity(db: &impl Records, schema_id: &str, id: &str) -> Result<Option<Value>, String> {
    if !id_ok(id) {
        return Err("invalid_entity_id".into());
    }
    let key = entity_key(schema_id, id);
    let item = db.read(&key)?;
    if let Some(ref v) = item {
        if v.get("id").and_then(Value::as_str) != Some(id)
            || v.get("schema_id").and_then(Value::as_str) != Some(schema_id)
            || v.get("revision")
                .and_then(Value::as_u64)
                .is_none_or(|rev| rev == 0)
            || !v.get("value").is_some_and(Value::is_object)
        {
            return Err("corrupt_structured_entity".into());
        }
    }
    Ok(item)
}
fn references_exist(db: &impl Records, def: &Value, document: &Value) -> Result<(), String> {
    let fields = def["fields"].as_object().ok_or("invalid_schema_fields")?;
    for (name, rule) in fields {
        if rule["type"] != "reference" {
            continue;
        }
        if let Some(target) = document.get(name).and_then(Value::as_str) {
            let schema_id = rule["target_schema"]
                .as_str()
                .ok_or("invalid_reference_target")?;
            schema(db, schema_id)?;
            if read_entity(db, schema_id, target)?.is_none() {
                return Err("reference_not_found".into());
            }
        }
    }
    Ok(())
}
fn check_unique(
    db: &impl Records,
    def: &Value,
    schema_id: &str,
    id: &str,
    value: &Value,
) -> Result<(), String> {
    let Some(constraints) = def.get("unique").and_then(Value::as_array) else {
        return Ok(());
    };
    for key in entries(db, schema_id)? {
        let Some(existing) = db.read(&key)? else {
            return Err("corrupt_structured_index".into());
        };
        let existing_id = existing["id"].as_str().ok_or("corrupt_structured_entity")?;
        if existing_id == id {
            continue;
        }
        for group in constraints {
            let columns = group.as_array().ok_or("invalid_unique_rule")?;
            if columns.iter().all(|column| {
                column.as_str().is_some_and(|col| {
                    value.get(col).is_some() && existing["value"].get(col) == value.get(col)
                })
            }) {
                return Err("unique_constraint_violation".into());
            }
        }
    }
    Ok(())
}

pub fn define(db: &mut impl Records, def: &Value) -> Result<Value, String> {
    check_schema(def)?;
    let id = def["id"].as_str().ok_or("invalid_schema_id")?;
    let key = schema_key(id);
    if let Some(old) = db.read(&key)? {
        if old == *def {
            return Ok(json!({"id":id,"created":false,"version":def["version"]}));
        }
        return Err("schema_migration_required".into());
    }
    let count = db
        .ids()?
        .iter()
        .filter(|k| k.starts_with("s-schema-"))
        .count();
    if count >= MAX_SCHEMAS {
        return Err("schema_count_limit".into());
    }
    db.write(&key, def)?;
    Ok(json!({"id":id,"created":true,"version":def["version"]}))
}
pub fn get_schema(db: &impl Records, id: &str) -> Result<Value, String> {
    schema(db, id)
}
pub fn put(
    db: &mut impl Records,
    schema_id: &str,
    id: &str,
    input: &Value,
    expected_revision: Option<u64>,
) -> Result<Value, String> {
    let def = schema(db, schema_id)?;
    if !id_ok(id) {
        return Err("invalid_entity_id".into());
    }
    if def["require_replica"] == false && id != "primary" {
        return Err("non_replicable_id_must_be_primary".into());
    }
    let value = normalize(&def, input)?;
    let old = read_entity(db, schema_id, id)?;
    let old_revision = old.as_ref().and_then(|v| v["revision"].as_u64());
    if old_revision != expected_revision {
        return Err("revision_conflict".into());
    }
    references_exist(db, &def, &value)?;
    check_unique(db, &def, schema_id, id, &value)?;
    let revision = old_revision
        .unwrap_or(0)
        .checked_add(1)
        .ok_or("revision_overflow")?;
    let entity = json!({"schema_id":schema_id,"schema_version":def["version"],"id":id,"revision":revision,"value":value});
    db.write(&entity_key(schema_id, id), &entity)?;
    Ok(json!({"id":id,"revision":revision,"created":old.is_none()}))
}
pub fn get(db: &impl Records, schema_id: &str, id: &str) -> Result<Value, String> {
    schema(db, schema_id)?;
    read_entity(db, schema_id, id)?.ok_or("entity_not_found".into())
}
pub fn list(
    db: &impl Records,
    schema_id: &str,
    cursor: Option<&str>,
    limit: u64,
) -> Result<Value, String> {
    schema(db, schema_id)?;
    if limit == 0 || limit > PAGE_MAX as u64 {
        return Err("invalid_page_limit".into());
    }
    if cursor.is_some_and(|id| !id_ok(id)) {
        return Err("invalid_page_cursor".into());
    }
    let mut ids = Vec::<String>::new();
    for key in entries(db, schema_id)? {
        let Some(id) = key.strip_prefix(&format!("s-{:02}-{schema_id}-", schema_id.len())) else {
            continue;
        };
        if !id_ok(id) {
            return Err("corrupt_structured_index".into());
        }
        if cursor.is_some_and(|c| id <= c) {
            continue;
        }
        ids.push(id.to_owned());
    }
    ids.sort();
    let has_more = ids.len() > limit as usize;
    ids.truncate(limit as usize);
    let next_cursor = if has_more { ids.last().cloned() } else { None };
    Ok(json!({"ids":ids,"next_cursor":next_cursor,"has_more":has_more}))
}
pub fn delete(
    db: &mut impl Records,
    schema_id: &str,
    id: &str,
    expected_revision: u64,
) -> Result<Value, String> {
    schema(db, schema_id)?;
    let item = read_entity(db, schema_id, id)?.ok_or("entity_not_found")?;
    if item["revision"].as_u64() != Some(expected_revision) {
        return Err("revision_conflict".into());
    }
    for skey in db.ids()?.into_iter().filter(|k| k.starts_with("s-schema-")) {
        let Some(def) = db.read(&skey)? else {
            return Err("corrupt_structured_index".into());
        };
        check_schema(&def)?;
        let Some(other_schema) = def["id"].as_str() else {
            return Err("corrupt_schema_record".into());
        };
        let fields = def["fields"].as_object().ok_or("invalid_schema_fields")?;
        let pointing: Vec<&str> = fields
            .iter()
            .filter(|(_, rule)| rule["type"] == "reference" && rule["target_schema"] == schema_id)
            .map(|(name, _)| name.as_str())
            .collect();
        if pointing.is_empty() {
            continue;
        }
        for key in entries(db, other_schema)? {
            let Some(record) = db.read(&key)? else {
                return Err("corrupt_structured_index".into());
            };
            if pointing.iter().any(|field| record["value"][*field] == id) {
                return Err("entity_referenced".into());
            }
        }
    }
    db.delete(&entity_key(schema_id, id))?;
    Ok(json!({"id":id,"deleted":true}))
}

// Version changes are deliberately explicit and forward-only. Revalidate
// every record against the replacement definition BEFORE mutating anything;
// missing required values without defaults reject the entire migration.
pub fn migrate(db: &mut impl Records, next: &Value) -> Result<Value, String> {
    check_schema(next)?;
    let id = next["id"].as_str().ok_or("invalid_schema_id")?;
    let old = schema(db, id)?;
    let old_version = old["version"].as_u64().ok_or("invalid_schema_version")?;
    if next["version"].as_u64() != old_version.checked_add(1) {
        return Err("schema_version_must_advance_one".into());
    }
    if next["require_replica"] != old["require_replica"] {
        return Err("replica_policy_change_forbidden".into());
    }
    let keys = entries(db, id)?;
    // Bounded work, no unbounded expansion in the worker. Larger migrations
    // require an explicitly designed paged protocol before publication.
    if keys.len() > 1024 {
        return Err("migration_batch_limit".into());
    }
    let mut updated = Vec::with_capacity(keys.len());
    for key in keys {
        let record = db.read(&key)?.ok_or("corrupt_structured_index")?;
        let entity_id = record["id"].as_str().ok_or("corrupt_structured_entity")?;
        if record["schema_id"] != id
            || record["schema_version"].as_u64() != Some(old_version)
            || entity_key(id, entity_id) != key
        {
            return Err("corrupt_structured_entity".into());
        }
        let revision = record["revision"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("corrupt_structured_entity")?;
        let normalized = normalize(next, &record["value"])?;
        references_exist(db, next, &normalized)?;
        let next_rev = revision.checked_add(1).ok_or("revision_overflow")?;
        let revised = json!({"schema_id":id,"schema_version":next["version"],"id":entity_id,
                           "revision":next_rev,"value":normalized});
        updated.push((key, revised));
    }
    // Validate new compound uniqueness against the *migrated* set.
    if let Some(constraints) = next.get("unique").and_then(Value::as_array) {
        for group in constraints {
            let mut seen = HashSet::<String>::new();
            let cols = group.as_array().ok_or("invalid_unique_rule")?;
            for (_, entity) in &updated {
                let parts = cols
                    .iter()
                    .map(|col| entity["value"].get(col.as_str().unwrap()))
                    .collect::<Vec<_>>();
                if parts.iter().all(|v| v.is_some()) {
                    let signature =
                        serde_json::to_string(&parts).map_err(|_| "invalid_unique_rule")?;
                    if !seen.insert(signature) {
                        return Err("unique_constraint_violation".into());
                    }
                }
            }
        }
    }
    for (key, record) in &updated {
        db.write(key, record)?;
    }
    db.write(&schema_key(id), next)?;
    Ok(json!({"id":id,"version":next["version"],"migrated":updated.len()}))
}

// A structured batch first applies every mutation to an in-memory overlay.
// Only after complete validation is the overlay flushed to an encrypted
// KDBX *transaction copy*, never to the installed vault directly.
pub fn apply_batch(db: &mut impl Records, operations: &Value) -> Result<Value, String> {
    let ops = operations.as_array().ok_or("invalid_batch")?;
    if ops.is_empty() || ops.len() > 32 {
        return Err("batch_size_out_of_range".into());
    }
    let mut overlay = Overlay::new(db);
    let mut results = Vec::with_capacity(ops.len());
    for op in ops {
        let fields = obj(op, "invalid_batch_operation")?;
        let kind = op
            .get("op")
            .and_then(Value::as_str)
            .ok_or("invalid_batch_operation")?;
        let answer = match kind {
            "define" => {
                only_fields(fields, &["op", "schema"], "invalid_batch_operation")?;
                define(
                    &mut overlay,
                    op.get("schema").ok_or("invalid_batch_operation")?,
                )?
            }
            "migrate" => {
                only_fields(fields, &["op", "schema"], "invalid_batch_operation")?;
                migrate(
                    &mut overlay,
                    op.get("schema").ok_or("invalid_batch_operation")?,
                )?
            }
            "put" => {
                only_fields(
                    fields,
                    &["op", "schema_id", "id", "value", "expected_revision"],
                    "invalid_batch_operation",
                )?;
                let name = op["schema_id"].as_str().ok_or("invalid_batch_operation")?;
                let id = op["id"].as_str().ok_or("invalid_batch_operation")?;
                let expected = match op.get("expected_revision") {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(
                        v.as_u64()
                            .filter(|n| *n > 0)
                            .ok_or("invalid_expected_revision")?,
                    ),
                };
                put(
                    &mut overlay,
                    name,
                    id,
                    op.get("value").ok_or("invalid_batch_operation")?,
                    expected,
                )?
            }
            "delete" => {
                only_fields(
                    fields,
                    &["op", "schema_id", "id", "expected_revision"],
                    "invalid_batch_operation",
                )?;
                let name = op["schema_id"].as_str().ok_or("invalid_batch_operation")?;
                let id = op["id"].as_str().ok_or("invalid_batch_operation")?;
                let revision = op["expected_revision"]
                    .as_u64()
                    .filter(|n| *n > 0)
                    .ok_or("invalid_expected_revision")?;
                delete(&mut overlay, name, id, revision)?
            }
            _ => return Err("invalid_batch_operation".into()),
        };
        results.push(answer);
    }
    overlay.flush()?;
    Ok(json!({"committed":true,"results":results}))
}

pub fn encrypted_batch(path: &Path, master: &[u8], operations: &Value) -> Result<Value, String> {
    // One outer commit encompasses ALL schema + entity mutations.
    crate::vault_records::transaction(path, master, |temp| {
        let mut db = EncryptedTxn { path: temp, master };
        apply_batch(&mut db, operations)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[derive(Default)]
    struct Memory(BTreeMap<String, Value>);
    impl Records for Memory {
        fn read(&self, id: &str) -> Result<Option<Value>, String> {
            Ok(self.0.get(id).cloned())
        }
        fn write(&mut self, id: &str, v: &Value) -> Result<(), String> {
            self.0.insert(id.into(), v.clone());
            Ok(())
        }
        fn delete(&mut self, id: &str) -> Result<(), String> {
            self.0.remove(id);
            Ok(())
        }
        fn ids(&self) -> Result<Vec<String>, String> {
            Ok(self.0.keys().cloned().collect())
        }
    }
    fn node() -> Value {
        json!({"id":"node","version":1,"require_replica":true,"fields":{
        "name":{"type":"string","required":true,"max_length":128},
        "host":{"type":"string","required":true},
        "enabled":{"type":"boolean","default":true}
    },"unique":[["name"]]})
    }
    fn port() -> Value {
        json!({"id":"vscode","version":1,"require_replica":true,"fields":{
        "node":{"type":"reference","required":true,"target_schema":"node"},
        "port":{"type":"integer","required":true},
        "password":{"type":"secret"}
    },"unique":[["node","port"]]})
    }
    #[test]
    fn bounded_large_structured_value_with_private_chunked_storage() {
        let mut db = Memory::default();
        let def = json!({"id":"asset","version":1,"require_replica":true,
            "fields":{"description":{"type":"string","required":true,"max_length":96000},
                "note":{"type":"string","max_length":4096}}});
        define(&mut db, &def).unwrap();
        let text = "Q".repeat(32_000);
        assert_eq!(
            put(&mut db, "asset", "big", &json!({"description":text}), None).unwrap()["revision"],
            1
        );
        assert_eq!(
            get(&db, "asset", "big").unwrap()["value"]["description"]
                .as_str()
                .unwrap()
                .len(),
            32_000
        );
        // A 96,000-byte field is valid: the document limit is 96 KiB (98,304 bytes).
        assert_eq!(
            put(
                &mut db,
                "asset",
                "limit-ok",
                &json!({"description":"B".repeat(96_000)}),
                None
            )
            .unwrap()["revision"],
            1
        );
        // Both fields obey their own limits, but the combined JSON exceeds 96 KiB.
        let oversized = json!({"description":"B".repeat(96_000),"note":"C".repeat(4000)});
        assert!(serde_json::to_vec(&oversized).unwrap().len() > MAX_DOCUMENT);
        assert_eq!(
            put(&mut db, "asset", "too-big", &oversized, None).unwrap_err(),
            "entity_too_large"
        );
        assert_eq!(
            get(&db, "asset", "too-big").unwrap_err(),
            "entity_not_found"
        );
    }
    #[test]
    fn replica_and_versioned_crud_and_revision() {
        let mut db = Memory::default();
        assert_eq!(define(&mut db, &node()).unwrap()["created"], true);
        assert_eq!(define(&mut db, &node()).unwrap()["created"], false);
        assert_eq!(
            put(
                &mut db,
                "node",
                "n1",
                &json!({"name":"server","host":"10.0.0.1"}),
                None
            )
            .unwrap()["revision"],
            1
        );
        assert_eq!(get(&db, "node", "n1").unwrap()["value"]["enabled"], true);
        assert!(put(
            &mut db,
            "node",
            "n1",
            &json!({"name":"server","host":"new"}),
            None
        )
        .is_err());
        assert_eq!(
            put(
                &mut db,
                "node",
                "n1",
                &json!({"name":"server","host":"new"}),
                Some(1)
            )
            .unwrap()["revision"],
            2
        );
        assert!(delete(&mut db, "node", "n1", 1).is_err());
        assert_eq!(delete(&mut db, "node", "n1", 2).unwrap()["deleted"], true);
    }
    #[test]
    fn cardinality_and_composite_unique_scoped_to_parent() {
        let mut db = Memory::default();
        define(&mut db, &node()).unwrap();
        define(&mut db, &port()).unwrap();
        for id in ["a", "b"] {
            put(&mut db, "node", id, &json!({"name":id,"host":"host"}), None).unwrap();
        }
        put(
            &mut db,
            "vscode",
            "first",
            &json!({"node":"a","port":8443}),
            None,
        )
        .unwrap();
        assert_eq!(
            put(
                &mut db,
                "vscode",
                "duplicate",
                &json!({"node":"a","port":8443}),
                None
            )
            .unwrap_err(),
            "unique_constraint_violation"
        );
        put(
            &mut db,
            "vscode",
            "other",
            &json!({"node":"b","port":8443}),
            None,
        )
        .unwrap();
        assert_eq!(
            delete(&mut db, "node", "a", 1).unwrap_err(),
            "entity_referenced"
        );
        assert_eq!(
            put(
                &mut db,
                "vscode",
                "missing",
                &json!({"node":"absent","port":22}),
                None
            )
            .unwrap_err(),
            "reference_not_found"
        );
    }
    #[test]
    fn singletons_have_stable_primary_id() {
        let mut db = Memory::default();
        let mut s = node();
        s["require_replica"] = json!(false);
        define(&mut db, &s).unwrap();
        assert_eq!(
            put(
                &mut db,
                "node",
                "other",
                &json!({"name":"one","host":"here"}),
                None
            )
            .unwrap_err(),
            "non_replicable_id_must_be_primary"
        );
        put(
            &mut db,
            "node",
            "primary",
            &json!({"name":"one","host":"here"}),
            None,
        )
        .unwrap();
    }
    #[test]
    fn schema_validation_and_migration_fail_closed() {
        let mut db = Memory::default();
        for bad in [
            json!({"id":"evil/../a","version":1,"require_replica":true,"fields":{"a":{"type":"string"}}}),
            json!({"id":"okay","version":0,"require_replica":true,"fields":{"a":{"type":"string"}}}),
            json!({"id":"okay","version":1,"require_replica":true,"fields":{"a":{"type":"secret","default":"password"}}}),
            json!({"id":"okay","version":1,"require_replica":true,"fields":{"a":{"type":"string"}},"unique":[["bad"]]}),
        ] {
            assert!(define(&mut db, &bad).is_err());
        }
        define(&mut db, &node()).unwrap();
        let mut changed = node();
        changed["version"] = json!(2);
        assert_eq!(
            define(&mut db, &changed).unwrap_err(),
            "schema_migration_required"
        );
        assert_eq!(db.0.len(), 1);
    }
    #[test]
    fn typed_required_and_unknown_fields_denied() {
        let mut db = Memory::default();
        define(&mut db, &node()).unwrap();
        for bad in [
            json!({"name":"x"}),
            json!({"name":"x","host":22}),
            json!({"name":"x","host":"host","unknown":true}),
        ] {
            assert!(put(&mut db, "node", "n1", &bad, None).is_err());
        }
        assert_eq!(db.0.len(), 1);
    }
    #[test]
    fn hyphenated_namespaces_cannot_collide() {
        let mut db = Memory::default();
        for schema_id in ["a", "a-b"] {
            let mut def = node();
            def["id"] = json!(schema_id);
            def["unique"] = json!([]);
            define(&mut db, &def).unwrap();
        }
        put(
            &mut db,
            "a",
            "b-c",
            &json!({"name":"one","host":"localhost"}),
            None,
        )
        .unwrap();
        put(
            &mut db,
            "a-b",
            "c",
            &json!({"name":"two","host":"localhost"}),
            None,
        )
        .unwrap();
        assert_eq!(get(&db, "a", "b-c").unwrap()["value"]["name"], "one");
        assert_eq!(get(&db, "a-b", "c").unwrap()["value"]["name"], "two");
    }
    #[test]
    fn secrets_never_appear_in_list_responses() {
        let mut db = Memory::default();
        define(&mut db, &node()).unwrap();
        define(&mut db, &port()).unwrap();
        put(
            &mut db,
            "node",
            "n1",
            &json!({"name":"server","host":"localhost"}),
            None,
        )
        .unwrap();
        put(
            &mut db,
            "vscode",
            "v1",
            &json!({"node":"n1","port":8081,"password":"SENSITIVE_SAMPLE_123"}),
            None,
        )
        .unwrap();
        let response = list(&db, "vscode", None, 10).unwrap();
        assert!(!response.to_string().contains("SENSITIVE_SAMPLE_123"));
        assert_eq!(
            get(&db, "vscode", "v1").unwrap()["value"]["password"],
            "SENSITIVE_SAMPLE_123"
        );
    }
    #[test]
    fn batch_stages_all_records_and_keeps_references_consistent() {
        let mut db = Memory::default();
        let operations = json!([
            {"op":"define","schema":node()},
            {"op":"define","schema":port()},
            {"op":"put","schema_id":"node","id":"n1","value":{"name":"server","host":"localhost"}},
            {"op":"put","schema_id":"vscode","id":"ide1","value":{"node":"n1","port":8081}}
        ]);
        assert_eq!(
            apply_batch(&mut db, &operations).unwrap()["results"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(get(&db, "vscode", "ide1").unwrap()["value"]["port"], 8081);
        let snapshot = db.0.clone();
        let invalid = json!([
            {"op":"put","schema_id":"node","id":"n2","value":{"name":"another","host":"localhost"}},
            {"op":"put","schema_id":"vscode","id":"ide2","value":{"node":"missing","port":8082}}
        ]);
        assert_eq!(
            apply_batch(&mut db, &invalid).unwrap_err(),
            "reference_not_found"
        );
        assert_eq!(
            db.0, snapshot,
            "failed batch must not mutate even first record"
        );
    }
    #[test]
    fn batch_deletes_referenced_children_before_parent_in_one_commit() {
        let mut db = Memory::default();
        define(&mut db, &node()).unwrap();
        define(&mut db, &port()).unwrap();
        put(
            &mut db,
            "node",
            "n1",
            &json!({"name":"one","host":"localhost"}),
            None,
        )
        .unwrap();
        put(
            &mut db,
            "vscode",
            "v1",
            &json!({"node":"n1","port":80}),
            None,
        )
        .unwrap();
        let removal = json!([
            {"op":"delete","schema_id":"vscode","id":"v1","expected_revision":1},
            {"op":"delete","schema_id":"node","id":"n1","expected_revision":1}
        ]);
        assert!(apply_batch(&mut db, &removal).unwrap()["committed"]
            .as_bool()
            .unwrap());
        assert!(get(&db, "node", "n1").is_err());
    }
    #[test]
    fn schema_migration_with_default_advances_revision_once() {
        let mut db = Memory::default();
        define(&mut db, &node()).unwrap();
        put(
            &mut db,
            "node",
            "n1",
            &json!({"name":"one","host":"localhost"}),
            None,
        )
        .unwrap();
        let mut next = node();
        next["version"] = json!(2);
        next["fields"]["tls"] = json!({"type":"boolean","required":true,"default":false});
        let batch = json!([{"op":"migrate","schema":next}]);
        assert_eq!(
            apply_batch(&mut db, &batch).unwrap()["results"][0]["migrated"],
            1
        );
        let record = get(&db, "node", "n1").unwrap();
        assert_eq!(record["schema_version"], 2);
        assert_eq!(record["revision"], 2);
        assert_eq!(record["value"]["tls"], false);
        assert_eq!(get_schema(&db, "node").unwrap()["version"], 2);
    }
    #[test]
    fn schema_migration_invalid_required_field_keeps_every_old_byte() {
        let mut db = Memory::default();
        define(&mut db, &node()).unwrap();
        put(
            &mut db,
            "node",
            "n1",
            &json!({"name":"one","host":"localhost"}),
            None,
        )
        .unwrap();
        let before = db.0.clone();
        let mut next = node();
        next["version"] = json!(2);
        next["fields"]["must-have"] = json!({"type":"string","required":true});
        assert_eq!(
            apply_batch(&mut db, &json!([{"op":"migrate","schema":next}])).unwrap_err(),
            "missing_required_field"
        );
        assert_eq!(db.0, before);
    }
    #[test]
    fn migration_rejects_incompatible_uniqueness_and_version_jumps() {
        let mut db = Memory::default();
        let mut s = node();
        s["unique"] = json!([]);
        define(&mut db, &s).unwrap();
        for id in ["one", "two"] {
            put(
                &mut db,
                "node",
                id,
                &json!({"name":"dup","host":"localhost"}),
                None,
            )
            .unwrap();
        }
        let before = db.0.clone();
        let mut changed = node();
        changed["version"] = json!(2);
        assert_eq!(
            apply_batch(&mut db, &json!([{"op":"migrate","schema":changed}])).unwrap_err(),
            "unique_constraint_violation"
        );
        assert_eq!(db.0, before);
        changed["version"] = json!(4);
        assert_eq!(
            migrate(&mut db, &changed).unwrap_err(),
            "schema_version_must_advance_one"
        );
    }
    #[test]
    fn batch_rejects_revision_conflicts_and_untrusted_operation_fields() {
        let mut db = Memory::default();
        define(&mut db, &node()).unwrap();
        let before = db.0.clone();
        let invalid = json!([{"op":"put","schema_id":"node","id":"n1","value":{"name":"host","host":"here"},"expected_revision":100}]);
        assert_eq!(
            apply_batch(&mut db, &invalid).unwrap_err(),
            "revision_conflict"
        );
        assert_eq!(db.0, before);
        let hidden = json!([{"op":"define","schema":node(),"untrusted":true}]);
        assert_eq!(
            apply_batch(&mut db, &hidden).unwrap_err(),
            "invalid_batch_operation"
        );
        assert_eq!(
            apply_batch(&mut db, &json!([])).unwrap_err(),
            "batch_size_out_of_range"
        );
    }
    #[test]
    fn paginated_thousand_records_and_stable_order() {
        let mut db = Memory::default();
        define(&mut db, &node()).unwrap();
        for index in 0..1024 {
            let id = format!("n{index:04}");
            put(
                &mut db,
                "node",
                &id,
                &json!({"name":id,"host":"localhost"}),
                None,
            )
            .unwrap();
        }
        let mut cursor = None::<String>;
        let mut total = 0;
        loop {
            let page = list(&db, "node", cursor.as_deref(), 97).unwrap();
            let values = page["ids"].as_array().unwrap();
            assert!(!values.is_empty());
            total += values.len();
            if page["has_more"] == false {
                break;
            }
            cursor = Some(page["next_cursor"].as_str().unwrap().into());
        }
        assert_eq!(total, 1024);
    }
}
