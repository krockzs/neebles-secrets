//! NEEBLES Secrets 1.0.3 — cryptographic operations inside the isolated worker.
//! No shell commands, plaintext persistence, logging or client-selected providers.
//! Authorized Secrets UI only; the broker must supply peer identity.
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use blake2::{Blake2b512, Blake2s256};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

// Cryptographic providers are loaded from a fixed OpenSSL 3 soname in the
// governed Secrets worker. Never use a path from IPC, environment, or settings.
// Existing Rust primitives remain unchanged; no handwritten SHA-3/scrypt.
mod openssl3 {
    use std::ffi::{c_char, c_int, c_uint, c_void, CString};
    use std::ptr;

    unsafe extern "C" {
        fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> c_int;
    }
    struct Library(*mut c_void);
    impl Library {
        fn load() -> Result<Self, String> {
            let soname = CString::new("libcrypto.so.3").expect("static soname");
            let handle = unsafe {
                dlopen(soname.as_ptr(), 2 /* RTLD_NOW */)
            };
            if handle.is_null() {
                Err("openssl3_provider_unavailable_in_worker".into())
            } else {
                Ok(Self(handle))
            }
        }
        unsafe fn symbol<F: Copy>(&self, name: &str) -> Result<F, String> {
            let name = CString::new(name).map_err(|_| "invalid_provider_symbol")?;
            let symbol = unsafe { dlsym(self.0, name.as_ptr()) };
            if symbol.is_null() {
                return Err("openssl3_required_symbol_unavailable".into());
            }
            // All symbol names and ABIs are fixed at build time; never derived
            // from caller-controlled values.
            if std::mem::size_of::<F>() != std::mem::size_of::<*mut c_void>() {
                return Err("openssl3_abi_mismatch".into());
            }
            Ok(unsafe { std::mem::transmute_copy::<*mut c_void, F>(&symbol) })
        }
    }
    impl Drop for Library {
        fn drop(&mut self) {
            unsafe {
                dlclose(self.0);
            }
        }
    }
    type MdFn = unsafe extern "C" fn() -> *const c_void;
    type DigestFn = unsafe extern "C" fn(
        *const c_void,
        usize,
        *mut u8,
        *mut c_uint,
        *const c_void,
        *mut c_void,
    ) -> c_int;
    type ScryptFn = unsafe extern "C" fn(
        *const c_char,
        usize,
        *const u8,
        usize,
        u64,
        u64,
        u64,
        u64,
        *mut u8,
        usize,
    ) -> c_int;

    pub(super) fn sha3(input: &[u8], bits: u16) -> Result<Vec<u8>, String> {
        let lib = Library::load()?;
        let (name, len) = match bits {
            256 => ("EVP_sha3_256", 32usize),
            512 => ("EVP_sha3_512", 64usize),
            _ => return Err("invalid_sha3_variant".into()),
        };
        let make_md: MdFn = unsafe { lib.symbol(name)? };
        let digest: DigestFn = unsafe { lib.symbol("EVP_Digest")? };
        let md = unsafe { make_md() };
        if md.is_null() {
            return Err("openssl3_sha3_unavailable".into());
        }
        let mut result = vec![0u8; len];
        let mut written: c_uint = 0;
        let status = unsafe {
            digest(
                input.as_ptr().cast(),
                input.len(),
                result.as_mut_ptr(),
                &mut written,
                md,
                ptr::null_mut(),
            )
        };
        if status != 1 || written as usize != len {
            return Err("openssl3_sha3_failed".into());
        }
        Ok(result)
    }
    pub(super) fn scrypt(
        password: &[u8],
        salt: &[u8],
        log_n: u32,
        output: &mut [u8],
    ) -> Result<(), String> {
        if !(10..=15).contains(&log_n)
            || !(16..=64).contains(&output.len())
            || !(8..=64).contains(&salt.len())
        {
            return Err("scrypt_parameters_out_of_range".into());
        }
        let lib = Library::load()?;
        let derive: ScryptFn = unsafe { lib.symbol("EVP_PBE_scrypt")? };
        // N=1024..32768, r=8, p=1. At most 32 MiB working memory;
        // OpenSSL imposes a further 64 MiB hard cap.
        let status = unsafe {
            derive(
                password.as_ptr().cast(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                1_u64 << log_n,
                8,
                1,
                64 * 1024 * 1024,
                output.as_mut_ptr(),
                output.len(),
            )
        };
        if status != 1 {
            output.fill(0);
            return Err("openssl3_scrypt_failed".into());
        }
        Ok(())
    }
}

const MAX_INPUT: usize = 4096;
const MAX_KEY: usize = 1024;

fn required<'a>(input: &'a Value, key: &str, max: usize) -> Result<&'a str, String> {
    let value = input
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing_{key}"))?;
    if value.is_empty() || value.len() > max {
        return Err(format!("invalid_{key}_length"));
    }
    Ok(value)
}
fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 || input.len() > 128 || !input.is_ascii() {
        return Err("invalid_salt_hex".into());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or("invalid_salt_hex")?;
        let lo = (pair[1] as char).to_digit(16).ok_or("invalid_salt_hex")?;
        out.push(((hi << 4) | lo) as u8);
    }
    if !(8..=64).contains(&out.len()) {
        return Err("salt must contain 8..64 bytes".into());
    }
    Ok(out)
}
fn encode(result: &[u8], encoding: &str) -> Result<String, String> {
    match encoding {
        "hex" => Ok(crate::hex(result)),
        "base64" => Ok(base64::engine::general_purpose::STANDARD.encode(result)),
        "base64url" => Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result)),
        _ => Err("unsupported_output_encoding".into()),
    }
}
// Compare existing digests and derived password hashes without returning new
// secret-derived values to the caller. The comparison is constant-time for
// equal-length byte slices; KDF work limits are inherited from compute_raw.
fn expected_bytes(input: &Value, encoding: &str) -> Result<Vec<u8>, String> {
    let expected = input
        .get("expected")
        .and_then(Value::as_str)
        .ok_or("missing_expected")?;
    if expected.is_empty() || expected.len() > 256 {
        return Err("expected_length_out_of_range".into());
    }
    let decoded = match encoding {
        "hex" => {
            if expected.len() % 2 != 0 || !expected.is_ascii() {
                return Err("invalid_expected_hex".into());
            }
            expected
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let hi = (pair[0] as char)
                        .to_digit(16)
                        .ok_or("invalid_expected_hex")?;
                    let lo = (pair[1] as char)
                        .to_digit(16)
                        .ok_or("invalid_expected_hex")?;
                    Ok(((hi << 4) | lo) as u8)
                })
                .collect::<Result<Vec<u8>, String>>()?
        }
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(expected)
            .map_err(|_| "invalid_expected_base64")?,
        "base64url" => base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(expected)
            .map_err(|_| "invalid_expected_base64url")?,
        _ => return Err("unsupported_output_encoding".into()),
    };
    if decoded.len() < 16 || decoded.len() > 64 {
        return Err("expected_bytes_out_of_range".into());
    }
    Ok(decoded)
}
fn verify(input: &Value) -> Result<Value, String> {
    let family = input
        .get("family")
        .and_then(Value::as_str)
        .ok_or("missing_family")?;
    if !matches!(family, "hash" | "hmac" | "kdf") {
        return Err("invalid_verification_family".into());
    }
    let algorithm = input.get("algorithm").and_then(Value::as_str).unwrap_or("");
    let encoding = input
        .get("encoding")
        .and_then(Value::as_str)
        .unwrap_or("hex");
    let expected = expected_bytes(input, encoding)?;
    if family == "kdf" {
        // Never verify against a freshly randomized salt: the caller must
        // supply the original salt from the prior derivation.
        if input
            .get("salt_hex")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
        {
            return Err("verification_requires_original_salt".into());
        }
        let requested = input
            .get("output_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(32);
        if requested != expected.len() as u64 {
            return Err("kdf_expected_length_mismatch".into());
        }
    }
    let computed = compute_raw(input)?;
    let actual = computed
        .get("value")
        .and_then(Value::as_str)
        .ok_or("invalid_compute_response")?;
    // Internal digest is encoded with the same strict encoding; comparing
    // decoded bytes avoids case differences in hexadecimal representation.
    let computed_bytes = expected_bytes(&json!({"expected":actual}), encoding)?;
    let matches = bool::from(computed_bytes.as_slice().ct_eq(expected.as_slice()));
    Ok(json!({"verified":matches,"family":family,"algorithm":algorithm}))
}
pub(crate) fn compute(input: &Value) -> Result<Value, String> {
    if input.get("verify").and_then(Value::as_bool) == Some(true) {
        verify(input)
    } else {
        compute_raw(input)
    }
}
fn compute_raw(input: &Value) -> Result<Value, String> {
    let family = input.get("family").and_then(Value::as_str).unwrap_or("");
    let algorithm = input.get("algorithm").and_then(Value::as_str).unwrap_or("");
    let encoding = input
        .get("encoding")
        .and_then(Value::as_str)
        .unwrap_or("hex");
    let text = input
        .get("text")
        .and_then(Value::as_str)
        .ok_or("missing_text")?;
    if text.len() > MAX_INPUT {
        return Err("invalid_text_length".into());
    }
    if family == "kdf" && text.is_empty() {
        return Err("empty_kdf_password".into());
    }
    let bytes = text.as_bytes();
    let result = match family {
        "hash" => {
            let digest = match algorithm {
                "sha256" => Sha256::digest(bytes).to_vec(),
                "sha512" => Sha512::digest(bytes).to_vec(),
                "blake2b512" => Blake2b512::digest(bytes).to_vec(),
                "blake2s256" => Blake2s256::digest(bytes).to_vec(),
                "sha3-256" => openssl3::sha3(bytes, 256)?,
                "sha3-512" => openssl3::sha3(bytes, 512)?,
                _ => return Err("unsupported_hash_algorithm".into()),
            };
            json!({"family":family,"algorithm":algorithm,"encoding":encoding,"value":encode(&digest,encoding)?})
        }
        "hmac" => {
            let key = required(input, "key", MAX_KEY)?.as_bytes();
            let mac = match algorithm {
                "hmac-sha256" => {
                    let mut m =
                        Hmac::<Sha256>::new_from_slice(key).map_err(|_| "invalid_hmac_key")?;
                    m.update(bytes);
                    m.finalize().into_bytes().to_vec()
                }
                "hmac-sha512" => {
                    let mut m =
                        Hmac::<Sha512>::new_from_slice(key).map_err(|_| "invalid_hmac_key")?;
                    m.update(bytes);
                    m.finalize().into_bytes().to_vec()
                }
                _ => return Err("unsupported_hmac_algorithm".into()),
            };
            json!({"family":family,"algorithm":algorithm,"encoding":encoding,"value":encode(&mac,encoding)?})
        }
        "kdf" => {
            let output_bytes = input
                .get("output_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(32);
            if !(16..=64).contains(&output_bytes) {
                return Err("output_bytes_out_of_range".into());
            }
            let supplied = input.get("salt_hex").and_then(Value::as_str).unwrap_or("");
            let salt = if supplied.is_empty() {
                crate::crypto_bytes(16)?
            } else {
                decode_hex(supplied)?
            };
            let mut output = vec![0u8; output_bytes as usize];
            let parameters = match algorithm {
                "pbkdf2-sha256" | "pbkdf2-sha512" => {
                    let iterations = input
                        .get("iterations")
                        .and_then(Value::as_u64)
                        .unwrap_or(100_000);
                    if !(10_000..=500_000).contains(&iterations) {
                        return Err("pbkdf2_iterations_out_of_range".into());
                    }
                    if algorithm == "pbkdf2-sha256" {
                        pbkdf2::pbkdf2_hmac::<Sha256>(bytes, &salt, iterations as u32, &mut output);
                    } else {
                        pbkdf2::pbkdf2_hmac::<Sha512>(bytes, &salt, iterations as u32, &mut output);
                    }
                    json!({"iterations":iterations,"output_bytes":output_bytes})
                }
                "scrypt" => {
                    let log_n = input
                        .get("scrypt_log_n")
                        .and_then(Value::as_u64)
                        .unwrap_or(14);
                    if !(10..=15).contains(&log_n) {
                        return Err("scrypt_parameters_out_of_range".into());
                    }
                    openssl3::scrypt(bytes, &salt, log_n as u32, &mut output)?;
                    json!({"log_n":log_n,"n":1_u64<<log_n,"r":8,"p":1,"output_bytes":output_bytes})
                }
                "argon2id" => {
                    let memory_kib = input
                        .get("memory_kib")
                        .and_then(Value::as_u64)
                        .unwrap_or(16384);
                    let iterations = input.get("iterations").and_then(Value::as_u64).unwrap_or(2);
                    let parallelism = input
                        .get("parallelism")
                        .and_then(Value::as_u64)
                        .unwrap_or(1);
                    if !(8192..=32768).contains(&memory_kib)
                        || !(1..=3).contains(&iterations)
                        || !(1..=4).contains(&parallelism)
                    {
                        return Err("argon2_parameters_out_of_range".into());
                    }
                    let params = Params::new(
                        memory_kib as u32,
                        iterations as u32,
                        parallelism as u32,
                        Some(output_bytes as usize),
                    )
                    .map_err(|_| "invalid_argon2_parameters")?;
                    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                        .hash_password_into(bytes, &salt, &mut output)
                        .map_err(|_| "argon2_failed")?;
                    json!({"memory_kib":memory_kib,"iterations":iterations,"parallelism":parallelism,"output_bytes":output_bytes})
                }
                _ => return Err("unsupported_kdf_algorithm".into()),
            };
            json!({"family":family,"algorithm":algorithm,"encoding":encoding,
                "value":encode(&output,encoding)?,"salt_hex":crate::hex(&salt),"parameters":parameters})
        }
        _ => return Err("unsupported_crypto_family".into()),
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_known_vector() {
        let answer = compute(&json!({"family":"hash","algorithm":"sha256","text":"abc"})).unwrap();
        assert_eq!(
            answer["value"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn hash_empty_text_known_vector() {
        let answer = compute(&json!({"family":"hash","algorithm":"sha256","text":""})).unwrap();
        assert_eq!(
            answer["value"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
    #[test]
    fn hmac_sha256_known_vector() {
        let answer=compute(&json!({"family":"hmac","algorithm":"hmac-sha256","text":"The quick brown fox jumps over the lazy dog","key":"key"})).unwrap();
        assert_eq!(
            answer["value"],
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }
    #[test]
    fn pbkdf2_is_deterministic_given_explicit_salt() {
        let args = json!({"family":"kdf","algorithm":"pbkdf2-sha256","text":"password","salt_hex":"00112233445566778899aabbccddeeff","iterations":10000});
        let a = compute(&args).unwrap();
        let b = compute(&args).unwrap();
        assert_eq!(a["value"], b["value"]);
        assert_eq!(a["salt_hex"], args["salt_hex"]);
    }
    #[test]
    fn verify_known_sha256_and_tampering() {
        let source = json!({"family":"hash","algorithm":"sha256","text":"abc"});
        let original = compute(&source).unwrap()["value"]
            .as_str()
            .unwrap()
            .to_owned();
        let ok = compute(&json!({"family":"hash","algorithm":"sha256","text":"abc",
            "verify":true,"expected":original}))
        .unwrap();
        assert_eq!(ok["verified"], true);
        assert!(ok.get("value").is_none());
        let bad = compute(
            &json!({"family":"hash","algorithm":"sha256","text":"not abc",
            "verify":true,"expected":original}),
        )
        .unwrap();
        assert_eq!(bad["verified"], false);
    }
    #[test]
    fn verify_hmac_base64url_and_modified_key() {
        let v = compute(
            &json!({"family":"hmac","algorithm":"hmac-sha256", "text":"abc",
            "key":"correct", "encoding":"base64url"}),
        )
        .unwrap();
        let digest = v["value"].as_str().unwrap();
        let ok = compute(
            &json!({"family":"hmac","algorithm":"hmac-sha256", "text":"abc",
            "key":"correct", "encoding":"base64url","verify":true,"expected":digest}),
        )
        .unwrap();
        assert_eq!(ok["verified"], true);
        let wrong = compute(
            &json!({"family":"hmac","algorithm":"hmac-sha256", "text":"abc",
            "key":"wrong", "encoding":"base64url","verify":true,"expected":digest}),
        )
        .unwrap();
        assert_eq!(wrong["verified"], false);
    }
    #[test]
    fn verify_pbkdf2_requires_matching_salt_and_parameters() {
        let settings = json!({"family":"kdf","algorithm":"pbkdf2-sha256","text":"password",
            "salt_hex":"00112233445566778899aabbccddeeff","iterations":10000,"output_bytes":32});
        let output = compute(&settings).unwrap();
        let mut request = settings.clone();
        request["verify"] = json!(true);
        request["expected"] = output["value"].clone();
        assert_eq!(compute(&request).unwrap()["verified"], true);
        request["text"] = json!("incorrect");
        assert_eq!(compute(&request).unwrap()["verified"], false);
        request["text"] = json!("password");
        request["salt_hex"] = json!("");
        assert!(compute(&request).unwrap_err().contains("original_salt"));
        request["salt_hex"] = json!("00112233445566778899aabbccddeeff");
        request["output_bytes"] = json!(64);
        assert!(compute(&request).unwrap_err().contains("length_mismatch"));
    }
    #[test]
    fn verification_rejects_malformed_expected_and_unsupported_family() {
        for (family, encoding, expected) in [
            ("hash", "hex", "zz"),
            ("hash", "base64", "?"),
            ("hash", "base64url", "!"),
            ("hash", "hex", "ff"),
        ] {
            let request = json!({"family":family,"algorithm":"sha256","text":"abc",
                "verify":true,"encoding":encoding,"expected":expected});
            assert!(compute(&request).is_err());
        }
        assert!(compute(&json!({"family":"invalid","verify":true,"expected":"a"})).is_err());
    }
    #[test]
    fn rejects_unbounded_work_and_bad_input() {
        for args in [
            json!({"family":"hash","algorithm":"md5","text":"abc"}),
            json!({"family":"hmac","algorithm":"hmac-sha256","text":"abc"}),
            json!({"family":"kdf","algorithm":"argon2id","text":"pw","memory_kib":524288}),
            json!({"family":"kdf","algorithm":"pbkdf2-sha256","text":"pw","iterations":100000000}),
            json!({"family":"kdf","algorithm":"argon2id","text":"pw","salt_hex":"XXXX"}),
        ] {
            assert!(compute(&args).is_err());
        }
    }
    #[test]
    fn sha3_known_vectors_and_verification() {
        for (bits,expected) in [
            ("sha3-256","3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
            ("sha3-512","b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")]
        {
            let v=compute(&json!({"family":"hash","algorithm":bits,"text":"abc"})).unwrap();
            assert_eq!(v["value"],expected);
            let verify=compute(&json!({"family":"hash","algorithm":bits,"text":"abc","verify":true,"expected":expected})).unwrap();
            assert_eq!(verify["verified"],true);
        }
    }
    #[test]
    fn scrypt_vector_and_original_salt_verification() {
        // OpenSSL and Python hashlib reference vector: N=1024,r=8,p=1.
        let args = json!({"family":"kdf","algorithm":"scrypt","text":"password",
            "salt_hex":"00112233445566778899aabbccddeeff","scrypt_log_n":10,"output_bytes":32});
        let calculated = compute(&args).unwrap();
        assert_eq!(
            calculated["value"],
            "f1ce526861012b22e90e9955c97e23060f9d0068c2bd73f6ffc32b5f73294a1e"
        );
        let mut request = args.clone();
        request["verify"] = json!(true);
        request["expected"] = calculated["value"].clone();
        assert_eq!(compute(&request).unwrap()["verified"], true);
        request["text"] = json!("wrong");
        assert_eq!(compute(&request).unwrap()["verified"], false);
        request["salt_hex"] = json!("");
        assert!(compute(&request).unwrap_err().contains("original_salt"));
    }
    #[test]
    fn scrypt_rejects_abusive_costs() {
        for exponent in [0, 9, 16, 40, u64::MAX] {
            assert!(compute(
                &json!({"family":"kdf","algorithm":"scrypt","text":"password",
                "scrypt_log_n":exponent,"salt_hex":"0011223344556677"})
            )
            .is_err());
        }
    }
}
