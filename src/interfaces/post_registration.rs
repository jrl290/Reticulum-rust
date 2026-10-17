//! Signed registration at a PHP node: the bytes the gateway signs and the
//! session token it reads back.
//!
//! Normative: Reticulum-post `REGISTRATION-STAGE1.md` §4.2 and §5. These are
//! the same bytes and the same sealed token as a browser's (Retichat-js
//! `signRegistration`, `decryptSessionToken`): a gateway signs the fields
//! its unsigned registration already sends. `PostInterface::register_with_remote`
//! drives them. Read `../../DESIGN_PRINCIPLES.md` first.

use crate::identity::Identity;
use serde_json::Value;

/// §4.2: the registration domain. `lp` of it starts `001a`.
pub(crate) const REGISTER_DOMAIN: &[u8] = b"reticulum-post/register/v1";
/// §3: nonce(16) || HMAC-SHA256(32).
pub(crate) const CHALLENGE_LEN: usize = 48;

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Lower-case hex of exactly `len` characters.
pub(crate) fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Decode lower-case hex of any even length; anything else is `None`.
pub(crate) fn from_lower_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !is_lower_hex(s, s.len()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// `lp(x) = u16be(len(x)) || x`.
fn lp(out: &mut Vec<u8>, field: &[u8]) -> Result<(), String> {
    let len = u16::try_from(field.len())
        .map_err(|_| format!("a signed field is {} bytes, more than lp() can carry", field.len()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// §4.2: the bytes a registration signs, read from the JSON body it is sent
/// in, as the PHP node reads them (`RegistrationProtocol::signedBytes`):
/// `challenge` exactly as the node gave it, an absent or null optional field
/// as `lp("")`. The gateway signs the very value it sends, so the body and
/// the signature cannot disagree.
pub(crate) fn registration_signed_bytes(challenge: &[u8], public_key: &[u8], body: &Value) -> Result<Vec<u8>, String> {
    let md = &body["metadata"];
    let text = |v: &Value, what: &str| v.as_str().map(str::to_string).ok_or_else(|| format!("{} is not a string", what));
    let optional = |key: &str| md[key].as_str().unwrap_or("").to_string();
    let name = text(&body["name"], "name")?;
    let bitrate = body["bitrate"].as_u64().ok_or("bitrate is not an unsigned integer")?;
    let mtu = body["mtu"].as_u64().and_then(|m| u32::try_from(m).ok()).ok_or("mtu is not a u32")?;
    let client = text(&md["client"], "metadata.client")?;
    let mode = md["mode"].as_u64().and_then(|m| u8::try_from(m).ok()).ok_or("metadata.mode is not a u8")?;
    let (transport, peer_url) = (optional("transport"), optional("peer_url"));
    let (peer_interface_id, peer_session_token) = (optional("peer_interface_id"), optional("peer_session_token"));

    let mut out = Vec::with_capacity(256);
    for field in [
        REGISTER_DOMAIN,
        challenge,
        public_key,
        name.as_bytes(),
        &bitrate.to_be_bytes()[..],
        &mtu.to_be_bytes()[..],
        client.as_bytes(),
        &[mode][..],
        transport.as_bytes(),
        peer_url.as_bytes(),
        peer_interface_id.as_bytes(),
        peer_session_token.as_bytes(),
    ] {
        lp(&mut out, field)?;
    }
    Ok(out)
}

/// §5: RNS `Identity.decrypt` of `session_token_encrypted`; the plaintext
/// MUST be 64 lower-case hex. There is no plaintext token to fall back to.
pub(crate) fn decrypt_session_token(encrypted_hex: &str, identity: &Identity) -> Result<String, String> {
    let blob = from_lower_hex(encrypted_hex).ok_or("session_token_encrypted is not lower-case hex")?;
    let plaintext = identity
        .clone()
        .decrypt(&blob)
        .map_err(|e| format!("session_token_encrypted does not decrypt with this identity: {}", e))?;
    let token = String::from_utf8(plaintext).map_err(|_| "the decrypted session token is not UTF-8".to_string())?;
    if !is_lower_hex(&token, 64) {
        return Err("the decrypted session token is not 64 lower-case hex".to_string());
    }
    Ok(token)
}

#[cfg(test)]
pub(crate) mod vectors {
    //! Stage 1's shared vectors, pinned through the gateway's own code.
    //!
    //! `tests/fixtures/registration_vectors.json` is a verbatim copy of
    //! Reticulum-post `php/tests/vectors/registration_vectors.json` (main
    //! d27c476, format 6), the file the PHP suite and Retichat-js
    //! (`registration_vectors.json`) test against. Never edit it by hand:
    //! copy it again and update `FIXTURE_SHA256`.
    use super::*;

    pub(crate) const FIXTURE: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/registration_vectors.json"));
    /// The SHA-256 Retichat-js `registration_vectors.test.mjs` pins too.
    const FIXTURE_SHA256: &str = "7d2bcfee1742a6421a05e2b212c04182cc94247d53128ad91d35139fb07304ef";

    pub(crate) fn doc() -> Value {
        serde_json::from_str(FIXTURE).expect("the vector file is JSON")
    }

    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        from_lower_hex(s).unwrap_or_else(|| panic!("not lower-case hex: {s}"))
    }

    pub(crate) fn identity(doc: &Value, name: &str) -> Identity {
        let prv = doc["identities"][name]["private_key_hex"].as_str().expect("a private key");
        Identity::from_bytes(&unhex(prv)).expect("a valid identity")
    }

    pub(crate) fn registration<'a>(doc: &'a Value, id: &str) -> &'a Value {
        doc["registrations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("no registration vector {id}"))
    }

    pub(crate) fn challenge<'a>(doc: &'a Value, id: &str) -> &'a Value {
        doc["challenges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("no challenge vector {id}"))
    }

    /// The four registrations a Stage 1 PHP node signs the same way: the
    /// browser's two (what the PHP and JS suites pin) and the gateway's two.
    const SIGNED: [&str; 4] = ["browser-first", "browser-reregister", "gateway-wake", "gateway-poll"];

    #[test]
    fn the_fixture_is_the_shared_stage1_copy() {
        use sha2::{Digest, Sha256};
        assert_eq!(to_hex(&Sha256::digest(FIXTURE.as_bytes())), FIXTURE_SHA256);
        assert_eq!(doc()["format_version"], 6);
        assert_eq!(doc()["constants"]["register_domain_hex"].as_str(), Some(to_hex(REGISTER_DOMAIN).as_str()));
    }

    #[test]
    fn lp_matches_the_vectors() {
        for ex in doc()["lp_examples"].as_array().unwrap() {
            let input = match ex["input_utf8"].as_str() {
                Some(text) => text.as_bytes().to_vec(),
                None => unhex(ex["input_hex"].as_str().unwrap()),
            };
            let mut out = Vec::new();
            lp(&mut out, &input).unwrap();
            assert_eq!(to_hex(&out), ex["output_hex"].as_str().unwrap());
        }
        assert!(lp(&mut Vec::new(), &vec![0u8; 65536]).is_err(), "lp() carries at most 65535 bytes");
    }

    /// §4.2: the gateway's bytes, read from each vector's request body, are
    /// the vector's `signed_bytes_hex` byte for byte, and its signature over
    /// them (Ed25519 is deterministic) is the vector's `signature_hex`.
    #[test]
    fn signed_bytes_and_signature_match_every_signed_registration_vector() {
        let doc = doc();
        for id in SIGNED {
            let v = registration(&doc, id);
            let body = &v["request_body"];
            let reg = &body["registration"];
            let signed = registration_signed_bytes(
                &unhex(reg["challenge"].as_str().unwrap()),
                &unhex(reg["public_key"].as_str().unwrap()),
                body,
            )
            .unwrap();
            assert_eq!(to_hex(&signed), v["signed_bytes_hex"].as_str().unwrap(), "{id}: signed bytes");
            let id_key = identity(&doc, v["identity"].as_str().unwrap());
            assert_eq!(to_hex(&id_key.sign(&signed)), v["signature_hex"].as_str().unwrap(), "{id}: signature");
            assert_eq!(reg["signature"], v["signature_hex"], "{id}: the body carries that signature");
        }
    }

    /// Each signed field changes the bytes: a gateway's peer fields and its
    /// transport are covered, so none can be swapped under its signature.
    #[test]
    fn every_signed_field_is_covered() {
        let doc = doc();
        let v = registration(&doc, "gateway-wake");
        let body = &v["request_body"];
        let reg = &body["registration"];
        let (c, k) = (unhex(reg["challenge"].as_str().unwrap()), unhex(reg["public_key"].as_str().unwrap()));
        let base = registration_signed_bytes(&c, &k, body).unwrap();
        let edits: [(&str, &str, Value); 9] = [
            ("", "name", Value::from("RNS PostInterface (other)")),
            ("", "bitrate", Value::from(10_000_001u64)),
            ("", "mtu", Value::from(501u64)),
            ("metadata", "client", Value::from("rns-post-interface")),
            ("metadata", "mode", Value::from(1u64)),
            ("metadata", "transport", Value::from("http-exchange")),
            ("metadata", "peer_url", Value::from("http://other.example.net:4371")),
            ("metadata", "peer_interface_id", Value::from("00000000000000000000000000000000")),
            ("metadata", "peer_session_token", Value::from("00")),
        ];
        for (parent, key, value) in edits {
            let mut edited = body.clone();
            let target = if parent.is_empty() { &mut edited } else { &mut edited[parent] };
            target[key] = value;
            assert_ne!(registration_signed_bytes(&c, &k, &edited).unwrap(), base, "{parent}.{key} is signed");
        }
        // Not signed and never acted on (§4.1): `implementation`.
        let mut edited = body.clone();
        edited["metadata"]["implementation"] = Value::from("other");
        assert_eq!(registration_signed_bytes(&c, &k, &edited).unwrap(), base);
    }

    /// §5: the token PHP's `RegistrationProtocol::encryptToken` sealed in
    /// each vector decrypts with the identity it was sealed to, to the
    /// vector's plaintext; the response example carries the same blob.
    #[test]
    fn the_sealed_token_of_every_signed_registration_vector_decrypts() {
        let doc = doc();
        for id in SIGNED {
            let v = registration(&doc, id);
            let enc = &v["encrypted_token"];
            let blob = enc["session_token_encrypted_hex"].as_str().unwrap();
            assert_eq!(v["response_example"]["session_token_encrypted"].as_str(), Some(blob), "{id}");
            let id_key = identity(&doc, v["identity"].as_str().unwrap());
            assert_eq!(decrypt_session_token(blob, &id_key).as_deref(), Ok(enc["plaintext_utf8"].as_str().unwrap()), "{id}");
        }
    }

    #[test]
    fn a_token_that_does_not_decrypt_is_refused() {
        let doc = doc();
        for t in doc["tokens_negative"].as_array().unwrap() {
            let id_key = identity(&doc, t["identity"].as_str().unwrap());
            assert!(decrypt_session_token(t["session_token_encrypted_hex"].as_str().unwrap(), &id_key).is_err(), "{}", t["id"]);
        }
        let gateway = identity(&doc, "gateway");
        assert!(decrypt_session_token("not hex", &gateway).is_err());
        assert!(decrypt_session_token("ABCD", &gateway).is_err(), "upper-case hex is refused");
        // A blob that decrypts but whose plaintext is not 64 lower-case hex.
        let sealed = gateway.encrypt(b"short").unwrap();
        assert!(decrypt_session_token(&to_hex(&sealed), &gateway).is_err());
    }
}
