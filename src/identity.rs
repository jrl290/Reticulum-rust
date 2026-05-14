// RNS::Identity equivalent

use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;
use x25519_dalek::{StaticSecret as X25519PrivateKey, PublicKey as X25519PublicKey};
use ed25519_dalek::{SecretKey as Ed25519PrivateKey, PublicKey as Ed25519PublicKey, Signature, Verifier};
use hkdf::Hkdf;
use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use once_cell::sync::Lazy;
use std::sync::Mutex;
use crate::log;
use crate::hexrep;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

// Constants
pub const CURVE: &str = "Curve25519";
pub const KEYSIZE: usize = 512; // bits (256 for encryption + 256 for signing)
pub const RATCHETSIZE: usize = 256; // bits
pub const TOKEN_OVERHEAD: usize = 48;
pub const AES128_BLOCKSIZE: usize = 16;
const RATCHET_EXPIRY: u64 = 60 * 60 * 24 * 30; // seconds (30 days)

pub const HASHLENGTH: usize = 256;
pub const SIGLENGTH: usize = KEYSIZE;
pub const NAME_HASH_LENGTH: usize = 80;
pub const TRUNCATED_HASHLENGTH: usize = crate::reticulum::TRUNCATED_HASHLENGTH;

static KNOWN_RATCHETS: Lazy<Mutex<HashMap<Vec<u8>, RatchetEntry>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static RATCHET_PERSIST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static KNOWN_DESTINATIONS: Lazy<Mutex<HashMap<Vec<u8>, KnownDestination>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static KNOWN_DESTINATIONS_LOADED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

/// Token implementation - Modified Fernet without VERSION/TIMESTAMP overhead
pub struct Token {
    signing_key: Vec<u8>,
    encryption_key: Vec<u8>,
}

impl Token {
    /// Create a new Token from a key (32 bytes for AES-128, 64 bytes for AES-256)
    pub fn new(key: &[u8]) -> Result<Self, String> {
        match key.len() {
            32 => {
                // AES-128-CBC: first 16 bytes signing, next 16 encryption
                Ok(Token {
                    signing_key: key[..16].to_vec(),
                    encryption_key: key[16..32].to_vec(),
                })
            }
            64 => {
                // AES-256-CBC: first 32 bytes signing,  next 32 encryption
                Ok(Token {
                    signing_key: key[..32].to_vec(),
                    encryption_key: key[32..64].to_vec(),
                })
            }
            _ => Err(format!("Token key must be 32 or 64 bytes, not {}", key.len())),
        }
    }

    /// Encrypt data with AES-256-CBC and HMAC
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        // Generate random IV
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);

        // Encrypt
        let cipher = Aes256CbcEnc::new_from_slices(&self.encryption_key, &iv)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        let mut buf = vec![0u8; plaintext.len() + AES128_BLOCKSIZE];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ciphertext = cipher.encrypt_padded_mut::<block_padding::Pkcs7>(&mut buf, plaintext.len())
            .map_err(|e| format!("Encryption failed: {}", e))?
            .to_vec();

        // Build token: IV + ciphertext
        let mut signed_parts = iv.to_vec();
        signed_parts.extend_from_slice(&ciphertext);

        // Add HMAC
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|e| format!("HMAC error: {}", e))?;
        mac.update(&signed_parts);
        let hmac_result = mac.finalize().into_bytes();

        signed_parts.extend_from_slice(&hmac_result);
        Ok(signed_parts)
    }

    /// Decrypt and verify AES-256-CBC token
    pub fn decrypt(&self, token: &[u8]) -> Result<Vec<u8>, String> {
        if token.len() <= 32 {
            return Err(format!("Cannot verify HMAC on token of only {} bytes", token.len()));
        }

        // Verify HMAC
        let received_hmac = &token[token.len() - 32..];
        let signed_parts = &token[..token.len() - 32];

        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|e| format!("HMAC error: {}", e))?;
        mac.update(signed_parts);
        let computed_hmac = mac.finalize().into_bytes();

        if computed_hmac.as_slice() != received_hmac {
            return Err("Token HMAC was invalid".to_string());
        }

        // Extract IV and ciphertext
        let iv = &token[..16];
        let ciphertext = &token[16..token.len() - 32];

        // Decrypt
        let cipher = Aes256CbcDec::new_from_slices(&self.encryption_key, iv)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        let mut buffer = ciphertext.to_vec();
        let plaintext = cipher.decrypt_padded_mut::<block_padding::Pkcs7>(&mut buffer)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(plaintext.to_vec())
    }
}

/// Calculates the SHA256 hash of the given data.
pub fn full_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Calculates a truncated SHA256 hash of the given data.
pub fn truncated_hash(data: &[u8]) -> Vec<u8> {
    let full = full_hash(data);
    let truncated_length = crate::reticulum::TRUNCATED_HASHLENGTH / 8;
    full[..truncated_length].to_vec()
}

/// Generates a random hash value (truncated, 16 bytes).
pub fn get_random_hash() -> Vec<u8> {
    let mut buffer = vec![0u8; crate::reticulum::TRUNCATED_HASHLENGTH / 8];
    OsRng.fill_bytes(&mut buffer);
    truncated_hash(&buffer)
}

/// Ratchet data stored on disk
#[derive(Serialize, Deserialize, Clone)]
struct RatchetEntry {
    public_key: Vec<u8>,
    timestamp: u64,
}

fn unix_now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn known_ratchet_max_age() -> u64 {
    let receiver_window = (crate::destination::RATCHET_COUNT.saturating_sub(1) as u64)
        .saturating_mul(crate::destination::RATCHET_INTERVAL);
    receiver_window.min(RATCHET_EXPIRY)
}

fn ratchet_entry_fresh(entry: &RatchetEntry, now: u64) -> bool {
    now <= entry.timestamp.saturating_add(known_ratchet_max_age())
}

/// Known destination data
#[derive(Serialize, Deserialize, Clone)]
struct KnownDestination {
    public_key: Vec<u8>,
    app_data: Option<Vec<u8>>,
}

/// Cryptographic identity for encryption, signing, and authentication
pub struct Identity {
    // X25519 keys for encryption (ECDH)
    encryption_prv_key: Option<X25519PrivateKey>,
    encryption_pub_key: Option<X25519PublicKey>,
    
    // Ed25519 keys for signing
    signing_prv_key: Option<Ed25519PrivateKey>,
    signing_pub_key: Option<Ed25519PublicKey>,
    
    // Hash of public keys
    pub hash: Option<Vec<u8>>,
    
    // Ratchet keys for forward secrecy
    ratchets: HashMap<Vec<u8>, Vec<u8>>,
    
    // Storage paths
    storage_path: Option<PathBuf>,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        let mut cloned = if let Ok(private_key) = self.get_private_key() {
            Identity::from_bytes(&private_key).unwrap_or_else(|_| Identity::new(true))
        } else if let Ok(public_key) = self.get_public_key() {
            Identity::from_public_key(&public_key).unwrap_or_else(|_| Identity::new(false))
        } else {
            Identity::new(false)
        };
        cloned.ratchets = self.ratchets.clone();
        cloned.storage_path = self.storage_path.clone();
        cloned
    }
}

impl Identity {
    // ===== Static hash utilities =====
    
    pub fn get_random_hash() -> Vec<u8> {
        get_random_hash()
    }

    pub fn full_hash(data: &[u8]) -> Vec<u8> {
        full_hash(data)
    }

    pub fn truncated_hash(data: &[u8]) -> Vec<u8> {
        truncated_hash(data)
    }

    // ===== Constructors =====
    
    /// Create a new identity.
    pub fn new(create_keys: bool) -> Self {
        let (encryption_prv_key, encryption_pub_key) = if create_keys {
            let mut enc_key_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut enc_key_bytes);
            let enc_prv = X25519PrivateKey::from(enc_key_bytes);
            let enc_pub = X25519PublicKey::from(&enc_prv);
            (Some(enc_prv), Some(enc_pub))
        } else {
            (None, None)
        };

        let (signing_prv_key, signing_pub_key) = if create_keys {
            let mut sign_key_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut sign_key_bytes);
            let secret = Ed25519PrivateKey::from_bytes(&sign_key_bytes)
                .expect("Failed to create Ed25519 private key");
            let public = Ed25519PublicKey::from(&secret);
            (Some(secret), Some(public))
        } else {
            (None, None)
        };

        let mut identity = Identity {
            encryption_prv_key,
            encryption_pub_key,
            signing_prv_key,
            signing_pub_key,
            hash: None,
            ratchets: HashMap::new(),
            storage_path: None,
        };

        if create_keys {
            identity.update_hashes();
        }
        identity
    }

    /// Generate new encryption and signing keys
    pub fn create_keys(&mut self) {
        let mut enc_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut enc_key_bytes);
        let enc_prv = X25519PrivateKey::from(enc_key_bytes);
        let enc_pub = X25519PublicKey::from(&enc_prv);
        self.encryption_prv_key = Some(enc_prv);
        self.encryption_pub_key = Some(enc_pub);
        
        let mut sign_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut sign_key_bytes);
        let secret = Ed25519PrivateKey::from_bytes(&sign_key_bytes)
            .expect("Failed to create Ed25519 private key");
        let public = Ed25519PublicKey::from(&secret);
        self.signing_prv_key = Some(secret);
        self.signing_pub_key = Some(public);
        
        self.update_hashes();
    }

    pub fn load_private_key(&mut self, prv_bytes: &[u8]) -> Result<(), String> {
        if prv_bytes.len() != KEYSIZE / 8 {
            return Err(format!("Private key must be {} bytes", KEYSIZE / 8));
        }

        let enc_key_bytes: [u8; 32] = prv_bytes[..32]
            .try_into()
            .map_err(|_| "Invalid encryption key".to_string())?;
        let enc_prv = X25519PrivateKey::from(enc_key_bytes);
        let enc_pub = X25519PublicKey::from(&enc_prv);

        let sign_key_bytes: [u8; 32] = prv_bytes[32..64]
            .try_into()
            .map_err(|_| "Invalid signing key".to_string())?;
        let sign_prv = Ed25519PrivateKey::from_bytes(&sign_key_bytes)
            .map_err(|e| format!("Invalid Ed25519 key: {}", e))?;
        let sign_pub = Ed25519PublicKey::from(&sign_prv);

        self.encryption_prv_key = Some(enc_prv);
        self.encryption_pub_key = Some(enc_pub);
        self.signing_prv_key = Some(sign_prv);
        self.signing_pub_key = Some(sign_pub);
        self.update_hashes();
        Ok(())
    }

    pub fn load_public_key(&mut self, pub_bytes: &[u8]) -> Result<(), String> {
        if pub_bytes.len() != KEYSIZE / 8 {
            return Err(format!("Public key must be {} bytes", KEYSIZE / 8));
        }

        let enc_pub_bytes: [u8; 32] = pub_bytes[..32]
            .try_into()
            .map_err(|_| "Invalid encryption public key".to_string())?;
        let enc_pub = X25519PublicKey::from(enc_pub_bytes);

        let sign_pub_bytes: [u8; 32] = pub_bytes[32..64]
            .try_into()
            .map_err(|_| "Invalid signing public key".to_string())?;
        let sign_pub = Ed25519PublicKey::from_bytes(&sign_pub_bytes)
            .map_err(|e| format!("Invalid Ed25519 public key: {}", e))?;

        self.encryption_prv_key = None;
        self.encryption_pub_key = Some(enc_pub);
        self.signing_prv_key = None;
        self.signing_pub_key = Some(sign_pub);
        self.update_hashes();
        Ok(())
    }

    /// Create an identity from existing key bytes
    pub fn from_bytes(prv_bytes: &[u8]) -> Result<Self, String> {
        let mut identity = Identity::new(false);
        identity.load_private_key(prv_bytes)?;
        Ok(identity)
    }

    /// Create an identity from public key bytes (64 bytes: 32 X25519 + 32 Ed25519)
    pub fn from_public_key(pub_bytes: &[u8]) -> Result<Self, String> {
        let mut identity = Identity::new(false);
        identity.load_public_key(pub_bytes)?;
        Ok(identity)
    }

    /// Load identity from file
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let data = fs::read(path)
            .map_err(|e| format!("Failed to read identity file: {}", e))?;
        Self::from_bytes(&data)
    }

    /// Save identity to file
    pub fn to_file(&self, path: &Path) -> Result<(), String> {
        let prv_bytes = self.get_private_key()?;
        fs::write(path, prv_bytes)
            .map_err(|e| format!("Failed to write identity file: {}", e))
    }

    // ===== Key accessors =====
    
    /// Get private key bytes (64 bytes: 32 X25519 + 32 Ed25519)
    pub fn get_private_key(&self) -> Result<Vec<u8>, String> {
        let mut key = Vec::with_capacity(64);
        let enc_prv = self.encryption_prv_key.as_ref().ok_or("Identity has no private key")?;
        let sign_prv = self.signing_prv_key.as_ref().ok_or("Identity has no private key")?;
        key.extend_from_slice(&enc_prv.to_bytes());
        key.extend_from_slice(sign_prv.as_bytes());
        Ok(key)
    }

    /// Get public key bytes (64 bytes: 32 X25519 + 32 Ed25519)
    pub fn get_public_key(&self) -> Result<Vec<u8>, String> {
        let mut key = Vec::with_capacity(64);
        let enc_pub = self.encryption_pub_key.as_ref().ok_or("Identity has no public key")?;
        let sign_pub = self.signing_pub_key.as_ref().ok_or("Identity has no public key")?;
        key.extend_from_slice(enc_pub.as_bytes());
        key.extend_from_slice(sign_pub.as_bytes());
        Ok(key)
    }

    /// Update hash based on current public keys
    fn update_hashes(&mut self) {
        if let Ok(pub_key) = self.get_public_key() {
            self.hash = Some(truncated_hash(&pub_key));
        } else {
            self.hash = None;
        }
    }

    // ===== Encryption/Decryption =====
    
    /// Encrypt plaintext for this identity
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        self.encrypt_with_ratchet(plaintext, None)
    }

    /// Encrypt plaintext for this identity, optionally using a ratchet public key
    pub fn encrypt_with_ratchet(&self, plaintext: &[u8], ratchet: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let salt = self.hash.as_ref().ok_or("Identity hash not available")?;
        // Generate ephemeral X25519 keypair
        let mut ephemeral_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut ephemeral_bytes);
        let ephemeral_prv = X25519PrivateKey::from(ephemeral_bytes);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral_prv);

        // Use ratchet public key if provided, otherwise use identity's public key
        let target_pub = if let Some(ratchet_pub_bytes) = ratchet {
            let ratchet_arr: [u8; 32] = ratchet_pub_bytes.try_into()
                .map_err(|_| "Invalid ratchet public key length")?;
            X25519PublicKey::from(ratchet_arr)
        } else {
            *self.encryption_pub_key.as_ref().ok_or("Identity has no public key")?
        };

        // Perform ECDH
        let shared_secret = ephemeral_prv.diffie_hellman(&target_pub);
        
        // Derive encryption key using HKDF
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), shared_secret.as_bytes());
        let mut derived_key = [0u8; 64];
        hkdf.expand(b"", &mut derived_key)
            .map_err(|_| "HKDF expansion failed".to_string())?;
        
        // Log encryption attempt (ratchet selection, ephemeral key, salt hash)
        let ratchet_info = if ratchet.is_some() {
            format!("ratchet[{}]", hexrep(&ratchet.unwrap()[..16], false))
        } else {
            "main_key".to_string()
        };
        crate::log(&format!("[ENCRYPT] {} salt={} ephemeral_pub={}", 
            ratchet_info,
            hexrep(salt, false),
            hexrep(ephemeral_pub.as_bytes(), false)
        ), crate::LOG_DEBUG, false, false);
        
        let token = Token::new(&derived_key)?;
        let ciphertext = token.encrypt(plaintext)?;
                // Log computed HMAC (first 16 bytes of the computed HMAC for debugging)
                // The actual HMAC is the last 32 bytes of ciphertext
                if ciphertext.len() >= 32 {
                    let hmac = &ciphertext[ciphertext.len() - 32..];
                    crate::log(&format!("[ENCRYPT] hmac_first_16={}", hexrep(&hmac[..16], false)), crate::LOG_DEBUG, false, false);
                }
        
        
        // Return: ephemeral_pub (32) + ciphertext
        let mut result = ephemeral_pub.as_bytes().to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt ciphertext encrypted for this identity (supports ratchets)
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        self.decrypt_with_ratchets(ciphertext, None)
    }

    /// Decrypt with optional additional destination ratchet private keys.
    /// `dest_ratchets` is a list of X25519 private key bytes (32 bytes each)
    /// from the destination's ratchet rotation. These are tried before the
    /// identity's own ratchets.
    pub fn decrypt_with_ratchets(&mut self, ciphertext: &[u8], dest_ratchets: Option<&[Vec<u8>]>) -> Result<Vec<u8>, String> {
        if ciphertext.len() <= 32 {
            return Err("Ciphertext too short".to_string());
        }

        crate::log(&format!("[DECRYPT] ciphertext_len={} identity_hash={} has_prv_key={} dest_ratchets={} identity_ratchets={}",
            ciphertext.len(),
            self.hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or("NONE".to_string()),
            self.encryption_prv_key.is_some(),
            dest_ratchets.map(|r| r.len()).unwrap_or(0),
            self.ratchets.len(),
        ), crate::LOG_NOTICE, false, false);

        // Extract ephemeral public key
        let ephemeral_pub_bytes: [u8; 32] = ciphertext[..32].try_into()
            .map_err(|_| "Invalid ephemeral public key".to_string())?;
        let ephemeral_pub = X25519PublicKey::from(ephemeral_pub_bytes);
        let token_data = &ciphertext[32..];

        // Try destination ratchet keys first (from Destination.ratchets rotation)
        if let Some(ratchets) = dest_ratchets {
            for (idx, ratchet_prv_bytes) in ratchets.iter().enumerate() {
                if ratchet_prv_bytes.len() == 32 {
                    let ratchet_prv = X25519PrivateKey::from(*<&[u8; 32]>::try_from(ratchet_prv_bytes.as_slice()).unwrap());
                    match self.decrypt_with_key(&ratchet_prv, &ephemeral_pub, token_data) {
                        Ok(plaintext) => {
                            crate::log(&format!("[DECRYPT] SUCCESS with dest_ratchet[{}]", idx), crate::LOG_DEBUG, false, false);
                            return Ok(plaintext);
                        }
                        Err(e) => {
                            crate::log(&format!("[DECRYPT] dest_ratchet[{}] failed: {}", idx, e), crate::LOG_DEBUG, false, false);
                        }
                    }
                }
            }
        }

        // Try identity's own ratchet keys
        for (ratchet_id, ratchet_prv_bytes) in &self.ratchets.clone() {
            let ratchet_prv = X25519PrivateKey::from(*<&[u8; 32]>::try_from(ratchet_prv_bytes.as_slice()).unwrap());
            match self.decrypt_with_key(&ratchet_prv, &ephemeral_pub, token_data) {
                Ok(plaintext) => {
                    crate::log(&format!("[DECRYPT] SUCCESS with identity_ratchet[{}]", hexrep(ratchet_id, false)), crate::LOG_DEBUG, false, false);
                    return Ok(plaintext);
                }
                Err(e) => {
                    crate::log(&format!("[DECRYPT] identity_ratchet[{}] failed: {}", hexrep(ratchet_id, false), e), crate::LOG_DEBUG, false, false);
                }
            }
        }

        // Fall back to main encryption key
        let enc_prv = self.encryption_prv_key.as_ref().ok_or("Identity has no private key")?;
        crate::log(&format!("[DECRYPT] trying main key, token_data_len={}", token_data.len()), crate::LOG_NOTICE, false, false);
        match self.decrypt_with_key(enc_prv, &ephemeral_pub, token_data) {
            Ok(plaintext) => {
                crate::log("[DECRYPT] SUCCESS with main key", crate::LOG_DEBUG, false, false);
                Ok(plaintext)
            }
            Err(e) => {
                crate::log(&format!("[DECRYPT] main key failed: {}", e), crate::LOG_NOTICE, false, false);
                Err(e)
            }
        }
    }

    fn decrypt_with_key(
        &self,
        prv_key: &X25519PrivateKey,
        ephemeral_pub: &X25519PublicKey,
        token_data: &[u8]
    ) -> Result<Vec<u8>, String> {
        let salt = self.hash.as_ref().ok_or("Identity hash not available")?;
        // Perform ECDH
        let shared_secret = prv_key.diffie_hellman(ephemeral_pub);

        // NOTE: do NOT log shared_secret, derived_key, or token_data hex.
        // Those values are sufficient to decrypt captured traffic and were
        // previously emitted at LOG_NOTICE — a critical leak for any user
        // who shares a log file. See log audit (2026-04).

        // Derive decryption key using HKDF
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), shared_secret.as_bytes());
        let mut derived_key = [0u8; 64];
        hkdf.expand(b"", &mut derived_key)
            .map_err(|_| "HKDF expansion failed".to_string())?;

        // Decrypt with Token
        let token = Token::new(&derived_key)?;
        token.decrypt(token_data)
    }

    // ===== Signing/Verification =====
    
    /// Sign data with this identity's signing key
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let sign_prv = self.signing_prv_key.as_ref().expect("Identity has no private key");
        let sign_pub = self.signing_pub_key.as_ref().expect("Identity has no public key");
        let mut keypair_bytes = [0u8; 64];
        keypair_bytes[..32].copy_from_slice(sign_prv.as_bytes());
        keypair_bytes[32..].copy_from_slice(sign_pub.as_bytes());
        let kp_secret = ed25519_dalek::Keypair::from_bytes(&keypair_bytes)
            .expect("Failed to reconstruct keypair from bytes");
        let signature = kp_secret.sign(data);
        signature.to_bytes().to_vec()
    }

    /// Verify a signature against this identity's public key
    pub fn validate(&self, signature: &[u8], data: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }

        let sign_pub = match self.signing_pub_key.as_ref() {
            Some(key) => key,
            None => return false,
        };
        
        let sig_bytes: [u8; 64] = match signature.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        
        match Signature::from_bytes(&sig_bytes) {
            Ok(sig) => sign_pub.verify(data, &sig).is_ok(),
            Err(_) => false,
        }
    }

    /// Generate proof for packet authentication
    pub fn prove(&self, packet_hash: &[u8], destination_hash: Option<&[u8]>) -> Vec<u8> {
        let mut data = packet_hash.to_vec();
        if let Some(dest_hash) = destination_hash {
            data.extend_from_slice(dest_hash);
        }
        self.sign(&data)
    }

    // ===== Ratchet Management =====
    
    /// Generate a new ratchet key
    pub fn generate_ratchet(&mut self) -> (Vec<u8>, Vec<u8>) {
        let mut ratchet_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut ratchet_bytes);
        let ratchet_prv = X25519PrivateKey::from(ratchet_bytes);
        let ratchet_pub = X25519PublicKey::from(&ratchet_prv);
        
        let ratchet_id = truncated_hash(ratchet_pub.as_bytes());
        self.ratchets.insert(ratchet_id.clone(), ratchet_bytes.to_vec());
        
        (ratchet_id, ratchet_pub.as_bytes().to_vec())
    }

    pub fn ratchet_public_bytes(ratchet_prv: &[u8]) -> Result<Vec<u8>, String> {
        if ratchet_prv.len() != 32 {
            return Err(format!("Invalid ratchet private key length: {}", ratchet_prv.len()));
        }
        let prv = X25519PrivateKey::from(*<&[u8; 32]>::try_from(ratchet_prv).map_err(|_| "Invalid ratchet key")?);
        let pub_key = X25519PublicKey::from(&prv);
        Ok(pub_key.as_bytes().to_vec())
    }

    pub fn ratchet_id_from_pub(ratchet_pub: &[u8]) -> Vec<u8> {
        full_hash(ratchet_pub)[..(NAME_HASH_LENGTH / 8)].to_vec()
    }

    pub fn remember_ratchet(destination_hash: &[u8], ratchet_pub: &[u8]) -> Result<(), String> {
        if ratchet_pub.len() != 32 {
            return Err(format!("Invalid ratchet public key length: {}", ratchet_pub.len()));
        }

        let now = unix_now_secs();
        let entry = RatchetEntry {
            public_key: ratchet_pub.to_vec(),
            timestamp: now,
        };

        let mut known = KNOWN_RATCHETS.lock().unwrap();
        if let Some(existing) = known.get(destination_hash) {
            if existing.public_key == ratchet_pub && ratchet_entry_fresh(existing, now) {
                return Ok(());
            }
        }

        let ratchet_id = Identity::ratchet_id_from_pub(ratchet_pub);
        log(
            &format!("Remembering ratchet {} for {}", crate::hexrep(&ratchet_id, true), crate::hexrep(destination_hash, true)),
            crate::LOG_EXTREME,
            false,
            false,
        );

        known.insert(destination_hash.to_vec(), entry.clone());
        drop(known);

        if crate::transport::Transport::is_connected_to_shared_instance() {
            return Ok(());
        }

        let destination_hash = destination_hash.to_vec();
        thread::spawn(move || {
            let _lock = RATCHET_PERSIST_LOCK.lock().unwrap();
            let hexhash = crate::hexrep(&destination_hash, false);
            let ratchet_dir = crate::reticulum::storage_path().join("ratchets");
            if fs::create_dir_all(&ratchet_dir).is_err() {
                return;
            }
            let outpath = ratchet_dir.join(format!("{}.out", hexhash));
            let finalpath = ratchet_dir.join(hexhash);
            if let Ok(data) = rmp_serde::to_vec(&entry) {
                if fs::write(&outpath, data).is_ok() {
                    let _ = fs::rename(outpath, finalpath);
                }
            }
        });

        Ok(())
    }

    pub fn get_ratchet(destination_hash: &[u8]) -> Option<Vec<u8>> {
        let now = unix_now_secs();
        {
            let mut known = KNOWN_RATCHETS.lock().unwrap();
            if let Some(entry) = known.get(destination_hash).cloned() {
                if ratchet_entry_fresh(&entry, now) {
                    return Some(entry.public_key);
                }
                known.remove(destination_hash);
            }
        }

        let hexhash = crate::hexrep(destination_hash, false);
        let ratchet_path = crate::reticulum::storage_path().join("ratchets").join(hexhash);
        if !ratchet_path.exists() {
            return None;
        }

        if let Ok(data) = fs::read(&ratchet_path) {
            if let Ok(entry) = rmp_serde::from_slice::<RatchetEntry>(&data) {
                if !ratchet_entry_fresh(&entry, now) {
                    let _ = fs::remove_file(&ratchet_path);
                    return None;
                }
                KNOWN_RATCHETS.lock().unwrap().insert(destination_hash.to_vec(), entry.clone());
                return Some(entry.public_key);
            }
        }

        None
    }

    /// Remember a ratchet key (persist to disk if storage_path is set)
    pub fn remember_ratchet_local(&mut self, ratchet_id: Vec<u8>, ratchet_pub: Vec<u8>) -> Result<(), String> {
        if ratchet_pub.len() != 32 {
            return Err(format!("Invalid ratchet public key length: {}", ratchet_pub.len()));
        }
        
        self.ratchets.insert(ratchet_id.clone(), ratchet_pub.clone());

        if let Some(ref storage_path) = self.storage_path {
            let hash = self.hash.as_ref().ok_or("Identity hash not available")?;
            let ratchet_dir = storage_path.join("ratchets").join(hex::encode(hash));
            fs::create_dir_all(&ratchet_dir)
                .map_err(|e| format!("Failed to create ratchet directory: {}", e))?;

            let entry = RatchetEntry {
                public_key: ratchet_pub,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            };

            let data = rmp_serde::to_vec(&entry)
                .map_err(|e| format!("Failed to serialize ratchet: {}", e))?;
            
            let ratchet_file = ratchet_dir.join(hex::encode(&ratchet_id));
            fs::write(ratchet_file, data)
                .map_err(|e| format!("Failed to write ratchet: {}", e))?;
        }

        Ok(())
    }

    /// Clean expired ratchets
    pub fn clean_ratchets(&mut self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        if let Some(ref storage_path) = self.storage_path {
            let hash = match self.hash.as_ref() {
                Some(hash) => hash,
                None => return,
            };
            let ratchet_dir = storage_path.join("ratchets").join(hex::encode(hash));
            if let Ok(entries) = fs::read_dir(&ratchet_dir) {
                for entry in entries.flatten() {
                    if let Ok(data) = fs::read(entry.path()) {
                        if let Ok(ratchet_entry) = rmp_serde::from_slice::<RatchetEntry>(&data) {
                            if now - ratchet_entry.timestamp > RATCHET_EXPIRY {
                                let _ = fs::remove_file(entry.path());
                                let ratchet_id = truncated_hash(&ratchet_entry.public_key);
                                self.ratchets.remove(&ratchet_id);
                            }
                        }
                    }
                }
            }
        }
    }

    // ===== Known Destinations =====

    fn load_known_destinations_if_needed() {
        let mut loaded = KNOWN_DESTINATIONS_LOADED.lock().unwrap();
        if *loaded {
            return;
        }

        let storage_path = crate::reticulum::storage_path();
        let mut destinations = KNOWN_DESTINATIONS.lock().unwrap();

        if let Ok(map) = Self::load_known_destinations(&storage_path) {
            *destinations = map;
        }

        *loaded = true;
    }

    pub fn remember_destination(destination_hash: &[u8], public_key: &[u8], app_data: Option<Vec<u8>>) -> Result<(), String> {
        Self::load_known_destinations_if_needed();

        let mut destinations = KNOWN_DESTINATIONS.lock().unwrap();
        let entry = destinations.entry(destination_hash.to_vec()).or_insert(KnownDestination {
            public_key: public_key.to_vec(),
            app_data: None,
        });

        if entry.public_key != public_key {
            entry.public_key = public_key.to_vec();
        }

        if app_data.is_some() {
            entry.app_data = app_data;
        }

        let storage_path = crate::reticulum::storage_path();
        Self::save_known_destinations(&destinations, &storage_path)?;
        Ok(())
    }

    pub fn recall(destination_hash: &[u8]) -> Option<Identity> {
        Self::load_known_destinations_if_needed();
        let destinations = KNOWN_DESTINATIONS.lock().unwrap();
        let entry = destinations.get(destination_hash)?;
        Identity::from_public_key(&entry.public_key).ok()
    }

    /// Recall identity by identity hash (not destination hash).
    /// Scans all known destinations for a matching public-key hash — O(n) but
    /// only called on subscribe/fanout paths, not hot paths.
    pub fn recall_from_identity_hash(identity_hash: &[u8]) -> Option<Identity> {
        Self::load_known_destinations_if_needed();
        let destinations = KNOWN_DESTINATIONS.lock().unwrap();
        for entry in destinations.values() {
            if truncated_hash(&entry.public_key) == identity_hash {
                return Identity::from_public_key(&entry.public_key).ok();
            }
        }
        None
    }

    pub fn recall_app_data(destination_hash: &[u8]) -> Option<Vec<u8>> {
        Self::load_known_destinations_if_needed();
        let destinations = KNOWN_DESTINATIONS.lock().unwrap();
        destinations.get(destination_hash).and_then(|entry| entry.app_data.clone())
    }

    pub fn recall_public_key(destination_hash: &[u8]) -> Option<Vec<u8>> {
        Self::load_known_destinations_if_needed();
        let destinations = KNOWN_DESTINATIONS.lock().unwrap();
        destinations.get(destination_hash).map(|entry| entry.public_key.clone())
    }

    /// Test-only: inject a known destination in-memory without disk I/O
    #[cfg(test)]
    pub fn remember_destination_in_memory(destination_hash: &[u8], public_key: &[u8]) {
        let mut destinations = KNOWN_DESTINATIONS.lock().unwrap();
        destinations.insert(destination_hash.to_vec(), KnownDestination {
            public_key: public_key.to_vec(),
            app_data: None,
        });
    }

    /// Test-only: remove a known destination from in-memory store
    #[cfg(test)]
    pub fn forget_destination_in_memory(destination_hash: &[u8]) {
        let mut destinations = KNOWN_DESTINATIONS.lock().unwrap();
        destinations.remove(destination_hash);
    }

    // ===== Known Destinations Storage =====
    
    /// Save known destinations to disk
    fn save_known_destinations(
        destinations: &HashMap<Vec<u8>, KnownDestination>,
        storage_path: &Path,
    ) -> Result<(), String> {
        let known_file = storage_path.join("known_destinations");
        let data = rmp_serde::to_vec(destinations)
            .map_err(|e| format!("Failed to serialize destinations: {}", e))?;
        fs::write(known_file, data)
            .map_err(|e| format!("Failed to write destinations: {}", e))
    }

    /// Load known destinations from disk
    fn load_known_destinations(storage_path: &Path) -> Result<HashMap<Vec<u8>, KnownDestination>, String> {
        let known_file = storage_path.join("known_destinations");
        if !known_file.exists() {
            return Ok(HashMap::new());
        }

        let data = fs::read(known_file)
            .map_err(|e| format!("Failed to read destinations: {}", e))?;

        if let Ok(map) = rmp_serde::from_slice::<HashMap<Vec<u8>, KnownDestination>>(&data) {
            return Ok(map);
        }

        let legacy = rmp_serde::from_slice::<HashMap<Vec<u8>, Vec<u8>>>(&data)
            .map_err(|e| format!("Failed to deserialize destinations: {}", e))?;
        let mut upgraded = HashMap::new();
        for (hash, public_key) in legacy {
            upgraded.insert(
                hash,
                KnownDestination {
                    public_key,
                    app_data: None,
                },
            );
        }
        Ok(upgraded)
    }

    // ===== Announce Validation =====
    
    /// Validate an announce packet
    pub fn validate_announce(
        packet: &[u8],
        destination_hash: Option<&[u8]>,
        public_key: Option<&[u8]>,
        context_flag: u8,
    ) -> bool {
        // Validate announce packet structure and signature
        // Announce structure: public_key + name_hash + random_hash + [ratchet] + signature + [app_data]
        
        if packet.len() < KEYSIZE / 8 + NAME_HASH_LENGTH / 8 + 10 + SIGLENGTH / 8 {
            return false;
        }

        let Some(dest_hash) = destination_hash else {
            return false;
        };

        let Some(pub_key_bytes) = public_key else {
            return false;
        };

        if pub_key_bytes.len() != KEYSIZE / 8 {
            return false;
        }

        // Parse announce components
        let public_key = &packet[..KEYSIZE / 8];
        let name_hash = &packet[KEYSIZE / 8..KEYSIZE / 8 + NAME_HASH_LENGTH / 8];
        let random_hash = &packet[KEYSIZE / 8 + NAME_HASH_LENGTH / 8..KEYSIZE / 8 + NAME_HASH_LENGTH / 8 + 10];
        
        // Check if ratchet is present based on context_flag
        let has_ratchet = context_flag == crate::packet::FLAG_SET;
        
        let (signature, app_data) = if has_ratchet {
            let sig_start = KEYSIZE / 8 + NAME_HASH_LENGTH / 8 + 10 + RATCHETSIZE / 8;
            let sig_end = sig_start + SIGLENGTH / 8;
            if packet.len() < sig_end {
                return false;
            }
            let signature = &packet[sig_start..sig_end];
            let app_data = if packet.len() > sig_end {
                &packet[sig_end..]
            } else {
                &[]
            };
            (signature, app_data)
        } else {
            let sig_start = KEYSIZE / 8 + NAME_HASH_LENGTH / 8 + 10;
            let sig_end = sig_start + SIGLENGTH / 8;
            if packet.len() < sig_end {
                return false;
            }
            let signature = &packet[sig_start..sig_end];
            let app_data = if packet.len() > sig_end {
                &packet[sig_end..]
            } else {
                &[]
            };
            (signature, app_data)
        };

        let ratchet = if has_ratchet {
            let ratchet_start = KEYSIZE / 8 + NAME_HASH_LENGTH / 8 + 10;
            let ratchet_end = ratchet_start + RATCHETSIZE / 8;
            if packet.len() < ratchet_end {
                return false;
            }
            &packet[ratchet_start..ratchet_end]
        } else {
            &[]
        };

        // Reconstruct signed data: destination_hash + public_key + name_hash + random_hash + ratchet + app_data
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(dest_hash);
        signed_data.extend_from_slice(public_key);
        signed_data.extend_from_slice(name_hash);
        signed_data.extend_from_slice(random_hash);
        signed_data.extend_from_slice(ratchet);
        signed_data.extend_from_slice(app_data);

        // Extract Ed25519 public key (bytes 32-64)
        let signing_pub_bytes: [u8; 32] = match pub_key_bytes[32..64].try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };

        let signing_pub = match Ed25519PublicKey::from_bytes(&signing_pub_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig_bytes: [u8; 64] = match signature.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };

        match Signature::from_bytes(&sig_bytes) {
            Ok(sig) => signing_pub.verify(&signed_data, &sig).is_ok(),
            Err(_) => false,
        }
    }

    /// Set storage path for ratchets and known destinations
    pub fn set_storage_path(&mut self, path: PathBuf) {
        self.storage_path = Some(path);
    }
}

pub fn persist_data() {
    // Placeholder for parity; ratchet persistence happens per identity instance.
}

pub fn exit_handler() {
    persist_data();
}

// Simple hex encoding helper
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};

    /// Build the `signed_part` exactly as Python LXMF does:
    ///   hashed_part = dest_hash + source_hash + packed_payload
    ///   message_hash = SHA-256(hashed_part)
    ///   signed_part  = hashed_part + message_hash
    fn make_signed_part(dest_hash: &[u8], source_hash: &[u8], payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut hashed_part = Vec::new();
        hashed_part.extend_from_slice(dest_hash);
        hashed_part.extend_from_slice(source_hash);
        hashed_part.extend_from_slice(payload);

        let message_hash: Vec<u8> = Sha256::digest(&hashed_part).to_vec();

        let mut signed_part = hashed_part.clone();
        signed_part.extend_from_slice(&message_hash);
        (signed_part, message_hash)
    }

    /// Verify that `Identity::sign` + `Identity::validate` round-trips correctly
    /// with the LXMF signed_part construction.
    #[test]
    fn test_sign_validate_roundtrip() {
        let sender = Identity::new(true);

        let dest_hash = [0xAAu8; 16];
        let source_hash = [0xBBu8; 16];
        let payload = b"hello lxmf payload";

        let (signed_part, _) = make_signed_part(&dest_hash, &source_hash, payload);

        let signature = sender.sign(&signed_part);
        assert_eq!(signature.len(), 64, "Ed25519 signature must be 64 bytes");

        assert!(
            sender.validate(&signature, &signed_part),
            "Signature should be valid with correct signed_part"
        );
    }

    /// Verify that a tampered message fails validation.
    #[test]
    fn test_validate_rejects_tampered_data() {
        let sender = Identity::new(true);

        let dest_hash = [0x01u8; 16];
        let source_hash = [0x02u8; 16];
        let payload = b"original payload";

        let (signed_part, _) = make_signed_part(&dest_hash, &source_hash, payload);
        let signature = sender.sign(&signed_part);

        let mut tampered = signed_part.clone();
        tampered[0] ^= 0xFF;

        assert!(
            !sender.validate(&signature, &tampered),
            "Signature must be invalid on tampered data"
        );
    }

    /// Verify the full recall cycle:
    ///   remember_destination → recall → validate
    /// This mirrors the path taken by `recall_identity` in lx_message.rs.
    #[test]
    fn test_remember_and_recall_then_validate() {
        let sender = Identity::new(true);

        let pub_key = sender.get_public_key().expect("sender must have public key");
        assert_eq!(pub_key.len(), 64);

        // Use a fixed fake destination hash (16 bytes).
        let dest_hash = [0xCAu8; 16];

        // Inject into the in-memory cache (save to disk may fail; that's OK for testing).
        let _ = Identity::remember_destination(&dest_hash, &pub_key, None);

        // Recall must succeed.
        let recalled = Identity::recall(&dest_hash)
            .expect("recalled identity must be Some after remember_destination");

        // Build LXMF-style signed_part.
        let source_hash = [0xDDu8; 16];
        let payload = b"test lxmf content";
        let (signed_part, _) = make_signed_part(&dest_hash, &source_hash, payload);

        // Sign with full keypair, validate with recalled (public-key-only) identity.
        let signature = sender.sign(&signed_part);
        assert!(
            recalled.validate(&signature, &signed_part),
            "Recalled identity must validate signature produced by the sender"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut identity = Identity::new(true);
        let plaintext = b"Hello, Reticulum!";
        
        // Encrypt using the identity's public key
        let ciphertext = identity.encrypt(plaintext)
            .expect("encrypt should succeed");
        
        // Ciphertext should be: 32 (ephemeral pub) + 16 (IV) + padded_cipher + 32 (HMAC)
        assert!(ciphertext.len() > 32 + 48, "ciphertext too short");
        
        // Decrypt using the identity's private key
        let decrypted = identity.decrypt(&ciphertext)
            .expect("decrypt should succeed");
        
        assert_eq!(&decrypted, plaintext, "Round trip must preserve plaintext");
    }

    #[test]
    fn test_python_to_rust_decrypt() {
        // Test vector generated by Python:
        // python3 test_cross_decrypt.py
        let prv_key_hex = "f09cf278a278eac75e1b58e152f208326bda4ee7ca388568bc418c95b2e2b47a750b75605ecbbe0007b0504bc0400e812a9cf4517c0801a1135cd32376e5524d";
        let ciphertext_hex = "3e19acbf94f5216db686965ea042e14dba91f490df71a92d49c38fe67b87ee2f67587119afd358f3d257f2e279b03258053555d4200fd55c022d40500fcd4e6a89468741d57d36c3c58faa36b6e60a591f3ad3399a469dd7d27ff73cb9b07115d57c6565336f88d91edf0234a5470c27";
        let expected_plaintext = b"Hello from Python to Rust!";
        let expected_hash_hex = "253526e044fbb538e2f402d986bdd185";

        let prv_key = crate::decode_hex(prv_key_hex).unwrap();
        let ciphertext = crate::decode_hex(ciphertext_hex).unwrap();

        let mut identity = Identity::from_bytes(&prv_key)
            .expect("should load identity from private key bytes");
        
        let hash_hex = identity.hash.as_ref()
            .map(|h| crate::hexrep(h, false))
            .unwrap_or_default();
        assert_eq!(hash_hex, expected_hash_hex, "Identity hash must match Python");

        let decrypted = identity.decrypt(&ciphertext)
            .expect("Rust must decrypt Python-encrypted ciphertext");
        
        assert_eq!(&decrypted[..], expected_plaintext, "Decrypted plaintext must match");
    }

            #[test]
            fn test_known_ratchet_max_age_matches_receiver_window() {
                let receiver_window = (crate::destination::RATCHET_COUNT.saturating_sub(1) as u64)
                    .saturating_mul(crate::destination::RATCHET_INTERVAL);
                assert_eq!(known_ratchet_max_age(), receiver_window);
                assert!(known_ratchet_max_age() < RATCHET_EXPIRY);
            }

            #[test]
            fn test_ratchet_entry_fresh_uses_receiver_window() {
                let max_age = known_ratchet_max_age();
                let now = max_age + 100;
                let fresh = RatchetEntry {
                    public_key: vec![0u8; 32],
                    timestamp: now - max_age,
                };
                let stale = RatchetEntry {
                    public_key: vec![0u8; 32],
                    timestamp: now - max_age - 1,
                };

                assert!(ratchet_entry_fresh(&fresh, now));
                assert!(!ratchet_entry_fresh(&stale, now));
            }
}
