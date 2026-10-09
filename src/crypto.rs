use std::convert::TryInto;
use std::fmt;
use std::hash::Hasher;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20Legacy;
use dryoc::classic::crypto_core::{
    crypto_core_hchacha20, crypto_scalarmult, crypto_scalarmult_base,
};
use dryoc::classic::crypto_sign::{
    crypto_sign_detached, crypto_sign_keypair,
};
use poly1305::universal_hash::KeyInit;
use poly1305::Poly1305;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha512};
use siphasher::sip::SipHasher13;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::*;

pub const SIGNATURE_SIZE: usize = 64;
pub const SIGN_SECRET_KEY_SIZE: usize = 64;
pub const SIGN_PUBLIC_KEY_SIZE: usize = 32;
pub const CRYPT_SECRET_KEY_SIZE: usize = 32;
pub const CRYPT_PUBLIC_KEY_SIZE: usize = 32;
pub const CRYPT_SEED_SIZE: usize = 32;
pub const SHARED_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;
pub const MAC_SIZE: usize = 16;

pub struct Signature([u8; SIGNATURE_SIZE]);

impl Default for Signature {
    fn default() -> Self {
        Self([0u8; SIGNATURE_SIZE])
    }
}

impl Signature {
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self(bytes)
    }
}

/// Libsodium's Ed25519 secret-key layout: seed || public key.
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignSK(
    #[serde(with = "BigArray")]
    [u8; SIGN_SECRET_KEY_SIZE],
);

impl Default for SignSK {
    fn default() -> Self {
        Self([0u8; SIGN_SECRET_KEY_SIZE])
    }
}

impl SignSK {
    pub fn as_bytes(&self) -> &[u8; SIGN_SECRET_KEY_SIZE] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; SIGN_SECRET_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn sign(&self, bytes: &[u8]) -> Signature {
        let mut signature = Signature::default();
        crypto_sign_detached(&mut signature.0, bytes, &self.0)
            .expect("Unable to sign");
        signature
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SignPK([u8; SIGN_PUBLIC_KEY_SIZE]);

impl SignPK {
    pub fn as_bytes(&self) -> &[u8; SIGN_PUBLIC_KEY_SIZE] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; SIGN_PUBLIC_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn as_string(&self) -> String {
        bin2hex(self.as_bytes())
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct SignKeyPair {
    pub sk: SignSK,
    pub pk: SignPK,
}

impl fmt::Debug for SignKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignKeyPair")
            .field("pk", &self.pk)
            .finish()
    }
}

impl SignKeyPair {
    pub fn new() -> Self {
        let (pk, sk) = crypto_sign_keypair();
        Self {
            sk: SignSK(sk),
            pk: SignPK(pk),
        }
    }
}

#[derive(
    Debug, Default, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop,
)]
pub struct CryptSK([u8; CRYPT_SECRET_KEY_SIZE]);

impl CryptSK {
    pub fn as_bytes(&self) -> &[u8; CRYPT_SECRET_KEY_SIZE] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; CRYPT_SECRET_KEY_SIZE]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CryptPK([u8; CRYPT_PUBLIC_KEY_SIZE]);

impl CryptPK {
    pub fn as_bytes(&self) -> &[u8; CRYPT_PUBLIC_KEY_SIZE] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; CRYPT_PUBLIC_KEY_SIZE]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CryptKeyPair {
    pub sk: CryptSK,
    pub pk: CryptPK,
}

impl CryptKeyPair {
    pub fn from_seed(seed: [u8; CRYPT_SEED_SIZE]) -> Self {
        // Libsodium retains the first 32 SHA-512 bytes as the stored
        // secret key; scalar multiplication performs the clamping.
        let mut hash = Sha512::digest(seed);
        let mut sk = CryptSK::default();
        sk.0.copy_from_slice(&hash[..CRYPT_SECRET_KEY_SIZE]);
        hash.as_mut_slice().zeroize();

        let mut pk = CryptPK::default();
        crypto_scalarmult_base(&mut pk.0, &sk.0);
        Self { sk, pk }
    }

    pub fn compute_shared_key(&self, pk: &[u8]) -> Result<SharedKey, Error> {
        let pk: &[u8; CRYPT_PUBLIC_KEY_SIZE] = pk
            .try_into()
            .map_err(|_| anyhow!("Bad public key length"))?;

        let mut dh = Zeroizing::new([0u8; SHARED_KEY_SIZE]);
        crypto_scalarmult(&mut dh, &self.sk.0, pk)
            .map_err(|_| anyhow!("Weak public key"))?;

        let mut shared_key = SharedKey::default();
        crypto_core_hchacha20(&mut shared_key.0, &[0u8; 16], &dh, None);
        Ok(shared_key)
    }
}

#[derive(Debug, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SharedKey([u8; SHARED_KEY_SIZE]);

/// Construct libsodium's XChaCha20 secretbox stream.
///
/// The first 32 stream bytes form the one-time Poly1305 key. The
/// remaining stream encrypts the message, starting at byte offset 32.
fn secretbox_stream(
    key: &[u8; SHARED_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> (ChaCha20Legacy, Zeroizing<[u8; 32]>) {
    let mut subkey = Zeroizing::new([0u8; 32]);
    let input: &[u8; 16] = nonce[..16].try_into().unwrap();
    crypto_core_hchacha20(&mut subkey, input, key, None);

    let tail: &[u8; 8] = nonce[16..].try_into().unwrap();
    let mut stream = ChaCha20Legacy::new((&*subkey).into(), tail.into());
    let mut poly_key = Zeroizing::new([0u8; 32]);
    stream.apply_keystream(&mut poly_key[..]);
    (stream, poly_key)
}

fn seal_secretbox(
    key: &[u8; SHARED_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let (mut stream, poly_key) = secretbox_stream(key, nonce);
    let output_len = plaintext
        .len()
        .checked_add(MAC_SIZE)
        .ok_or_else(|| anyhow!("Message too long"))?;
    let mut encrypted = vec![0u8; output_len];
    encrypted[MAC_SIZE..].copy_from_slice(plaintext);

    stream
        .try_apply_keystream(&mut encrypted[MAC_SIZE..])
        .map_err(|_| anyhow!("Message too long"))?;

    // Secretbox authenticates the ciphertext directly: no AEAD length
    // block and no zero-padding of the final Poly1305 block.
    let tag = Poly1305::new((&*poly_key).into())
        .compute_unpadded(&encrypted[MAC_SIZE..]);
    encrypted[..MAC_SIZE].copy_from_slice(&tag);
    Ok(encrypted)
}

impl SharedKey {
    pub fn from_bytes(bytes: [u8; SHARED_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn as_raw_bytes(&self) -> &[u8; SHARED_KEY_SIZE] {
        &self.0
    }

    /// Preserves the original infallible signature.
    ///
    /// Panics for an invalid nonce length or a message exceeding the
    /// underlying stream cipher's counter limit.
    pub fn seal_raw(&self, nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce: &[u8; NONCE_SIZE] = nonce
            .try_into()
            .expect("Nonce must be exactly 24 bytes");
        seal_secretbox(&self.0, nonce, plaintext)
            .expect("Unable to encrypt")
    }

    pub fn open_raw(&self, nonce: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce: &[u8; NONCE_SIZE] = nonce
            .try_into()
            .map_err(|_| anyhow!("Bad nonce length"))?;
        ensure!(encrypted.len() >= MAC_SIZE, "Unable to decrypt");

        let (mut stream, poly_key) = secretbox_stream(&self.0, nonce);
        let (supplied_tag, ciphertext) = encrypted.split_at(MAC_SIZE);
        let expected_tag = Poly1305::new((&*poly_key).into())
            .compute_unpadded(ciphertext);

        ensure!(
            bool::from(expected_tag.as_slice().ct_eq(supplied_tag)),
            "Unable to decrypt"
        );

        // Authenticate before releasing or decrypting any plaintext.
        let mut decrypted = ciphertext.to_vec();
        stream
            .try_apply_keystream(&mut decrypted)
            .map_err(|_| anyhow!("Unable to decrypt"))?;
        Ok(decrypted)
    }

    pub fn decrypt(&self, nonce: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, Error> {
        let mut decrypted = self.open_raw(nonce, encrypted)?;
        let idx = decrypted
            .iter()
            .rposition(|x| *x != 0x00)
            .ok_or_else(|| anyhow!("Padding error"))?;
        ensure!(decrypted[idx] == 0x80, "Padding error");
        decrypted.truncate(idx);
        Ok(decrypted)
    }

    pub fn encrypt_into(
        &self,
        target: &mut Vec<u8>,
        nonce: &[u8],
        client_nonce: &[u8],
        plaintext: Vec<u8>,
        max_target_size: usize,
    ) -> Result<(), Error> {
        let nonce: &[u8; NONCE_SIZE] = nonce
            .try_into()
            .map_err(|_| anyhow!("Bad nonce length"))?;
        ensure!(max_target_size >= MAC_SIZE, "Max target size too small");

        let plaintext_len = plaintext.len();
        let max_padded_plaintext_len = max_target_size - MAC_SIZE;
        let mut hasher = SipHasher13::new();
        hasher.write(&self.0);
        hasher.write(client_nonce);
        let pad_size = 1 + (hasher.finish() as usize & 0xff);

        let mut padded_plaintext_len = plaintext_len
            .checked_add(pad_size)
            .ok_or_else(|| anyhow!("Message too long"))?
            & !63;
        if padded_plaintext_len <= plaintext_len {
            padded_plaintext_len = padded_plaintext_len
                .checked_add(256)
                .ok_or_else(|| anyhow!("Message too long"))?;
        }
        padded_plaintext_len =
            padded_plaintext_len.min(max_padded_plaintext_len);
        ensure!(padded_plaintext_len > plaintext_len, "No room for padding");

        let mut padded_plaintext = plaintext;
        padded_plaintext.push(0x80);
        padded_plaintext.resize(padded_plaintext_len, 0);

        let encrypted = seal_secretbox(&self.0, nonce, &padded_plaintext)?;
        target.extend_from_slice(&encrypted);
        Ok(())
    }
}

pub fn bin2hex(bin: &[u8]) -> String {
    hex::encode(bin)
}

/// Retained for callers. Pure-Rust primitives need no global initialization.
pub fn init() -> Result<(), Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_round_trips_and_rejects_tampering() {
        let key = SharedKey::from_bytes([0x42; 32]);
        let nonce = [0x07; NONCE_SIZE];

        for len in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1120] {
            let message = vec![0xda; len];
            let encrypted = key.seal_raw(&nonce, &message);
            assert_eq!(encrypted.len(), len + MAC_SIZE);
            assert_eq!(key.open_raw(&nonce, &encrypted).unwrap(), message);

            for index in [0, encrypted.len() - 1] {
                let mut tampered = encrypted.clone();
                tampered[index] ^= 1;
                assert!(key.open_raw(&nonce, &tampered).is_err());
            }
            assert!(key.open_raw(&[0x08; NONCE_SIZE], &encrypted).is_err());
        }

        assert!(key.open_raw(&nonce[..23], &[0u8; 16]).is_err());
        assert!(key.open_raw(&nonce, &[0u8; 15]).is_err());
    }

    #[test]
    fn padding_and_public_key_validation() {
        let key = SharedKey::from_bytes([0x42; 32]);
        let nonce = [0x07; NONCE_SIZE];

        for bad in [&[][..], &[0u8][..], &[0x81, 0][..]] {
            assert!(key.decrypt(&nonce, &key.seal_raw(&nonce, bad)).is_err());
        }
        assert_eq!(
            key.decrypt(&nonce, &key.seal_raw(&nonce, &[0xda, 0x80, 0, 0]))
                .unwrap(),
            [0xda]
        );

        let alice = CryptKeyPair::from_seed([1; 32]);
        let bob = CryptKeyPair::from_seed([2; 32]);
        let ab = alice.compute_shared_key(bob.pk.as_bytes()).unwrap();
        let ba = bob.compute_shared_key(alice.pk.as_bytes()).unwrap();
        assert_eq!(ab.as_raw_bytes(), ba.as_raw_bytes());
        assert!(alice.compute_shared_key(&[0u8; 32]).is_err());
        assert!(alice.compute_shared_key(&[0u8; 31]).is_err());
    }
}

#[cfg(all(test, feature = "sodium-compat-tests"))]
mod sodium_compat_tests {
    use super::*;
    use libsodium_sys as sodium;

    fn initialize() {
        unsafe {
            assert!(sodium::sodium_init() >= 0);
        }
    }

    #[test]
    fn ed25519_key_layout_and_signatures_match() {
        initialize();

        for seed_byte in [0, 1, 0x42, 0xff] {
            let seed = [seed_byte; 32];
            let (rust_pk, rust_sk) =
                dryoc::classic::crypto_sign::crypto_sign_seed_keypair(&seed);
            let mut c_pk = [0u8; 32];
            let mut c_sk = [0u8; 64];

            unsafe {
                assert_eq!(
                    sodium::crypto_sign_seed_keypair(
                        c_pk.as_mut_ptr(),
                        c_sk.as_mut_ptr(),
                        seed.as_ptr(),
                    ),
                    0
                );
            }
            assert_eq!(rust_pk, c_pk);
            assert_eq!(rust_sk, c_sk);

            let sk = SignSK::from_bytes(c_sk);
            for message in [&[][..], b"DNSCrypt certificate".as_slice(), &[0u8; 257][..]] {
                let rust_sig = sk.sign(message);
                let mut c_sig = [0u8; 64];
                unsafe {
                    assert_eq!(
                        sodium::crypto_sign_detached(
                            c_sig.as_mut_ptr(),
                            std::ptr::null_mut(),
                            message.as_ptr(),
                            message.len() as _,
                            sk.as_bytes().as_ptr(),
                        ),
                        0
                    );
                    assert_eq!(
                        sodium::crypto_sign_verify_detached(
                            rust_sig.as_bytes().as_ptr(),
                            message.as_ptr(),
                            message.len() as _,
                            c_pk.as_ptr(),
                        ),
                        0
                    );
                }
                assert_eq!(rust_sig.as_bytes(), &c_sig);
            }
        }
    }

    #[test]
    fn classical_key_derivation_matches() {
        initialize();

        for seed_byte in [0, 1, 0x42, 0xff] {
            let seed = [seed_byte; 32];
            let rust_kp = CryptKeyPair::from_seed(seed);
            let mut c_pk = [0u8; 32];
            let mut c_sk = [0u8; 32];

            unsafe {
                assert_eq!(
                    sodium::crypto_box_curve25519xchacha20poly1305_seed_keypair(
                        c_pk.as_mut_ptr(),
                        c_sk.as_mut_ptr(),
                        seed.as_ptr(),
                    ),
                    0
                );
            }
            assert_eq!(rust_kp.pk.as_bytes(), &c_pk);
            assert_eq!(rust_kp.sk.as_bytes(), &c_sk);

            let peer = CryptKeyPair::from_seed([seed_byte.wrapping_add(1); 32]);
            let rust_shared = rust_kp
                .compute_shared_key(peer.pk.as_bytes())
                .unwrap();
            let mut c_shared = [0u8; 32];
            unsafe {
                assert_eq!(
                    sodium::crypto_box_curve25519xchacha20poly1305_beforenm(
                        c_shared.as_mut_ptr(),
                        peer.pk.as_bytes().as_ptr(),
                        c_sk.as_ptr(),
                    ),
                    0
                );
            }
            assert_eq!(rust_shared.as_raw_bytes(), &c_shared);

            // Includes noncanonical low-order encodings.
            let mut weak_keys = vec![[0u8; 32]];
            let mut one = [0u8; 32];
            one[0] = 1;
            weak_keys.push(one);
            let mut high_bit_zero = [0u8; 32];
            high_bit_zero[31] = 0x80;
            weak_keys.push(high_bit_zero);
            let mut p_minus_one = [0xffu8; 32];
            p_minus_one[0] = 0xec;
            p_minus_one[31] = 0x7f;
            weak_keys.push(p_minus_one);

            for pk in weak_keys {
                let rc = unsafe {
                    sodium::crypto_box_curve25519xchacha20poly1305_beforenm(
                        c_shared.as_mut_ptr(),
                        pk.as_ptr(),
                        c_sk.as_ptr(),
                    )
                };
                assert_ne!(rc, 0);
                assert!(rust_kp.compute_shared_key(&pk).is_err());
            }
        }
    }

    #[test]
    fn secretbox_bytes_and_cross_decryption_match() {
        initialize();

        for nonce_byte in [0, 1, 0x7f, 0xff] {
            let nonce = [nonce_byte; NONCE_SIZE];
            let key = SharedKey::from_bytes([0x42; 32]);

            for len in [
                0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65,
                127, 128, 129, 1120, 4096,
            ] {
                let message: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(31))
                    .collect();
                let rust_encrypted = key.seal_raw(&nonce, &message);
                let mut c_encrypted = vec![0u8; len + MAC_SIZE];

                unsafe {
                    assert_eq!(
                        sodium::crypto_box_curve25519xchacha20poly1305_easy_afternm(
                            c_encrypted.as_mut_ptr(),
                            message.as_ptr(),
                            message.len() as _,
                            nonce.as_ptr(),
                            key.as_raw_bytes().as_ptr(),
                        ),
                        0
                    );
                }
                assert_eq!(rust_encrypted, c_encrypted, "length {len}");
                assert_eq!(key.open_raw(&nonce, &c_encrypted).unwrap(), message);

                let mut c_plaintext = vec![0u8; len];
                unsafe {
                    assert_eq!(
                        sodium::crypto_box_curve25519xchacha20poly1305_open_easy_afternm(
                            c_plaintext.as_mut_ptr(),
                            rust_encrypted.as_ptr(),
                            rust_encrypted.len() as _,
                            nonce.as_ptr(),
                            key.as_raw_bytes().as_ptr(),
                        ),
                        0
                    );
                }
                assert_eq!(c_plaintext, message);
            }
        }
    }
}