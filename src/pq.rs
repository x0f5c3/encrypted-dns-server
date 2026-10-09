use std::convert::TryInto;
use dryoc::classic::crypto_kem_xwing::{
    crypto_kem_xwing_dec, crypto_kem_xwing_seed_keypair_inplace,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::SharedKey;
use crate::errors::*;

pub const PQ_ES_VERSION: [u8; 2] = [0x00, 0x03];
pub const XWING_PK_SIZE: usize = 1216;
pub const XWING_CT_SIZE: usize = 1120;
pub const XWING_SEED_SIZE: usize = 32;

pub const PQ_RESUME_MAGIC: [u8; 8] = *b"PQResume";
pub const PQ_CONTROL_MAGIC: [u8; 4] = *b"PQDR";
pub const PQ_CONTROL_VERSION: u8 = 0x01;
pub const PQ_EXT_VERSION: u8 = 0x01;
pub const PQ_KDF_ID: u8 = 0x01;
pub const PQ_AEAD_ID: u8 = 0x01;
pub const PQ_PROFILE_EXT_SIZE: usize = 12;

pub const TICKET_KEY_ID_SIZE: usize = 4;
pub const TICKET_NONCE_SIZE: usize = 24;
pub const MAC_SIZE: usize = 16;

/// Default ticket lifetime, in seconds.
pub const PQ_TICKET_LIFETIME: u32 = 600;

/// Signed profile extension binding algorithms and field lengths.
pub fn profile_extension() -> [u8; PQ_PROFILE_EXT_SIZE] {
    let pk_len = (XWING_PK_SIZE as u16).to_be_bytes();
    let ct_len = (XWING_CT_SIZE as u16).to_be_bytes();
    [
        b'P', b'Q', b'D', PQ_EXT_VERSION,
        PQ_ES_VERSION[0], PQ_ES_VERSION[1],
        PQ_KDF_ID, PQ_AEAD_ID,
        pk_len[0], pk_len[1], ct_len[0], ct_len[1],
    ]
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// RFC 5869 HKDF-SHA256, preserving the original infallible API.
///
/// Panics if the requested output exceeds RFC 5869's 255 * 32 byte limit.
/// All protocol callers request 32 bytes.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("HKDF-SHA256 output must be at most 8160 bytes");
}

/// X-Wing secret key stored as its 32-byte seed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct XWingKeyPair {
    seed: [u8; XWING_SEED_SIZE],
}

impl XWingKeyPair {
    pub fn from_seed(seed: [u8; XWING_SEED_SIZE]) -> Self {
        Self { seed }
    }

    pub fn public_key_bytes(&self) -> [u8; XWING_PK_SIZE] {
        let mut pk = [0u8; XWING_PK_SIZE];
        let mut sk = Zeroizing::new([0u8; XWING_SEED_SIZE]);
        crypto_kem_xwing_seed_keypair_inplace(&mut pk, &mut sk, &self.seed);
        pk
    }

    pub fn decapsulate(&self, ct_bytes: &[u8]) -> Result<[u8; 32], Error> {
        let ct: &[u8; XWING_CT_SIZE] = ct_bytes
            .try_into()
            .map_err(|_| anyhow!("Bad ciphertext length"))?;
        let mut ss = Zeroizing::new([0u8; 32]);
        crypto_kem_xwing_dec(&mut ss, ct, &self.seed)
            .map_err(|_| anyhow!("X-Wing decapsulation failed"))?;
        Ok(*ss)
    }
}

/// Bind the shared key to the exact signed certificate.
#[allow(clippy::too_many_arguments)]
pub fn cert_context(
    es_version: &[u8; 2],
    minor: &[u8; 2],
    resolver_pk: &[u8],
    client_magic: &[u8; 8],
    serial: &[u8; 4],
    ts_start: &[u8; 4],
    ts_end: &[u8; 4],
    extensions: &[u8],
) -> Vec<u8> {
    let mut c = Vec::with_capacity(
        14 + 2 + 2 + resolver_pk.len() + 8 + 4 + 4 + 4 + extensions.len(),
    );
    c.extend_from_slice(b"DNSCrypt-PQ-v1");
    c.extend_from_slice(es_version);
    c.extend_from_slice(minor);
    c.extend_from_slice(resolver_pk);
    c.extend_from_slice(client_magic);
    c.extend_from_slice(serial);
    c.extend_from_slice(ts_start);
    c.extend_from_slice(ts_end);
    c.extend_from_slice(extensions);
    c
}

/// Derive the shared key for a query carrying a KEM ciphertext.
pub fn derive_shared_key(
    kem_ss: &[u8; 32],
    es_version: &[u8; 2],
    client_magic: &[u8; 8],
    cert_ctx: &[u8],
    client_kex: &[u8],
) -> SharedKey {
    let mut salt = [0u8; 10];
    salt[..2].copy_from_slice(es_version);
    salt[2..].copy_from_slice(client_magic);
    let mut info = Vec::with_capacity(cert_ctx.len() + client_kex.len());
    info.extend_from_slice(cert_ctx);
    info.extend_from_slice(client_kex);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf_sha256(&salt, kem_ss, &info, &mut key[..]);
    SharedKey::from_bytes(*key)
}

pub fn resume_secret(
    shared_key: &[u8; 32],
    client_magic: &[u8; 8],
    client_nonce: &[u8],
) -> [u8; 32] {
    let mut salt = Vec::with_capacity(8 + client_nonce.len());
    salt.extend_from_slice(client_magic);
    salt.extend_from_slice(client_nonce);
    let mut out = [0u8; 32];
    hkdf_sha256(&salt, shared_key, b"DNSCrypt-PQ-resume-secret-v1", &mut out);
    out
}

pub fn resumed_shared_key(
    resume_secret: &[u8; 32],
    client_magic: &[u8; 8],
    client_nonce: &[u8],
    ticket: &[u8],
) -> SharedKey {
    let mut salt = Vec::with_capacity(8 + client_nonce.len());
    salt.extend_from_slice(client_magic);
    salt.extend_from_slice(client_nonce);
    let mut info = Vec::with_capacity(27 + 32);
    info.extend_from_slice(b"DNSCrypt-PQ-resumed-query-v1");
    info.extend_from_slice(&sha256(ticket));
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf_sha256(&salt, resume_secret, &info, &mut key[..]);
    SharedKey::from_bytes(*key)
}

#[derive(Clone)]
pub struct TicketKey {
    pub id: [u8; TICKET_KEY_ID_SIZE],
    pub key: SharedKey,
}

impl TicketKey {
    /// Derive a stable ticket key from the provider signing key.
    pub fn derive(provider_sk: &[u8]) -> Self {
        let mut input = Zeroizing::new(Vec::with_capacity(25 + provider_sk.len()));
        input.extend_from_slice(b"DNSCrypt-PQ-ticket-key-v1");
        input.extend_from_slice(provider_sk);
        Self {
            id: [0x00, 0x00, 0x00, 0x01],
            key: SharedKey::from_bytes(sha256(&input)),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn ticket_plain(
    resume_secret: &[u8; 32],
    es_version: &[u8; 2],
    client_magic: &[u8; 8],
    serial: &[u8; 4],
    ts_end: &[u8; 4],
    ticket_expiry: u32,
    profile_extension_hash: &[u8; 32],
) -> Vec<u8> {
    let mut tp = Vec::with_capacity(32 + 2 + 8 + 4 + 4 + 4 + 32);
    tp.extend_from_slice(resume_secret);
    tp.extend_from_slice(es_version);
    tp.extend_from_slice(client_magic);
    tp.extend_from_slice(serial);
    tp.extend_from_slice(ts_end);
    tp.extend_from_slice(&ticket_expiry.to_be_bytes());
    tp.extend_from_slice(profile_extension_hash);
    tp
}

pub struct TicketFields {
    pub resume_secret: [u8; 32],
    pub es_version: [u8; 2],
    pub client_magic: [u8; 8],
    pub ticket_expiry: u32,
}

pub fn parse_ticket_plain(tp: &[u8]) -> Result<TicketFields, Error> {
    ensure!(
        tp.len() == 32 + 2 + 8 + 4 + 4 + 4 + 32,
        "Bad ticket plaintext length"
    );
    let mut resume_secret = [0u8; 32];
    resume_secret.copy_from_slice(&tp[..32]);
    let mut es_version = [0u8; 2];
    es_version.copy_from_slice(&tp[32..34]);
    let mut client_magic = [0u8; 8];
    client_magic.copy_from_slice(&tp[34..42]);
    let mut expiry_bytes = [0u8; 4];
    expiry_bytes.copy_from_slice(&tp[50..54]);
    Ok(TicketFields {
        resume_secret,
        es_version,
        client_magic,
        ticket_expiry: u32::from_be_bytes(expiry_bytes),
    })
}

pub fn seal_ticket(
    tk: &TicketKey,
    ticket_nonce: &[u8; TICKET_NONCE_SIZE],
    ticket_plain: &[u8],
) -> Vec<u8> {
    let sealed = tk.key.seal_raw(ticket_nonce, ticket_plain);
    let mut ticket =
        Vec::with_capacity(TICKET_KEY_ID_SIZE + TICKET_NONCE_SIZE + sealed.len());
    ticket.extend_from_slice(&tk.id);
    ticket.extend_from_slice(ticket_nonce);
    ticket.extend_from_slice(&sealed);
    ticket
}

/// The caller must silently drop queries when opening their ticket fails.
pub fn open_ticket(tk: &TicketKey, ticket: &[u8]) -> Result<Vec<u8>, Error> {
    ensure!(
        ticket.len() > TICKET_KEY_ID_SIZE + TICKET_NONCE_SIZE + MAC_SIZE,
        "Short ticket"
    );
    ensure!(ticket[..TICKET_KEY_ID_SIZE] == tk.id, "Unknown ticket key");
    let nonce =
        &ticket[TICKET_KEY_ID_SIZE..TICKET_KEY_ID_SIZE + TICKET_NONCE_SIZE];
    let sealed = &ticket[TICKET_KEY_ID_SIZE + TICKET_NONCE_SIZE..];
    tk.key.open_raw(nonce, sealed)
}

pub fn control_block(ticket_lifetime: u32, ticket: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(4 + 1 + 4 + 2 + ticket.len());
    c.extend_from_slice(&PQ_CONTROL_MAGIC);
    c.push(PQ_CONTROL_VERSION);
    c.extend_from_slice(&ticket_lifetime.to_be_bytes());
    c.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    c.extend_from_slice(ticket);
    c
}

/// ISO/IEC 7816-4 padding; always append at least the 0x80 marker.
pub fn pad7816(plaintext: &mut Vec<u8>, floor: usize) {
    plaintext.push(0x80);
    let mut target = (plaintext.len() + 63) & !63;
    if target < floor {
        target = floor;
    }
    plaintext.resize(target, 0);
}

/// Shrink preferred padding when necessary to fit the size budget.
pub fn pad7816_within(
    plaintext: &mut Vec<u8>,
    floor: usize,
    max_len: usize,
) -> Result<(), Error> {
    ensure!(plaintext.len() < max_len, "No room for padding");
    pad7816(plaintext, floor);
    plaintext.truncate(max_len);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dryoc::classic::crypto_kem_xwing::crypto_kem_xwing_enc_deterministic;

    fn iota(buf: &mut [u8], start: u8) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
    }

    fn hexd(d: &[u8]) -> String {
        hex::encode(d)
    }

    fn hex_to_vec(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        hex::decode(s).unwrap()
    }

    /// Pinned Appendix 3 values remain enabled without the C feature.
    #[test]
    fn appendix3_vectors() {
        let mut resolver_seed = [0u8; 32];
        iota(&mut resolver_seed, 0x20);
        let mut eseed = [0u8; 64];
        iota(&mut eseed, 0x40);
        let client_magic = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
        let es_version = PQ_ES_VERSION;
        let minor = [0x00, 0x00];
        let serial = [0x00, 0x00, 0x00, 0x01];
        let ts_start = [0x68, 0x00, 0x00, 0x00];
        let ts_end = [0x68, 0x01, 0x51, 0x80];
        let mut q_nonce = [0u8; 12];
        iota(&mut q_nonce, 0xb0);
        let mut r_nonce = [0u8; 12];
        iota(&mut r_nonce, 0xc0);
        let mut tk_key = [0u8; 32];
        iota(&mut tk_key, 0x80);
        let tk = TicketKey {
            id: [0x00, 0x00, 0x00, 0x01],
            key: SharedKey::from_bytes(tk_key),
        };
        let mut ticket_nonce = [0u8; 24];
        iota(&mut ticket_nonce, 0xd0);
        let ticket_expiry: u32 = 0x6800_0258;
        let ticket_lifetime: u32 = 0x0000_012c;
        let mut rq_nonce = [0u8; 12];
        iota(&mut rq_nonce, 0xf0);
        let mut rr_nonce = [0u8; 12];
        iota(&mut rr_nonce, 0x10);
        let extensions = profile_extension();
        assert_eq!(hexd(&extensions), "505144010003010104c00460");

        let dns_query = hex_to_vec(
            "12340100000100000000000003777777076578616d706c6503636f6d0000010001",
        );
        let dns_response = hex_to_vec(
            "12348180000100010000000003777777076578616d706c6503636f6d00000100\
             01c00c0001000100000e1000045db8d822",
        );

        let kp = XWingKeyPair::from_seed(resolver_seed);
        let resolver_pk = kp.public_key_bytes();
        let mut ct_bytes = [0u8; XWING_CT_SIZE];
        let mut kem_ss = [0u8; 32];
        crypto_kem_xwing_enc_deterministic(
            &mut ct_bytes,
            &mut kem_ss,
            &resolver_pk,
            &eseed,
        )
            .unwrap();
        assert_eq!(
            hexd(&kem_ss),
            "8dac8602d4ce5e27e81335b54b25fdcaea86e56613214ee0522db4a5e0a38d50"
        );
        assert_eq!(kp.decapsulate(&ct_bytes).unwrap(), kem_ss);

        let ctx = cert_context(
            &es_version, &minor, &resolver_pk, &client_magic,
            &serial, &ts_start, &ts_end, &extensions,
        );
        let shared_key =
            derive_shared_key(&kem_ss, &es_version, &client_magic, &ctx, &ct_bytes);
        let sk_bytes = *shared_key.as_raw_bytes();
        assert_eq!(
            hexd(&sk_bytes),
            "e6d4ab9cffc9b49e2a64d80d7eb2dde280f806b89e834d596ad385b1dd75e9ef"
        );

        let mut q_nonce24 = [0u8; 24];
        q_nonce24[..12].copy_from_slice(&q_nonce);
        let mut qpt = dns_query.clone();
        pad7816(&mut qpt, 64);
        assert_eq!(qpt.len(), 64);
        let enc_query = shared_key.seal_raw(&q_nonce24, &qpt);
        assert_eq!(
            hexd(&enc_query),
            "c41764468cb42d3a837c51234c08be714af49e1a6830ea6da28178e9e280d76b\
             ac1b87fd7f56515f2b2cc3d4715aaa42907c282db1edff0bc3b92cd535a710e2\
             64859a5bdaf67c17ffa6e1c6f6e02a50"
        );
        let mut full_query = Vec::new();
        full_query.extend_from_slice(&client_magic);
        full_query.extend_from_slice(&ct_bytes);
        full_query.extend_from_slice(&q_nonce);
        full_query.extend_from_slice(&enc_query);
        assert_eq!(full_query.len(), 1220);
        assert_eq!(
            hexd(&sha256(&full_query)),
            "65c3421776283f503779916e7b5c32d0d41c885508ad892b349688db6c901233"
        );

        let rs = resume_secret(&sk_bytes, &client_magic, &q_nonce);
        assert_eq!(
            hexd(&rs),
            "df158804e3f8ddf383ff7c9d3128491b29437a894936ec72c68aed8a9553272b"
        );
        let peh = sha256(&extensions);
        let tp = ticket_plain(
            &rs, &es_version, &client_magic, &serial,
            &ts_end, ticket_expiry, &peh,
        );
        let ticket = seal_ticket(&tk, &ticket_nonce, &tp);
        assert_eq!(ticket.len(), 130);
        assert_eq!(
            hexd(&ticket),
            "00000001d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e1d90c86\
             474574e0e51e82d8a29938896b0999e827138f8f452f21e044d9809f65a013cf\
             ad8981be94c1354178b3e03dd518c28bcbaab962aa45246e446de7763288aa4a\
             01e207725a0ae7bc95452fef3743f6083deb10cd23e2881e8d9307fc2f43bce1\
             a97e"
        );
        let control = control_block(ticket_lifetime, &ticket);
        assert_eq!(control.len(), 141);

        let mut rpt = Vec::new();
        rpt.extend_from_slice(&(control.len() as u16).to_be_bytes());
        rpt.extend_from_slice(&control);
        rpt.extend_from_slice(&dns_response);
        pad7816(&mut rpt, 64);
        assert_eq!(rpt.len(), 256);
        assert_eq!(
            hexd(&sha256(&rpt)),
            "a215df14b59d272b506224ed1f6ab5956be2bf189f847dfac4f8649c5f94d99e"
        );
        let mut r_nonce24 = [0u8; 24];
        r_nonce24[..12].copy_from_slice(&q_nonce);
        r_nonce24[12..].copy_from_slice(&r_nonce);
        let enc_response = shared_key.seal_raw(&r_nonce24, &rpt);
        let mut full_response = Vec::new();
        full_response.extend_from_slice(&[
            0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38,
        ]);
        full_response.extend_from_slice(&q_nonce);
        full_response.extend_from_slice(&r_nonce);
        full_response.extend_from_slice(&enc_response);
        assert_eq!(full_response.len(), 304);
        assert_eq!(
            hexd(&sha256(&full_response)),
            "33c081503d5ead4061a30d3f095fc9f226b8c01c3bbffa8fc6f4d9b15087de5c"
        );

        assert_eq!(
            hexd(&sha256(&ticket)),
            "fb196d81022c6b480f1340c80987088a85145194c18441928a4ae8e5a153536c"
        );
        let resumed_key = resumed_shared_key(&rs, &client_magic, &rq_nonce, &ticket);
        assert_eq!(
            hexd(resumed_key.as_raw_bytes()),
            "e61f03acb2ee2ef01b952a0c312c60653267d47a2766fcfd804747fdf2fe789f"
        );
        let mut rq_nonce24 = [0u8; 24];
        rq_nonce24[..12].copy_from_slice(&rq_nonce);
        let mut rqpt = dns_query.clone();
        pad7816(&mut rqpt, 256);
        assert_eq!(rqpt.len(), 256);
        let renc_query = resumed_key.seal_raw(&rq_nonce24, &rqpt);
        assert_eq!(renc_query.len(), 272);
        let mut resume_query = Vec::new();
        resume_query.extend_from_slice(&PQ_RESUME_MAGIC);
        resume_query.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        resume_query.extend_from_slice(&ticket);
        resume_query.extend_from_slice(&rq_nonce);
        resume_query.extend_from_slice(&renc_query);
        assert_eq!(resume_query.len(), 424);
        assert_eq!(
            hexd(&sha256(&resume_query)),
            "34be2e331b4d7c7e808e968c5efc9f25675a9de9064cb33f7c66950e0e4e6db7"
        );

        let mut rrpt = Vec::new();
        rrpt.extend_from_slice(&[0x00, 0x00]);
        rrpt.extend_from_slice(&dns_response);
        pad7816(&mut rrpt, 64);
        let mut rr_nonce24 = [0u8; 24];
        rr_nonce24[..12].copy_from_slice(&rq_nonce);
        rr_nonce24[12..].copy_from_slice(&rr_nonce);
        let renc_response = resumed_key.seal_raw(&rr_nonce24, &rrpt);
        let mut resume_response = Vec::new();
        resume_response.extend_from_slice(&[
            0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38,
        ]);
        resume_response.extend_from_slice(&rq_nonce);
        resume_response.extend_from_slice(&rr_nonce);
        resume_response.extend_from_slice(&renc_response);
        assert_eq!(resume_response.len(), 112);
        assert_eq!(
            hexd(&sha256(&resume_response)),
            "2bf202dd3f33d38854450e70a02bd1a317a23bf6d79c5dae406787c9c5f34f52"
        );

        let opened = open_ticket(&tk, &ticket).unwrap();
        let fields = parse_ticket_plain(&opened).unwrap();
        assert_eq!(fields.resume_secret, rs);
        assert_eq!(fields.es_version, es_version);
        assert_eq!(fields.client_magic, client_magic);
        assert_eq!(fields.ticket_expiry, ticket_expiry);
    }

    #[test]
    fn rejects_bad_lengths_and_ticket_tampering() {
        let kp = XWingKeyPair::from_seed([0x20; 32]);
        assert!(kp.decapsulate(&[0u8; XWING_CT_SIZE - 1]).is_err());
        assert!(kp.decapsulate(&[0u8; XWING_CT_SIZE + 1]).is_err());
        assert!(parse_ticket_plain(&[0u8; 85]).is_err());

        let tk = TicketKey {
            id: [0, 0, 0, 1],
            key: SharedKey::from_bytes([0x42; 32]),
        };
        let tp = ticket_plain(
            &[1; 32], &PQ_ES_VERSION, &[2; 8],
            &[3; 4], &[4; 4], 600, &[5; 32],
        );
        let ticket = seal_ticket(&tk, &[7; 24], &tp);
        assert_eq!(open_ticket(&tk, &ticket).unwrap(), tp);

        for index in [0, 4, 28, ticket.len() - 1] {
            let mut tampered = ticket.clone();
            tampered[index] ^= 1;
            assert!(open_ticket(&tk, &tampered).is_err());
        }
    }
}

#[cfg(all(test, feature = "sodium-compat-tests"))]
mod sodium_compat_tests {
    use super::*;
    use dryoc::classic::crypto_kem_xwing::crypto_kem_xwing_enc_deterministic;
    use libsodium_sys as sodium;

    fn initialize() {
        unsafe {
            assert!(sodium::sodium_init() >= 0);
        }
    }

    #[test]
    fn sha256_and_hkdf_match() {
        initialize();

        for data in [&[][..], b"DNSCrypt-PQ-v1".as_slice(), &[0u8; 257][..]] {
            let mut c_hash = [0u8; 32];
            unsafe {
                assert_eq!(
                    sodium::crypto_hash_sha256(
                        c_hash.as_mut_ptr(),
                        data.as_ptr(),
                        data.len() as _,
                    ),
                    0
                );
            }
            assert_eq!(sha256(data), c_hash);
        }

        for (salt, ikm, info) in [
            (&[][..], &[][..], &[][..]),
            (&b"salt"[..], &b"ikm"[..], &b"context\0suffix"[..]),
            (&[0x42u8; 64][..], &[0x24u8; 65][..], &[0xffu8; 100][..]),
        ] {
            for len in [0, 1, 31, 32, 33, 64, 100, 8160] {
                let mut rust_out = vec![0u8; len];
                hkdf_sha256(salt, ikm, info, &mut rust_out);
                let mut prk = Zeroizing::new([0u8; 32]);
                let mut c_out = vec![0u8; len];

                unsafe {
                    assert_eq!(
                        sodium::crypto_kdf_hkdf_sha256_extract(
                            prk.as_mut_ptr(),
                            salt.as_ptr(),
                            salt.len() as _,
                            ikm.as_ptr(),
                            ikm.len() as _,
                        ),
                        0
                    );
                    assert_eq!(
                        sodium::crypto_kdf_hkdf_sha256_expand(
                            c_out.as_mut_ptr(),
                            c_out.len() as _,
                            info.as_ptr().cast(),
                            info.len() as _,
                            prk.as_ptr(),
                        ),
                        0
                    );
                }
                assert_eq!(rust_out, c_out, "HKDF length {len}");
            }
        }
    }

    #[test]
    fn xwing_keygen_encapsulation_and_decapsulation_match() {
        initialize();

        for start in [0u8, 0x20, 0x80, 0xff] {
            let mut seed = [0u8; 32];
            for (i, b) in seed.iter_mut().enumerate() {
                *b = start.wrapping_add(i as u8);
            }
            let mut enc_seed = [0u8; 64];
            for (i, b) in enc_seed.iter_mut().enumerate() {
                *b = start.wrapping_add(0x20).wrapping_add(i as u8);
            }

            let kp = XWingKeyPair::from_seed(seed);
            let rust_pk = kp.public_key_bytes();
            let mut c_pk = [0u8; XWING_PK_SIZE];
            let mut c_sk = Zeroizing::new([0u8; 32]);
            unsafe {
                assert_eq!(
                    sodium::crypto_kem_xwing_seed_keypair(
                        c_pk.as_mut_ptr(),
                        c_sk.as_mut_ptr(),
                        seed.as_ptr(),
                    ),
                    0
                );
            }
            assert_eq!(rust_pk, c_pk);
            assert_eq!(*c_sk, seed);

            let mut rust_ct = [0u8; XWING_CT_SIZE];
            let mut rust_ss = [0u8; 32];
            crypto_kem_xwing_enc_deterministic(
                &mut rust_ct, &mut rust_ss, &rust_pk, &enc_seed,
            )
                .unwrap();

            let mut c_ct = [0u8; XWING_CT_SIZE];
            let mut c_ss = [0u8; 32];
            unsafe {
                assert_eq!(
                    sodium::crypto_kem_xwing_enc_deterministic(
                        c_ct.as_mut_ptr(),
                        c_ss.as_mut_ptr(),
                        c_pk.as_ptr(),
                        enc_seed.as_ptr(),
                    ),
                    0
                );
            }
            assert_eq!(rust_ct, c_ct);
            assert_eq!(rust_ss, c_ss);
            assert_eq!(kp.decapsulate(&c_ct).unwrap(), c_ss);

            let mut c_dec = [0u8; 32];
            unsafe {
                assert_eq!(
                    sodium::crypto_kem_xwing_dec(
                        c_dec.as_mut_ptr(),
                        rust_ct.as_ptr(),
                        c_sk.as_ptr(),
                    ),
                    0
                );
            }
            assert_eq!(c_dec, rust_ss);

            // Compare both status and output for modified ciphertexts.
            // ML-KEM implicit rejection can return a secret successfully;
            // ciphertext modification is not always a KEM error.
            for index in [0, 1087, 1088, XWING_CT_SIZE - 1] {
                let mut modified = rust_ct;
                modified[index] ^= 1;
                let rust_result = kp.decapsulate(&modified);
                let rc = unsafe {
                    sodium::crypto_kem_xwing_dec(
                        c_dec.as_mut_ptr(),
                        modified.as_ptr(),
                        c_sk.as_ptr(),
                    )
                };
                assert_eq!(rust_result.is_ok(), rc == 0);
                if rc == 0 {
                    assert_eq!(rust_result.unwrap(), c_dec);
                }
            }

            let mut weak_ct = rust_ct;
            weak_ct[1088..].fill(0);
            let rc = unsafe {
                sodium::crypto_kem_xwing_dec(
                    c_dec.as_mut_ptr(),
                    weak_ct.as_ptr(),
                    c_sk.as_ptr(),
                )
            };
            assert_ne!(rc, 0);
            assert!(kp.decapsulate(&weak_ct).is_err());
        }
    }
}