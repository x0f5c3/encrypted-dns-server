#![allow(dead_code)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use libsodium_sys as sodium;
use zeroize::Zeroizing;

// Compile the actual production implementation into this benchmark.
mod errors {
    pub use anyhow::{anyhow, ensure, Error};
}

#[path = "../src/crypto.rs"]
mod crypto;

#[path = "../src/pq.rs"]
mod pq;

use crypto::{CryptKeyPair, CryptPK, CryptSK, SharedKey, SignSK};
use pq::XWingKeyPair;

const NONCE: [u8; 24] = [0x07; 24];

fn c_classical_keypair(seed: &[u8; 32]) -> CryptKeyPair {
    let mut pk = [0u8; 32];
    let mut sk = Zeroizing::new([0u8; 32]);
    let rc = unsafe {
        sodium::crypto_box_curve25519xchacha20poly1305_seed_keypair(
            pk.as_mut_ptr(),
            sk.as_mut_ptr(),
            seed.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    CryptKeyPair {
        sk: CryptSK::from_bytes(*sk),
        pk: CryptPK::from_bytes(pk),
    }
}

fn c_shared_key(kp: &CryptKeyPair, peer_pk: &[u8; 32]) -> SharedKey {
    let mut key = Zeroizing::new([0u8; 32]);
    let rc = unsafe {
        sodium::crypto_box_curve25519xchacha20poly1305_beforenm(
            key.as_mut_ptr(),
            peer_pk.as_ptr(),
            kp.sk.as_bytes().as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    SharedKey::from_bytes(*key)
}

fn c_sign(sk: &SignSK, message: &[u8]) -> [u8; 64] {
    let mut signature = [0u8; 64];
    let rc = unsafe {
        sodium::crypto_sign_detached(
            signature.as_mut_ptr(),
            std::ptr::null_mut(),
            message.as_ptr(),
            message.len() as _,
            sk.as_bytes().as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    signature
}

fn c_seal(key: &SharedKey, nonce: &[u8; 24], message: &[u8]) -> Vec<u8> {
    let mut encrypted = vec![0u8; message.len() + 16];
    let rc = unsafe {
        sodium::crypto_box_curve25519xchacha20poly1305_easy_afternm(
            encrypted.as_mut_ptr(),
            message.as_ptr(),
            message.len() as _,
            nonce.as_ptr(),
            key.as_raw_bytes().as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    encrypted
}

fn c_open(key: &SharedKey, nonce: &[u8; 24], encrypted: &[u8]) -> Vec<u8> {
    assert!(encrypted.len() >= 16);
    let mut plaintext = vec![0u8; encrypted.len() - 16];
    let rc = unsafe {
        sodium::crypto_box_curve25519xchacha20poly1305_open_easy_afternm(
            plaintext.as_mut_ptr(),
            encrypted.as_ptr(),
            encrypted.len() as _,
            nonce.as_ptr(),
            key.as_raw_bytes().as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    plaintext
}

fn c_sha256(message: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let rc = unsafe {
        sodium::crypto_hash_sha256(
            hash.as_mut_ptr(),
            message.as_ptr(),
            message.len() as _,
        )
    };
    assert_eq!(rc, 0);
    hash
}

fn c_hkdf(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut prk = Zeroizing::new([0u8; 32]);
    let mut output = [0u8; 32];
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
                output.as_mut_ptr(),
                output.len() as _,
                info.as_ptr().cast(),
                info.len() as _,
                prk.as_ptr(),
            ),
            0
        );
    }
    output
}

fn c_xwing_public_key(seed: &[u8; 32]) -> [u8; pq::XWING_PK_SIZE] {
    let mut pk = [0u8; pq::XWING_PK_SIZE];
    let mut sk = Zeroizing::new([0u8; 32]);
    let rc = unsafe {
        sodium::crypto_kem_xwing_seed_keypair(
            pk.as_mut_ptr(),
            sk.as_mut_ptr(),
            seed.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    pk
}

fn c_xwing_decapsulate(
    seed: &[u8; 32],
    ct: &[u8; pq::XWING_CT_SIZE],
) -> [u8; 32] {
    let mut ss = Zeroizing::new([0u8; 32]);
    let rc = unsafe {
        sodium::crypto_kem_xwing_dec(
            ss.as_mut_ptr(),
            ct.as_ptr(),
            seed.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    *ss
}

fn bench_backends(c: &mut Criterion) {
    unsafe {
        assert!(sodium::sodium_init() >= 0);
    }
    crypto::init().unwrap();

    // Fixture verification happens before any timed measurements.
    // The full compatibility suite should also be run with the command below.
    let seed = [0x20; 32];
    let kp = CryptKeyPair::from_seed(seed);
    let c_kp = c_classical_keypair(&seed);
    assert_eq!(kp.pk.as_bytes(), c_kp.pk.as_bytes());
    assert_eq!(kp.sk.as_bytes(), c_kp.sk.as_bytes());

    let peer = CryptKeyPair::from_seed([0x40; 32]);
    let key = kp.compute_shared_key(peer.pk.as_bytes()).unwrap();
    assert_eq!(
        key.as_raw_bytes(),
        c_shared_key(&kp, peer.pk.as_bytes()).as_raw_bytes()
    );

    let (sign_pk, sign_sk) =
        dryoc::classic::crypto_sign::crypto_sign_seed_keypair(&seed);
    let sign_sk = SignSK::from_bytes(sign_sk);
    let signature = sign_sk.sign(b"benchmark fixture");
    assert_eq!(
        signature.as_bytes(),
        &c_sign(&sign_sk, b"benchmark fixture")
    );
    unsafe {
        assert_eq!(
            sodium::crypto_sign_verify_detached(
                signature.as_bytes().as_ptr(),
                b"benchmark fixture".as_ptr(),
                b"benchmark fixture".len() as _,
                sign_pk.as_ptr(),
            ),
            0
        );
    }

    let xwing_kp = XWingKeyPair::from_seed(seed);
    let xwing_pk = xwing_kp.public_key_bytes();
    assert_eq!(xwing_pk, c_xwing_public_key(&seed));

    let mut ct = [0u8; pq::XWING_CT_SIZE];
    let mut ss = [0u8; 32];
    dryoc::classic::crypto_kem_xwing::crypto_kem_xwing_enc_deterministic(
        &mut ct,
        &mut ss,
        &xwing_pk,
        &[0x40; 64],
    )
        .unwrap();

    let mut c_ct = [0u8; pq::XWING_CT_SIZE];
    let mut c_ss = [0u8; 32];
    unsafe {
        assert_eq!(
            sodium::crypto_kem_xwing_enc_deterministic(
                c_ct.as_mut_ptr(),
                c_ss.as_mut_ptr(),
                xwing_pk.as_ptr(),
                [0x40u8; 64].as_ptr(),
            ),
            0
        );
    }
    assert_eq!(ct, c_ct);
    assert_eq!(ss, c_ss);
    assert_eq!(xwing_kp.decapsulate(&ct).unwrap(), ss);
    assert_eq!(c_xwing_decapsulate(&seed, &ct), ss);

    let sizes = [32usize, 64, 256, 512, 1232, 4096, 65535];
    let messages: Vec<Vec<u8>> = sizes
        .iter()
        .map(|&len| {
            (0..len)
                .map(|i| (i as u8).wrapping_mul(31))
                .collect()
        })
        .collect();
    let encrypted: Vec<Vec<u8>> = messages
        .iter()
        .map(|message| {
            let rust_ct = key.seal_raw(&NONCE, message);
            let c_ct = c_seal(&key, &NONCE, message);
            assert_eq!(rust_ct, c_ct);
            assert_eq!(key.open_raw(&NONCE, &c_ct).unwrap(), *message);
            assert_eq!(c_open(&key, &NONCE, &rust_ct), *message);
            assert_eq!(pq::sha256(message), c_sha256(message));
            assert_eq!(
                sign_sk.sign(message).as_bytes(),
                &c_sign(&sign_sk, message)
            );
            rust_ct
        })
        .collect();

    let salt = [0x24; 10];
    let ikm = [0x42; 32];
    let info = vec![0x80; 2400];
    let mut hkdf_output = [0u8; 32];
    pq::hkdf_sha256(&salt, &ikm, &info, &mut hkdf_output);
    assert_eq!(hkdf_output, c_hkdf(&salt, &ikm, &info));

    {
        let mut group = c.benchmark_group("classical_seed_keypair");
        group.bench_function("rust", |b| {
            b.iter(|| CryptKeyPair::from_seed(black_box(seed)))
        });
        group.bench_function("sodium", |b| {
            b.iter(|| c_classical_keypair(black_box(&seed)))
        });
        group.finish();
    }

    {
        let mut group = c.benchmark_group("classical_shared_key");
        group.bench_function("rust", |b| {
            b.iter(|| {
                black_box(&kp)
                    .compute_shared_key(black_box(peer.pk.as_bytes()))
                    .unwrap()
            })
        });
        group.bench_function("sodium", |b| {
            b.iter(|| c_shared_key(black_box(&kp), black_box(peer.pk.as_bytes())))
        });
        group.finish();
    }

    {
        let mut group = c.benchmark_group("secretbox_seal");
        for message in &messages {
            group.throughput(Throughput::Bytes(message.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("rust", message.len()),
                message,
                |b, message| {
                    b.iter(|| {
                        black_box(&key).seal_raw(
                            black_box(&NONCE),
                            black_box(message),
                        )
                    })
                },
            );
            group.bench_with_input(
                BenchmarkId::new("sodium", message.len()),
                message,
                |b, message| {
                    b.iter(|| {
                        c_seal(
                            black_box(&key),
                            black_box(&NONCE),
                            black_box(message),
                        )
                    })
                },
            );
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("secretbox_open");
        for (message, ciphertext) in messages.iter().zip(&encrypted) {
            group.throughput(Throughput::Bytes(message.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("rust", message.len()),
                ciphertext,
                |b, ciphertext| {
                    b.iter(|| {
                        black_box(&key)
                            .open_raw(black_box(&NONCE), black_box(ciphertext))
                            .unwrap()
                    })
                },
            );
            group.bench_with_input(
                BenchmarkId::new("sodium", message.len()),
                ciphertext,
                |b, ciphertext| {
                    b.iter(|| {
                        c_open(
                            black_box(&key),
                            black_box(&NONCE),
                            black_box(ciphertext),
                        )
                    })
                },
            );
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("sha256");
        for message in &messages {
            group.throughput(Throughput::Bytes(message.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("rust", message.len()),
                message,
                |b, message| b.iter(|| pq::sha256(black_box(message))),
            );
            group.bench_with_input(
                BenchmarkId::new("sodium", message.len()),
                message,
                |b, message| b.iter(|| c_sha256(black_box(message))),
            );
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("ed25519_sign");
        for message in &messages {
            group.throughput(Throughput::Bytes(message.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("rust", message.len()),
                message,
                |b, message| {
                    b.iter(|| black_box(&sign_sk).sign(black_box(message)))
                },
            );
            group.bench_with_input(
                BenchmarkId::new("sodium", message.len()),
                message,
                |b, message| {
                    b.iter(|| c_sign(black_box(&sign_sk), black_box(message)))
                },
            );
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("hkdf_sha256_32");
        group.bench_function("rust", |b| {
            b.iter(|| {
                let mut output = [0u8; 32];
                pq::hkdf_sha256(
                    black_box(&salt),
                    black_box(&ikm),
                    black_box(&info),
                    &mut output,
                );
                black_box(output)
            })
        });
        group.bench_function("sodium", |b| {
            b.iter(|| {
                c_hkdf(
                    black_box(&salt),
                    black_box(&ikm),
                    black_box(&info),
                )
            })
        });
        group.finish();
    }

    {
        let mut group = c.benchmark_group("xwing_public_key");
        group.bench_function("rust", |b| {
            b.iter(|| black_box(&xwing_kp).public_key_bytes())
        });
        group.bench_function("sodium", |b| {
            b.iter(|| c_xwing_public_key(black_box(&seed)))
        });
        group.finish();
    }

    {
        let mut group = c.benchmark_group("xwing_decapsulate");
        group.bench_function("rust", |b| {
            b.iter(|| {
                black_box(&xwing_kp)
                    .decapsulate(black_box(&ct))
                    .unwrap()
            })
        });
        group.bench_function("sodium", |b| {
            b.iter(|| c_xwing_decapsulate(black_box(&seed), black_box(&ct)))
        });
        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(5))
        .sample_size(50);
    targets = bench_backends
}
criterion_main!(benches);