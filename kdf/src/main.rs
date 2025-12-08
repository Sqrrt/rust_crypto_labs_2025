use hmac::{Hmac, Mac};
use sha2::Sha256;
pub use pbkdf2::pbkdf2; //ТОЛЬКО ДЛЯ ТЕСТОВ!!!
//pub use hkdf::Hkdf; //ТОЛЬКО ДЛЯ ТЕСТОВ!!!

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC init не должен падать");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hkdf_hmac_sha256(skm: &[u8], xts: &[u8], ctx_info: &[u8], l: usize) -> Vec<u8> {
    const HASH_LEN: usize = 32;

    //extract шаг
    let prk = hmac_sha256(xts, skm);
    //expand шаг
    let t = (l + HASH_LEN - 1) / HASH_LEN; // округление вверх как раз
    let mut result = Vec::with_capacity(t * HASH_LEN);
    let mut k_prev = Vec::new();
    for i in 1..=t {
        // Собираем вход: T(i-1) || CTXInfo || i
        let mut input = Vec::new();
        input.extend_from_slice(&k_prev);      // добавляем предыдущее k
        input.extend_from_slice(ctx_info);     // добавляем ctx_info
        input.push(i as u8);                   // добавляем i
        k_prev = hmac_sha256(&prk, &input);
        result.extend_from_slice(&k_prev);
    }

    //длина l
    result.truncate(l);
    result
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, vec_len: usize) -> Vec<u8> {
    const HASH_LEN: usize = 32; // SHA-256
    let dk_len = vec_len;

    if dk_len == 0 {
        return Vec::new();
    }
    let l = (dk_len + HASH_LEN - 1) / HASH_LEN; //также округление вверх
    let mut result = Vec::with_capacity(l * HASH_LEN);
    for i in 1..=l {
        let mut salt_i = Vec::with_capacity(salt.len() + 4);
        salt_i.extend_from_slice(salt);
        let i_bytes = (i as u32).to_be_bytes();
        salt_i.extend_from_slice(&i_bytes);
        let mut u = hmac_sha256(password, &salt_i);
        let mut t = u.clone();

        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for (t_byte, u_byte) in t.iter_mut().zip(u.iter()) {
                *t_byte ^= *u_byte;
            }
        }

        result.extend_from_slice(&t);
    }
    result
}

fn kdf_j(j: u8, key: &[u8], d: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.push(0x01);                     // 0x01
    input.extend_from_slice(b"level");    // level
    input.push(b'0' + j);                 // j -> level1, level2, level3
    input.push(0x00);                     // 0x00
    input.extend_from_slice(d);                 // D
    input.push(0x01);                     // 0x01
    input.push(0x00);                     // 0x00

    hmac_sha256(key, &input)
}
fn str8(x: u64) -> [u8; 8] {
    x.to_be_bytes()
}
#[allow(warnings)]
struct TlsTreeDebug {
    d1: [u8; 8],
    d2: [u8; 8],
    d3: [u8; 8],
    k1: Vec<u8>,
    k2: Vec<u8>,
    k3: Vec<u8>,
}
fn tlstree_debug(root: &[u8], i: u64) -> (Vec<u8>, TlsTreeDebug) {
    const C1: u16 = 0x69B1;
    const C2: u16 = 0x8040;
    const C3: u16 = 0x4D20;

    let d1 = str8(i & (C1 as u64));
    let k1 = kdf_j(1, root, &d1);

    let d2 = str8(i & (C2 as u64));
    let k2 = kdf_j(2, &k1, &d2);

    let d3 = str8(i & (C3 as u64));
    let k3 = kdf_j(3, &k2, &d3);

    (
        k3.clone(),
        TlsTreeDebug { d1, d2, d3, k1, k2, k3 },
    )
}
fn tlstree(root: &[u8], i: u64) -> Vec<u8> {
    // Константы из Р 1323565.1.030—2020
    const C1: u16 = 0x69B1;
    const C2: u16 = 0x8040;
    const C3: u16 = 0x4D20;

    // STR8(i & C1)
    let d1 = str8(i & (C1 as u64));
    let k1 = kdf_j(1, root, &d1);

    // STR8(i & C2)
    let d2 = str8(i & (C2 as u64));
    let k2 = kdf_j(2, &k1, &d2);

    // STR8(i & C3)
    let d3 = str8(i & (C3 as u64));
    let k3 = kdf_j(3, &k2, &d3);
    k3
}
//так как надо для различных длин проверить + разные константы для tlstree, то тут удобнее будет через тесты
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hkdf_different_lengths() {
        let skm = b"my-secret-key-material";
        let xts = b"random-salt-123";
        let ctx = b"context-info";

        //разные длины
        let len1 = 32;
        let len2 = 64;
        let len3 = 96;

        let k1 = hkdf_hmac_sha256(skm, xts, ctx, len1);
        let k2 = hkdf_hmac_sha256(skm, xts, ctx, len2);
        let k3 = hkdf_hmac_sha256(skm, xts, ctx, len3);

        assert_eq!(k1.len(), len1);
        assert_eq!(k2.len(), len2);
        assert_eq!(k3.len(), len3);

        //первые 16 байт k2 и k3 должны совпадать с k1
        assert_eq!(&k2[..len1], &k1[..]);
        assert_eq!(&k3[..len1], &k1[..]);
    }

    #[test]
    fn test_hkdf_different_inputs() {
        let skm1 = b"secret1";
        let skm2 = b"secret2";
        let xts1 = b"saltA";
        let xts2 = b"saltB";
        let ctx1 = b"ctx1";
        let ctx2 = b"ctx2";

        let k1 = hkdf_hmac_sha256(skm1, xts1, ctx1, 32);
        let k2 = hkdf_hmac_sha256(skm2, xts1, ctx1, 32);
        let k3 = hkdf_hmac_sha256(skm1, xts2, ctx1, 32);
        let k4 = hkdf_hmac_sha256(skm1, xts1, ctx2, 32);

        //все ключи должны быть разными
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, k4);
        assert_ne!(k2, k3);
        assert_ne!(k2, k4);
        assert_ne!(k3, k4);
    }

    #[test]
    fn test_pbkdf2_different_iterations() {
        let password = b"password123";
        let salt = b"salt456";
        let len = 32usize;

        let k100 = pbkdf2_hmac_sha256(password, salt, 100, len);
        let k1000 = pbkdf2_hmac_sha256(password, salt, 1000, len);
        let k5000 = pbkdf2_hmac_sha256(password, salt, 5000, len);

        assert_ne!(k100, k1000);
        assert_ne!(k1000, k5000);
        assert_ne!(k100, k5000);
    }
    #[test]
    fn test_pbkdf2_different_lengths() {
        let password = b"password123";
        let salt = b"salt456";
        let iterations = 1000;

        let k16 = pbkdf2_hmac_sha256(password, salt, iterations, 32);
        let k32 = pbkdf2_hmac_sha256(password, salt, iterations, 64);
        let k48 = pbkdf2_hmac_sha256(password, salt, iterations, 96);

        assert_eq!(k16.len(), 32);
        assert_eq!(k32.len(), 64);
        assert_eq!(k48.len(), 96);
    }
    #[test]
    fn test_pbkdf2_same_input_same_output() {
        let password = b"test-pass";
        let salt = b"test-salt";
        let iterations = 2048;
        let len = 48usize;

        let k1 = pbkdf2_hmac_sha256(password, salt, iterations, len);
        let k2 = pbkdf2_hmac_sha256(password, salt, iterations, len);

        assert_eq!(k1, k2); //детерминированность
    }

    #[test]
    fn test_pbkdf2_known_answer() {
        let password = b"cactus_polivaetsya_po_credam";
        let salt = b"salt";
        let iterations = 1;
        let r = 32;
        let mut output = [0u8; 32];

        let derived = pbkdf2_hmac_sha256(password, salt, iterations, r);

        pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut output).expect("invalid_len");

        assert_eq!(derived, output);
    }
    #[test]
    fn test_tlstree_conditions() {
        let root = b"rootrootrootroot";

        //значения i
        let i_a = 0x0000u64;
        let i_b = 0x0001u64;
        let i_c = 0x8000u64;
        let i_d = 0xC000u64;

        let (k_a, dbg_a) = tlstree_debug(root, i_a);
        let (k_b, _dbg_b) = tlstree_debug(root, i_b);
        let (k_c, dbg_c) = tlstree_debug(root, i_c);
        let (k_d, dbg_d) = tlstree_debug(root, i_d);

        //хотя бы у двух — разные i & C1 => ключи разные
        assert_ne!(k_a, k_b);

        //равные i&C1, но разные i&C2 => ключи разные
        assert_eq!(dbg_a.d1, dbg_c.d1, "C1 должны совпадать");
        assert_ne!(dbg_a.d2, dbg_c.d2, "C2 должны различаться");
        assert_ne!(k_a, k_c);

        //равные i&C2, но разные i&C3 => ключи разные
        assert_eq!(dbg_c.d2, dbg_d.d2, "C2 должны совпадать");
        assert_ne!(dbg_c.d3, dbg_d.d3, "C3 должны различаться");
        assert_ne!(k_c, k_d);

        //детерминированность
        let (k_a2, dbg_a2) = tlstree_debug(root, i_a);
        assert_eq!(k_a, k_a2);
        assert_eq!(dbg_a.k3, dbg_a2.k3);
    }
}


fn main() {
    println!("hkdf");
    let skm = b"stul_ne_skripit";
    let xts = b"pepper_lol";
    let ctx = b"contexta_net";
    let hkdf_key = hkdf_hmac_sha256(skm, xts, ctx, 32);
    println!("HKDF:               {}", hex::encode(&hkdf_key));

    println!("PBKDF2");
    let password = b"my_super_password_is_qwerty";
    let salt = b"im_a_super_unique_user";
    let pbkdf2_key = pbkdf2_hmac_sha256(password, salt, 333, 32);
    println!("PBKDF2:             {}", hex::encode(&pbkdf2_key));

    println!("TLSTREE");
    let root_key = b"rootrootrootroot";
    let i_values = [0u64, 1, 32768, 49152];
    for &i in &i_values {
        let tlstree_key = tlstree(root_key, i);
        println!("TLSTREE(i={:>6}) = {}", i, hex::encode(&tlstree_key));
    }
}
