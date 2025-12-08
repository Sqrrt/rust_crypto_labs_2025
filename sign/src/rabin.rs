use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_traits::{One, Zero};
use rand::RngCore;

pub struct Rabin {
    pub vk: RabinPublicKey,
    pub sk: RabinSecretKey,
}
pub struct RabinPublicKey {
    pub n: BigUint,
}

pub struct RabinSecretKey {
    pub p: BigUint,
    pub q: BigUint,
}
#[allow(warnings)]
impl Rabin {
    pub fn KGen(l: usize) -> Self{
        let mut rng = rand::thread_rng();
        let p = Self::generate_prime_3mod4(l,&mut rng);
        let q = Self::generate_prime_3mod4(l,&mut rng);
        let n = &p * &q;
        let vk = RabinPublicKey { n};
        let sk = RabinSecretKey { p, q};
        Self{vk, sk}
    }
    pub fn Enc(&self, message: &[u8]) -> Option<Vec<u8>> {
        let m = BigUint::from_bytes_be(message);
        if m >= self.vk.n {
            eprintln!("Ошибка: сообщение >= N, шифрование невозможно");
            return None;
        }
        let c = m.modpow(&BigUint::from(2u32), &self.vk.n);
        Some(c.to_bytes_be())
    }
    pub fn Dec(&self, message: &[u8]) -> [Vec<u8>; 4] {
        let (p, q) = (&self.sk.p, &self.sk.q);
        let c = BigUint::from_bytes_be(message);
        //a = +- c^((p+1)/4) mod p
        let exp_p = (p + BigUint::from(1u32)) >> 2;
        let a = c.modpow(&exp_p, p);
        let a1 = a.clone();
        let a2 = (p - a) % p;

        //b = +- c^((q+1)/4) mod q
        let exp_q = (q + BigUint::from(1u32)) >> 2;
        let b = c.modpow(&exp_q, q);
        let b1 = b.clone();
        let b2 = (q - b) % q;

        //кто
        let m11 = crt(&a1, p, &b1, q, &self.vk.n);
        let m12 = crt(&a1, p, &b2, q, &self.vk.n);
        let m21 = crt(&a2, p, &b1, q, &self.vk.n);
        let m22 = crt(&a2, p, &b2, q, &self.vk.n);

        let roots = [m11, m12, m21, m22];

        roots.map(|r| r.to_bytes_be())
    }
    //генерация простого числа заданной длины и остатком
    fn generate_prime_3mod4(bits: usize, rng: &mut impl RngCore) -> BigUint {
        loop {
            //кандидат с битом 0 = 1 (нечётный) b битом 1 = 1
            let mut candidate = rng.gen_biguint(bits as u64);
            if candidate < BigUint::from(3u32) {
                candidate = BigUint::from(3u32);
            }

            //последние два бита - 11
            candidate.set_bit(0, true);
            candidate.set_bit(1, true);

            if Self::is_probably_prime(&candidate) {
                return candidate;
            }
        }
    }
    //тест Миллера-Рабина (10 раундов)
    fn is_probably_prime(n: &BigUint) -> bool {
        if *n <= BigUint::from(1u32) { return false; }
        if *n <= BigUint::from(3u32) { return true; }
        if n.bit(0) == false { return false; }

        let mut d = n - 1u32;
        let mut s = 0;
        while d.bit(0) == false {
            d >>= 1;
            s += 1;
        }

        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - 1u32));
            let mut x = a.modpow(&d, n);
            if x == BigUint::from(1u32)|| x == n - 1u32 {
                continue;
            }
            let mut composite = true;
            for _ in 1..s {
                x = x.modpow(&BigUint::from(2u32), n);
                if x == n - 1u32 {
                    composite = false;
                    break;
                }
            }
            if composite {
                return false;
            }
        }
        true
    }
}
//обратный элемент по модулю
pub fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = m.to_bigint().unwrap();
    let mut new_r = a.to_bigint().unwrap();

    while !new_r.is_zero() {
        let quotient = &r / &new_r;

        let temp_t = new_t.clone();
        new_t = &t - &quotient * &new_t;
        t = temp_t;

        let temp_r = new_r.clone();
        new_r = &r - &quotient * &new_r;
        r = temp_r;
    }

    if r != BigInt::one() {
        return None;
    }
    if t < BigInt::zero() {
        t = t % m.to_bigint().unwrap() + m.to_bigint().unwrap();
    }

    Some(t.to_biguint().unwrap())
}
//КТО
fn crt(a: &BigUint, p: &BigUint, b: &BigUint, q: &BigUint, n: &BigUint) -> BigUint {
    let q_inv = modinv(q, p).expect("q^(-1) mod p");
    let p_inv = modinv(p, q).expect("p^(-1) mod q");

    let term1 = a * q * &q_inv;
    let term2 = b * p * &p_inv;
    (term1 + term2) % n
}