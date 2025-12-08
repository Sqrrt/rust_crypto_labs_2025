use num_traits::identities::Zero;
use num_traits::identities::One;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use rand::RngCore;
use sha2::{Digest, Sha256};

//структуры для хранения
#[derive(Clone)]
pub struct Rsa {
    pub pk: RsaPublicKey,
    pub sk: RsaSecretKey,
}
#[derive(Clone)]
pub struct RsaPublicKey {
    pub n: BigUint,
    pub e: BigUint,
}
#[derive(Clone)]
pub struct RsaSecretKey {
    pub n: BigUint,
    pub d: BigUint,
}
#[allow(warnings)]
impl Rsa {
    //генерация
    pub fn KGen(l: usize) -> Self {
        let mut rng = rand::thread_rng();
        //простые p и q
        let p = Self::generate_prime(l, &mut rng);
        let q = Self::generate_prime(l, &mut rng);
        //модуль и функция эйлера
        let n = &p * &q;
        let phi = (&p - 1u32) * (&q - 1u32);
        let mut e = BigUint::from(65537u32);
        if BigUint::from(65537u32) > phi {
            eprintln!("очень маленькие простые числа, e решено выбрать трём");
            e = BigUint::from(3u32);
        }
        let d = modinv(&e, &phi).expect("должен существовать обратный");

        //вывод ключей
        let pk = RsaPublicKey { n: n.clone(), e };
        let sk = RsaSecretKey { n, d };
        Self { pk, sk }
    }
    //подпись
    pub fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {

        let hash = Sha256::digest(message);
        let y = BigUint::from_bytes_be(&hash);

        //необходимо, чтобы y < N
        if y >= self.sk.n {
            eprintln!("нужен меньший хэш или больший ключ");
            return None;
        }

        let sigma = y.modpow(&self.sk.d, &self.sk.n);
        Some(sigma.to_bytes_be())
    }

    //верификация
    pub fn verify(&self, message: &[u8], sigma_bytes: &[u8]) -> bool {

        let sigma = BigUint::from_bytes_be(sigma_bytes);
        let y_prime = sigma.modpow(&self.pk.e, &self.pk.n);

        let hash = Sha256::digest(message);
        let y = BigUint::from_bytes_be(&hash);
        y_prime == y
    }

    //генерация простого числа заданной длины
    fn generate_prime(bits: usize, rng: &mut impl RngCore) -> BigUint {
        loop {
            let mut candidate = rng.gen_biguint(bits as u64);
            //проверка, что число >= 3 и нечётное
            if candidate < BigUint::from(3u32) {
                candidate = BigUint::from(3u32);
            }
            if candidate.bit(0) == false {
                candidate += 1u32;
            }
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