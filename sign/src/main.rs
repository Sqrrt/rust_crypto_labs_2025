mod rsa;
mod rabin;
use num_bigint::BigUint;
use rand::RngCore;
use rsa::{Rsa, RsaPublicKey, RsaSecretKey};
use rabin::Rabin;
//сертификат: (ID, публичный ключ, подпись УЦ)
#[derive(Clone)]
pub struct Certificate {
    id: String,
    pk: RsaPublicKey,
    sigma_ca: Vec<u8>,
}

//сериализация публичного ключа в байты, чтобы можно было подписывать
fn serialize_pk(pk: &RsaPublicKey) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&pk.n.to_bytes_be());
    buf.extend_from_slice(&pk.e.to_bytes_be());
    buf
}
//генерация ключевой пары
pub struct CertRequest {
    pub pk_user: RsaPublicKey,
    pub sigma_user: Vec<u8>,
}
pub fn user_generate_request(user_rsa: &Rsa) -> CertRequest {
    let pk_bytes = serialize_pk(&user_rsa.pk);
    let sigma_user = user_rsa
        .sign(&pk_bytes)
        .expect("не удалось подписать открытый ключ");
    CertRequest {
        pk_user: user_rsa.pk.clone(),
        sigma_user,
    }
}
pub fn ca_issue_certificate(request: &CertRequest, ca_rsa: &Rsa) -> Option<Certificate> {
    //проверка подписи пользователя
    let pk_bytes = serialize_pk(&request.pk_user);
    let user_verifier = Rsa {
        pk: request.pk_user.clone(),
        sk: RsaSecretKey {
            n: BigUint::from(1u32),
            d: BigUint::from(1u32),
        },
    };
    if !user_verifier.verify(&pk_bytes, &request.sigma_user) {
        return None; //неверная подпись
    }

    //генерация ID
    let id = {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        format!("ID-{:02x}{:02x}{:02x}{:02x}", buf[0], buf[1], buf[2], buf[3])
    };

    //формирование сообщения для подписи УЦ
    let mut msg = id.as_bytes().to_vec();
    msg.extend_from_slice(&serialize_pk(&request.pk_user));

    //подпись УЦ
    let sigma_ca = ca_rsa.sign(&msg)?;

    Some(Certificate {
        id,
        pk: request.pk_user.clone(),
        sigma_ca,
    })
}
//проверка сертификата
pub fn user_verify_certificate(cert: &Certificate, ca_pk: &RsaPublicKey) -> bool {
    let mut msg = cert.id.as_bytes().to_vec();
    msg.extend_from_slice(&serialize_pk(&cert.pk));

    let ca_verifier = Rsa {
        pk: ca_pk.clone(),
        sk: RsaSecretKey {
            n: BigUint::from(1u32),
            d: BigUint::from(1u32),
        },
    };
    ca_verifier.verify(&msg, &cert.sigma_ca)
}

fn main() {
    //тестирование RSA
    println!("RSA test:");
    let rsa = Rsa::KGen(512);
    let mut msg = b"This is so secret!";
    println!("   Сообщение: {}", std::str::from_utf8(msg).unwrap());
    let sig = rsa.sign(msg).expect("Подпись RSA");
    let valid = rsa.verify(msg, &sig);
    println!("   Подпись: {}", if valid { "валидна" } else { "недействительна" });
    assert!(valid, "Несоответствие подписи!");
    msg = b"I change it AHAHA!";
    println!("   Сообщение: {}", std::str::from_utf8(msg).unwrap());
    let forged = rsa.verify(msg, &sig);
    println!("   Подпись: {}", if forged { "валидна" } else { "недействительна" });
    assert!(!forged, "Соответствие некорректной подписи!");
    //тестирование Rabin
    println!("Rabin test:");
    let rabin = Rabin::KGen(512);
    let mut msg = b"Rabin message with secret!";
    println!("   Сообщение: {}", std::str::from_utf8(msg).unwrap());
    //println!("Исходное сообщение: {:?}", msg);
    let c = rabin.Enc(msg).expect("Ошибка шифрования");
    //println!("Шифртекст: {:x?}", c);
    let roots1 = rabin.Dec(&c);

    /*println!("4 корня расшифрования:");
    for (i, r) in roots1.iter().enumerate() {
        println!("  root {}: {:?}", i + 1, r);
    }*/

    let msg_big = BigUint::from_bytes_be(msg);
    let mut found = false;
    for r in &roots1 {
        if BigUint::from_bytes_be(r) == msg_big {
            found = true;
            break;
        }
    }
    println!("   Проверка: сообщение найдено среди корней? {}", found);
    assert!(found, "   Изначальное сообщение отсутствует среди корней Рабина!");

    msg = b"Ooops, I changed it again!";
    println!("   Сообщение: {}", std::str::from_utf8(msg).unwrap());
    let roots2 = rabin.Dec(&c);

    /*println!("4 корня расшифрования:");
    for (i, r) in roots2.iter().enumerate() {
        println!("  root {}: {:?}", i + 1, r);
    }*/

    let msg_big = BigUint::from_bytes_be(msg);
    found = false;
    for r in &roots2 {
        if BigUint::from_bytes_be(r) == msg_big {
            found = true;
            break;
        }
    }
    println!("   Проверка: сообщение найдено среди корней? {}", found);
    assert!(!found, "   Испорченное сообщение присутствует среди корней Рабина!");
    //тест сертификата
    println!("Cert test:");


    let user_rsa = Rsa::KGen(512);
    let ca_rsa = Rsa::KGen(512);

    //запрос на сертификат
    let request = user_generate_request(&user_rsa);
    println!("   Сертификат создан");

    //выпуск сертификата
    let cert = ca_issue_certificate(&request, &ca_rsa)
        .expect("Ошибка");
    println!("   Сертификат выпущен с ID: {}", cert.id);

    //проверка сертификата
    let valid = user_verify_certificate(&cert, &ca_rsa.pk);
    println!("   Проверка сертификата: {}", if valid { "OK" } else { "FAIL" });

    assert!(valid, "Сертификат некорректен");

    let mut fake_cert = cert.clone();
    fake_cert.id = "ID-0000FFFF".to_string(); // испортим ID
    let forged = user_verify_certificate(&fake_cert, &ca_rsa.pk);

    println!("   Проверка сертификата {}", if forged { "OK" } else { "FAIL" });
    assert!(!forged, "Испорченный сертификат корректен");
}