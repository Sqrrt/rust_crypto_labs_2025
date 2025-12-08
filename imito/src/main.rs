use aes::Aes192;
use cipher::{KeyInit, BlockCipherEncrypt, BlockCipherDecrypt};
use sha2::{Sha256, Digest};
use hex;

//XOR массивов произвольной длины
fn xor_arrays<'out>(a: &[u8], b: &[u8], out: &'out mut [u8]) {
    assert_eq!(a.len(), b.len());
    for i in 0..a.len() {
        out[i] = a[i] ^ b[i];
    }
}
//конкатенация массивов
fn concat_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(a.len() + b.len());
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}
//генерация ключей для OMAC
fn gen_keys(key: &[u8; 24]) -> ([u8; 16], [u8; 16]) {
    let zero_block = [0u8; 16];
    let l = aes192_encrypt_block(key, &zero_block);
    let k1 = temp(&l);
    let k2 = temp(&k1);
    (k1, k2)
}

fn temp(block: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        let b = block[i];
        out[i] = (b << 1) | carry;
        carry = (b & 0x80) >> 7;
    }
    if carry != 0 {
        out[15] ^= 0x87;
    }
    out
}

//шифрование блока
pub fn aes192_encrypt_block(key: &[u8; 24], block: &[u8; 16]) -> [u8; 16] {
    let  cipher = Aes192::new(key.into());
    let mut buf = *block;
    cipher.encrypt_block((&mut buf).into());
    buf.into()
}

//расшифрование блока
pub fn aes192_decrypt_block(key: &[u8; 24], block: &[u8; 16]) -> [u8; 16] {
    let  cipher = Aes192::new(key.into());
    let mut buf = *block;
    cipher.decrypt_block((&mut buf).into());
    buf.into()
}

//хеширование
pub fn hasher_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

//генерация ключа для HMAC
pub fn key_gen(data: &String) -> [u8; 64] {
    let bytes = data.as_bytes();
    let mut result = [0u8; 64];
    if bytes.len() <= 64{
        result[..bytes.len()].copy_from_slice(bytes);
    }
    else{
        let r = hasher_sha256(bytes);
        result[..32].copy_from_slice(&r);
    }
    result
}
//это для атаки, чтобы блок не формировался
pub fn one_zeros_pad_zero(data: &[u8], block_size: usize) -> Vec<u8> {
    assert!(block_size > 0 && block_size <= 255);
    let rem = data.len() % block_size;
    if rem == 0 {
        // Уже кратно блоку — не добавляем ничего
        return data.to_vec();
    }
    let pad_len = block_size - rem;
    let mut out = Vec::with_capacity(data.len() + pad_len);
    out.extend_from_slice(data);
    // маркер
    out.push(0x80);
    if pad_len > 1 {
        out.extend(std::iter::repeat(0u8).take(pad_len - 1));
    }
    out
}
//паддинг для OMAC 10...
pub fn one_zeros_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    assert!(block_size <= 255); //так как дополняем последний блок, его длина явно меньше 255, поэтому такое дополнение подходит
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = Vec::from(data);
    if pad_len > 0 {
        padded.push(0x80);
        if pad_len > 1 {
            padded.extend(std::iter::repeat(0u8).take(pad_len - 1));
        }
    }
    padded
}

pub fn imito_cbc_mac(key: &[u8; 24] ,data: &[u8]) -> Vec<u8>{
    let padded_data = one_zeros_pad_zero(data, 16);
    let mut result = [0u8; 16];
    for block in padded_data.chunks(16) {
        let mut res = [0u8; 16];

        let mut block16 = [0u8;16];
        block16.copy_from_slice(block);
        xor_arrays(&result, &block16, &mut res);

        result = aes192_encrypt_block(key, &res);
    }
    result.to_vec()
}
//все верификации одинаковые
pub fn imito_cbc_mac_verify(imito: &[u8], data: &[u8], key: &[u8; 24]) -> bool{
    let new_imito = imito_cbc_mac(key, &data);
    if new_imito == *imito {
        return true
    }
    false
}
pub fn imito_omac(key: &[u8; 24] ,data: &[u8]) -> Vec<u8>{
    let (k1, k2) = gen_keys(key);

    let mut result = [0u8; 16];
    let blocks: Vec<&[u8]> = data.chunks(16).collect();
    let n = blocks.len();
    if n == 0 {
        // пустое сообщение: единственный блок = pad(0) XOR K2
        let block = one_zeros_pad(&[], 16);
        let mut res = [0u8; 16];

        let mut block16 = [0u8;16];
        block16.copy_from_slice(&block);
        xor_arrays(&result, &block16, &mut res);

        result = aes192_encrypt_block(key, &res);
    } else {
        //обрабатываем все блоки кроме последнего
        for block in &blocks[..n-1] {
            let mut res = [0u8; 16];

            let mut block16 = [0u8;16];
            block16.copy_from_slice(block);
            xor_arrays(&result, &block16, &mut res);

            result = aes192_encrypt_block(key, &res);
        }

        //обрабатываем последний блок
        let last = blocks[n-1];
        let mut last_block = [0u8; 16];

        if last.len() == 16 {
            //если полный блок -> XOR с K1
            xor_arrays(last, &k1, &mut last_block);
        } else {
            //если неполный -> паддинг 10... и XOR с K2
            let padded = one_zeros_pad(last, 16);

            let mut padded16 = [0u8; 16];
            padded16.copy_from_slice(&padded);

            xor_arrays(&padded16, &k2, &mut last_block);
        }

        //последний шаг - CBC-MAC
        let mut res = [0u8; 16];
        xor_arrays(&result, &last_block, &mut res);
        result = aes192_encrypt_block(key, &res);
    }
    result.to_vec()
}

pub fn imito_omac_verify(imito: &[u8], data: &[u8], key: &[u8; 24]) -> bool{
    let new_imito = imito_omac(key, &data);
    if new_imito == *imito {
        return true
    }
    false
}

pub fn imito_hmac(key: &[u8; 24] ,data: &[u8]) -> Vec<u8> {
    let s = hex::encode(key);
    let mut xor_ipad = [0u8; 64];
    let mut xor_opad = [0u8; 64];
    //генерация ключа
    let key_plus = key_gen(&s);
    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5C; 64];
    xor_arrays(&IPAD, &key_plus, &mut xor_ipad);
    xor_arrays(&OPAD, &key_plus, &mut xor_opad);
    let h1 = hasher_sha256(&concat_bytes(&xor_ipad, data));
    let h2 = hasher_sha256(&concat_bytes(&xor_opad, &h1));
    h2.to_vec()
}
pub fn imito_hmac_verify(imito: &[u8], data: &[u8], key: &[u8; 24]) -> bool{
    let new_imito = imito_hmac(key, &data);
    if new_imito == *imito {
        return true
    }
    false
}



pub fn forge_cbc_mac_with_oracle<F>(
    tag_oracle: F,
    m: &[u8],
    s_block: &[u8; 16],
) -> (Vec<u8>, Vec<u8>)
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    //получаем тэг для m
    let tag_m = tag_oracle(m);
    assert_eq!(tag_m.len(), 16, "oracle must return 16-byte tag");

    //mid = s_block XOR tag_m
    let mut mid = [0u8; 16];
    for i in 0..16 {
        mid[i] = s_block[i] ^ tag_m[i];
    }

    //forged = m || mid
    let mut forged = Vec::with_capacity(m.len() + 16);
    forged.extend_from_slice(m);
    forged.extend_from_slice(&mid);

    //получаем тег для forged (опционально, но возвращаем)
    let tag_forged = tag_oracle(&forged);

    (forged, tag_forged)
}

fn main() {
    let key = [0x55u8; 24];
    let message = b"Hello, this is a test message for MAC!";
    let empty_message = b"";

    println!("=== Тестирование CBC-MAC ===");
    let cbc_tag = imito_cbc_mac(&key, message);
    println!("CBC-MAC тэг: {}", hex::encode(&cbc_tag));
    assert!(imito_cbc_mac_verify(&cbc_tag, message, &key));
    println!("CBC-MAC верифицировано");

    let cbc_tag_empty = imito_cbc_mac(&key, empty_message);
    assert!(imito_cbc_mac_verify(&cbc_tag_empty, empty_message, &key));
    println!("CBC-MAC (пустое) верифицировано");

    println!("\n=== Тестирование OMAC (CMAC) ===");
    let omac_tag = imito_omac(&key, message);
    println!("OMAC тэг: {}", hex::encode(&omac_tag));
    assert!(imito_omac_verify(&omac_tag, message, &key));
    println!("OMAC верифицировано");

    let omac_tag_empty = imito_omac(&key, empty_message);
    assert!(imito_omac_verify(&omac_tag_empty, empty_message, &key));
    println!("OMAC (пустое) верифицировано");

    println!("\n=== Тестирование HMAC ===");
    let hmac_tag = imito_hmac(&key, message);
    println!("HMAC тэг: {}", hex::encode(&hmac_tag));
    assert!(imito_hmac_verify(&hmac_tag, message, &key));
    println!("HMAC верифицировано");

    let hmac_tag_empty = imito_hmac(&key, empty_message);
    assert!(imito_hmac_verify(&hmac_tag_empty, empty_message, &key));
    println!("HMAC (пустое) верифицировано");

    println!("\n=== Атака на CBC-MAC ===");
    let cbc_oracle = |data: &[u8]| -> Vec<u8> {
        imito_cbc_mac(&key, data)
    };

    let m = b"Pay Alice 100$ for candy!";
    // Нужен S — ровно 16-байтный блок для подделки
    const S_BLOCK: &[u8] = b"and to Bob 100$!";

    let s_block_arr: [u8; 16] = S_BLOCK.try_into().unwrap();

    println!("Исходное сообщение: {:?}", std::str::from_utf8(m).unwrap_or("invalid"));
    println!("Блок для подделки: {:?}", std::str::from_utf8(&s_block_arr).unwrap_or("invalid"));

    let (forged_message, forged_tag) = forge_cbc_mac_with_oracle(cbc_oracle, m, &s_block_arr);

    println!("Поддельное сообщение: {}", hex::encode(&forged_message));
    println!("Поддельный тег: {}", hex::encode(&forged_tag));

    if imito_cbc_mac_verify(&forged_tag, &forged_message, &key) {
        println!("Атака успешна: поддельный тег принят CBC-MAC!");
    } else {
        println!("Атака провалилась");
    }

    println!("\n=== Проверка устойчивости OMAC ===");
    let forged_omac_tag = imito_omac(&key, &forged_message);
    if forged_omac_tag == forged_tag {
        println!("OMAC уязвим? Это странно!");
    } else {
        println!("OMAC отклонил поддельный тег — устойчив к атаке!");
    }
}