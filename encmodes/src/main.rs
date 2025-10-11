use aes::Aes192;
use cipher::{KeyInit, BlockCipherEncrypt, BlockCipherDecrypt};
use rand::Rng;
use std::time::Instant;

//генерация iv
pub fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    rand::rng().fill(&mut iv);
    iv
}

//генерация случаного iv длины 8 байт для режима ctr
pub fn generate_iv_ctr() -> [u8; 8] {
    let mut iv = [0u8; 8];
    rand::rng().fill(&mut iv);
    iv
}

//генерация ключа
pub fn generate_key() -> [u8; 24] {
    let mut rng = rand::rng();
    let mut key = [0u8; 24];
    rng.fill(&mut key);
    key
}

//функция генерации раундового ключа (nonce+counter) для ctr (также 16 байт)
fn generate_nc(iv: [u8; 8], counter: u64) -> [u8; 16] {
    let mut result = [0u8; 16];
    let counter = counter.to_be_bytes();
    result[..8].copy_from_slice(&iv);
    result[8..].copy_from_slice(&counter);
    result
}

//вспомогательная функция для Xor массивов
fn xor_arrays(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}


//Шифр - AES192, соответственно длина ключа - 24 байта, размер блоков - 16 байт
//Документация, как это в rust - https://docs.rs/aes/latest/aes/
//Функции режимов работы все принимают соответственно ключ 24 байта, iv генерируется размером 16 байт

//шифрование блока
pub fn aes192_encrypt_block(cipher: &Aes192, block: &[u8; 16]) -> [u8; 16] {
    let mut buf = *block;
    cipher.encrypt_block((&mut buf).into());
    buf.into()
}

//расшифрование блока
pub fn aes192_decrypt_block(cipher: &Aes192, block: &[u8; 16]) -> [u8; 16] {
    let mut buf = *block;
    cipher.decrypt_block((&mut buf).into());
    buf.into()
}

//расширение открытого текста
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    assert!(block_size <= 255); //так как дополняем последний блок, его длина явно меньше 255, поэтому такое дополнение подходит
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = Vec::from(data);
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

//шифрование ECB
pub fn encrypt_aes192_ecb(data: &[u8], key : &[u8; 24]) -> Vec<u8> {
    let  cipher = Aes192::new(key.into());
    let mut res= Vec::new();
    let padded_data = pkcs7_pad(data, 16);
    for block in padded_data.chunks(16) {
        let mut block_array = [0u8; 16];
        block_array[0..block.len()].copy_from_slice(block);
        let new_block =  aes192_encrypt_block(&cipher, &block_array);
        res.extend_from_slice(&new_block);

    }
    res
}

//расшифрование ECB
pub fn decrypt_aes192_ecb(data: &[u8], key : &[u8; 24]) -> Vec<u8> {
    let  cipher = Aes192::new(key.into());
    let mut res= Vec::new();
    for block in data.chunks(16) {
        let mut block_array = [0u8; 16];
        block_array[0..block.len()].copy_from_slice(block);
        let new_block =  aes192_decrypt_block(&cipher, &block_array);
        res.extend_from_slice(&new_block);
    }
    res
}

//шифрование CBC
pub fn encrypt_aes192_cbc(data: &[u8], key : &[u8; 24], iv: &[u8; 16]) -> Vec<u8> {
    let  cipher = Aes192::new(key.into());
    let mut res= Vec::new();
    let mut r = *iv;
    let padded_data = pkcs7_pad(data, 16);
    for block in padded_data.chunks(16) {
        let mut block_array = [0u8; 16];
        block_array[0..block.len()].copy_from_slice(block);
        let new_block = xor_arrays(block_array , r);
        let res_block = aes192_encrypt_block(&cipher, &new_block);
        res.extend_from_slice(&res_block);
        r = res_block;
    }
    res
}

//расшифрование CBC
pub fn decrypt_aes192_cbc(data: &[u8], key : &[u8; 24], iv: &[u8; 16]) -> Vec<u8> {
    let  cipher = Aes192::new(key.into());
    let mut res= Vec::new();
    let mut r = *iv;
    for block in data.chunks(16) {
        let mut block_array = [0u8; 16];
        block_array[0..block.len()].copy_from_slice(block);
        let decrypt_block = aes192_decrypt_block(&cipher, &block_array);
        let res_block = xor_arrays(decrypt_block , r);
        res.extend_from_slice(&res_block);
        r = block_array;
    }
    res
}

//шифрование CFB
pub fn encrypt_aes192_cfb(data: &[u8], key : &[u8; 24], iv: &[u8; 16]) -> Vec<u8> {
    let  cipher = Aes192::new(key.into());
    let mut res= Vec::new();
    let mut r = *iv;
    let padded_data = pkcs7_pad(data, 16);
    for block in padded_data.chunks(16) {
        let mut block_array = [0u8; 16];
        block_array[0..block.len()].copy_from_slice(block);
        let encrypt_block = aes192_encrypt_block(&cipher, &r);
        let res_block = xor_arrays(block_array , encrypt_block);
        res.extend_from_slice(&res_block);
        r = res_block;
    }
    res
}

//расшифрование CFB
pub fn decrypt_aes192_cfb(data: &[u8], key : &[u8; 24], iv: &[u8; 16]) -> Vec<u8> {
    let  cipher = Aes192::new(key.into());
    let mut res= Vec::new();
    let mut r = *iv;
    for block in data.chunks(16) {
        let mut block_array = [0u8; 16];
        block_array[0..block.len()].copy_from_slice(block);
        let decrypt_block = aes192_encrypt_block(&cipher, &r);
        let res_block = xor_arrays(block_array , decrypt_block);
        res.extend_from_slice(&res_block);
        r = block_array;
    }
    res
}

//шифрование OFB
pub fn encrypt_aes192_ofb(data: &[u8], key : &[u8; 24], iv: &[u8; 16]) -> Vec<u8> {
    let  cipher = Aes192::new(key.into());
    let mut res= Vec::new();
    let mut r = *iv;
    let padded_data = pkcs7_pad(data, 16);
    for block in padded_data.chunks(16) {
        let encrypt_block = aes192_encrypt_block(&cipher, &r);
        let mut block_array = [0u8; 16];
        block_array[0..block.len()].copy_from_slice(block);
        let res_block = xor_arrays(block_array , encrypt_block);
        res.extend_from_slice(&res_block);
        r = encrypt_block;
    }
    res
}

//расшифрование OFB
pub fn decrypt_aes192_ofb(data: &[u8], key : &[u8; 24], iv: &[u8; 16]) -> Vec<u8> {
    let  cipher = Aes192::new(key.into());
    let mut res= Vec::new();
    let mut r = *iv;
    for block in data.chunks(16) {
        let encrypt_block = aes192_encrypt_block(&cipher, &r);
        if block.len() != 16 {
            pkcs7_pad(block, 16);
        }
        let mut block_array = [0u8; 16];
        block_array[0..block.len()].copy_from_slice(block);
        let res_block = xor_arrays(block_array , encrypt_block);
        res.extend_from_slice(&res_block);
        r = encrypt_block;
    }
    res
}

//шифрование CTR
pub fn encrypt_aes192_ctr(data: &[u8], key : &[u8; 24], iv: &[u8; 8]) -> Vec<u8> {
    let  cipher = Aes192::new(key.into());
    let mut res= Vec::new();
    let mut counter = 0;
    let mut r = generate_nc(*iv, counter);
    let padded_data = pkcs7_pad(data, 16);
    for block in padded_data.chunks(16) {
        let encrypt_block = aes192_encrypt_block(&cipher, &r);
        let mut block_array = [0u8; 16];
        block_array[0..block.len()].copy_from_slice(block);
        let res_block = xor_arrays(block_array , encrypt_block);
        res.extend_from_slice(&res_block);
        counter += 1;
        r = generate_nc(*iv, counter);
    }
    res
}
//расшифрование CTR
pub fn decrypt_aes192_ctr(data: &[u8], key : &[u8; 24], iv: &[u8; 8]) -> Vec<u8> {
    let  cipher = Aes192::new(key.into());
    let mut res= Vec::new();
    let mut counter = 0;
    let mut r = generate_nc(*iv, counter);
    for block in data.chunks(16) {
        let encrypt_block = aes192_encrypt_block(&cipher, &r);
        let mut block_array = [0u8; 16];
        block_array[0..block.len()].copy_from_slice(block);
        let res_block = xor_arrays(block_array , encrypt_block);
        res.extend_from_slice(&res_block);
        counter += 1;
        r = generate_nc(*iv, counter);
    }
    res
}

fn main() {
    let message =
        "Стояла зима.
        Дул ветер из степи.
        И холодно было младенцу в вертепе
        На склоне холма.

        Его согревало дыханье вола.
        Домашние звери
        Стояли в пещере,
        Над яслями теплая дымка плыла.

        Доху отряхнув от постельной трухи
        И зернышек проса,
        Смотрели с утеса
        Спросонья в полночную даль пастухи.

        Вдали было поле в снегу и погост,
        Ограды, надгробья,
        Оглобля в сугробе,
        И небо над кладбищем, полное звезд.

        А рядом, неведомая перед тем,
        Застенчивей плошки
        В оконце сторожки
        Мерцала звезда по пути в Вифлеем.

        Она пламенела, как стог, в стороне
        От неба и Бога,
        Как отблеск поджога,
        Как хутор в огне и пожар на гумне.

        Она возвышалась горящей скирдой
        Соломы и сена
        Средь целой вселенной,
        Встревоженной этою новой звездой.

        Растущее зарево рдело над ней
        И значило что-то,
        И три звездочета
        Спешили на зов небывалых огней.

        За ними везли на верблюдах дары.
        И ослики в сбруе, один малорослей
        Другого, шажками спускались с горы.
        И странным виденьем грядущей поры
        Вставало вдали все пришедшее после.
        Все мысли веков, все мечты, все миры,
        Все будущее галерей и музеев,
        Все шалости фей, все дела чародеев,
        Все елки на свете, все сны детворы.

        Весь трепет затепленных свечек, все цепи,
        Все великолепье цветной мишуры…
        …Все злей и свирепей дул ветер из степи…
        …Все яблоки, все золотые шары.

        Часть пруда скрывали верхушки ольхи,
        Но часть было видно отлично отсюда
        Сквозь гнезда грачей и деревьев верхи.
        Как шли вдоль запруды ослы и верблюды,
        Могли хорошо разглядеть пастухи.
        — Пойдемте со всеми, поклонимся чуду, -
        Сказали они, запахнув кожухи.

        От шарканья по снегу сделалось жарко.
        По яркой поляне листами слюды
        Вели за хибарку босые следы.
        На эти следы, как на пламя огарка,
        Ворчали овчарки при свете звезды.

        Морозная ночь походила на сказку,
        И кто-то с навьюженной снежной гряды
        Все время незримо входил в их ряды.
        Собаки брели, озираясь с опаской,
        И жались к подпаску, и ждали беды.

        По той же дороге, чрез эту же местность
        Шло несколько ангелов в гуще толпы.
        Незримыми делала их бестелесность,
        Но шаг оставлял отпечаток стопы.

        У камня толпилась орава народу.
        Светало. Означились кедров стволы.
        — А кто вы такие? — спросила Мария.
        — Мы племя пастушье и неба послы,
        Пришли вознести вам обоим хвалы.
        — Всем вместе нельзя. Подождите у входа.
        Средь серой, как пепел, предутренней мглы
        Топтались погонщики и овцеводы,
        Ругались со всадниками пешеходы,
        У выдолбленной водопойной колоды
        Ревели верблюды, лягались ослы.

        Светало. Рассвет, как пылинки золы,
        Последние звезды сметал с небосвода.
        И только волхвов из несметного сброда
        Впустила Мария в отверстье скалы.

        Он спал, весь сияющий, в яслях из дуба,
        Как месяца луч в углубленье дупла.
        Ему заменяли овчинную шубу
        Ослиные губы и ноздри вола.

        Стояли в тени, словно в сумраке хлева,
        Шептались, едва подбирая слова.
        Вдруг кто-то в потемках, немного налево
        От яслей рукой отодвинул волхва,
        И тот оглянулся: с порога на деву,
        Как гостья, смотрела звезда Рождества.";

    //let message = "завтра надо купить шампунь";

    let _iv = generate_iv(); //iv в этой лр сгенерирую случайно
    let _iv2 = generate_iv_ctr();
    let key = generate_key(); //и ключ тоже
    println!("Key: {:?}", key);
    println!("IV: {:?}", _iv);
    println!("IV_ctr: {:?}", _iv2);


    //Для проверки, что правильно работает (plaintext==message)
    //Можно любой режим поставить, сообщение действительно будет исходное
    let cbc_ciphertext = encrypt_aes192_cbc(message.as_ref(), &key, &_iv);
    let cbc_plaintext = decrypt_aes192_cbc(&*cbc_ciphertext, &key, &_iv);
    println!("Расшифровка сообщения:, {:?}", String::from_utf8(cbc_plaintext));



    //Будем замерять время на тысяче шифрованиях и расшифрованиях
    //стихотворения Бориса Пастернака "Рождественская звезда"
    let start = Instant::now();
    for _i in 0..1000 {
        let ctr_ciphertext = encrypt_aes192_ctr(message.as_ref(), &key, &_iv2);
        let ctr_plaintext = decrypt_aes192_ctr(&*ctr_ciphertext, &key, &_iv2);
        //println!("Шифртекст ctr:, {:?}", ctr_ciphertext);
        //println!("Расшифрованный текст ctr:, {:?}", String::from_utf8(ctr_plaintext));
    }
    let duration = start.elapsed();
    println!("Время ctr:, {:?}", duration);
    let start = Instant::now();
    for _i in 0..1000 {
        let cbc_ciphertext = encrypt_aes192_cbc(message.as_ref(), &key, &_iv);
        let cbc_plaintext = decrypt_aes192_cbc(&*cbc_ciphertext, &key, &_iv);
        //println!("Шифртекст cbc:, {:?}", cbc_ciphertext);
        //println!("Расшифрованный текст cbc:, {:?}", String::from_utf8(cbc_plaintext));
    }
    let duration = start.elapsed();
    println!("Время cbc:, {:?}", duration);
    let start = Instant::now();
    for _i in 0..1000 {
        let cfb_ciphertext = encrypt_aes192_cfb(message.as_ref(), &key, &_iv);
        let cfb_plaintext = decrypt_aes192_cfb(&*cfb_ciphertext, &key, &_iv);
        //println!("Шифртекст cfb:, {:?}", cfb_ciphertext);
        //println!("Расшифрованный текст cfb:, {:?}", String::from_utf8(cfb_plaintext));
    }
    let duration = start.elapsed();
    println!("Время cfb:, {:?}", duration);
    let start = Instant::now();
    for _i in 0..1000 {
        let ofb_ciphertext = encrypt_aes192_ofb(message.as_ref(), &key, &_iv);
        let ofb_plaintext = decrypt_aes192_ofb(&*ofb_ciphertext, &key, &_iv);
        //println!("Шифртекст ofb:, {:?}", ofb_ciphertext);
        //println!("Расшифрованный текст ofb:, {:?}", String::from_utf8(ofb_plaintext));
    }
    let duration = start.elapsed();
    println!("Время ofb:, {:?}", duration);
    let start = Instant::now();
    for _i in 0..1000 {
        let ecb_ciphertext = encrypt_aes192_ecb(message.as_ref(), &key);
        let ecb_plaintext = decrypt_aes192_ecb(&*ecb_ciphertext, &key);
        //println!("Шифртекст ecb:, {:?}", ecb_ciphertext);
        //println!("Расшифрованный текст ecb:, {:?}", String::from_utf8(ecb_plaintext));
    }
    let duration = start.elapsed();
    println!("Время ecb:, {:?}", duration);
    let  cipher = Aes192::new(&key.into());
    let start = Instant::now();
    for _i in 0..1000 {
        aes192_encrypt_block(&cipher, &_iv);
        aes192_encrypt_block(&cipher, &_iv);
    }
    let duration = start.elapsed();
    println!("Время шифрования одного блока:, {:?}", duration);
}
//В выводе можно видеть:
//ecb самый быстрый - там минимальное количество операций, данные блока зашифрования никуда не передаются
//ofb, cfb, cbc раюотают примерно за одинаковое время, потому что по структуре и по операциям одинаковые
//ctr работает немного дольше, из-за необходимости дополнительной генерации раундового ключа, который iv/2 | counter
