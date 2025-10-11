use rand::RngCore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
///структура для удобства (типа u48 нет в rust'е)
pub struct U48 {
    ///хранит 6 массивов по 8 бит
    bytes: [u8; 6],
}

impl U48 {
    pub fn print_bits(&self) {
        for b in &self.bytes {
            print!("{:08b} ", b);
        }
        println!();
    }

    fn from_bytes(bytes: [u8; 6]) -> Self {
        Self { bytes }
    }

    pub fn random_pseudo() -> Self {
        let mut bytes = [0u8; 6];
        rand::rng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn xor(&self, other: &U48) -> U48 {
        let mut result = [0u8; 6];
        for i in 0..6 {
            result[i] = self.bytes[i] ^ other.bytes[i];
        }
        U48::from_bytes(result)
    }

    ///функции get_bit и set_bit проще написать один раз тут,
    /// чтобы потом просто к элементам доступ иметь,
    /// вне зависимости от того, что нам надо -
    /// 8 блоков по 6 бит, или какая-то ещё более сложная структура

    pub fn get_bit(&self, position: usize) -> u32 {
        assert!(position < 48, "Position must be 0-47");
        let byte_index = position / 8;
        let bit_index = 7 - (position % 8);
        ((self.bytes[byte_index] >> bit_index) & 1) as u32
    }
    pub fn set_bit(&mut self, position: usize, value: u32) {
        assert!(position < 48, "Position must be 0-47");
        assert!(value <= 1, "Value must be 0 or 1");
        let byte_index = position / 8;
        let bit_index = 7 - (position % 8);
        if value != 0 {
            self.bytes[byte_index] |= 1 << bit_index;
        } else {
            self.bytes[byte_index] &= !(1 << bit_index);
        }
    }

    ///совершает перестановку p по паттерну

    pub fn from_pattern(input: u32, pattern: &[usize; 48]) -> Self {
        let mut result = U48::default();

        for (target_bit, &source_bit) in pattern.iter().enumerate() {
            assert!(source_bit <= 32, "Pattern values must be 1-32");
            if source_bit > 0 {
                let source_value = (input >> (32 - source_bit)) & 1;
                result.set_bit(target_bit, source_value);
            }
        }
        result
    }
}