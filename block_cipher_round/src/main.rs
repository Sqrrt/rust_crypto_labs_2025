mod struct_u48;
use struct_u48::U48;


///функция расширения
fn e(value: u32) -> U48{

    let pattern = [
        32, 1, 2, 3, 4, 5,
         4, 5, 6, 7, 8, 9,
         8, 9,10,11,12,13,
        12,13,14,15,16,17,
        16,17,18,19,20,21,
        20,21,22,23,24,25,
        24,25,26,27,28,29,
        28,29,30,31,32, 1
    ];

    let result = U48::from_pattern(value, &pattern);
    result
}
///Преобразование S-блоков
fn s(input: U48) -> u32{
    const TABLES:[[[u8;16];4];8] = [
        [
            [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
            [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
            [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
            [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
        ],
        [
            [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
            [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
            [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
            [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
        ],
        [
            [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
            [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
            [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
            [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
        ],
        [
            [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
            [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
            [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
            [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
        ],
        [
            [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
            [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
            [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
            [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
        ],
        [
            [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
            [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
            [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
            [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
        ],
        [
            [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
            [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
            [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
            [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
        ],
        [
            [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
            [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
            [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
            [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
        ]
    ];
    let mut bi:u32 = 0;
    for i in 0..8{
        let a1 = input.get_bit(0 + i*6);
        let a2 = input.get_bit(5 + i*6);
        let b1 = input.get_bit(1 + i*6);
        let b2 = input.get_bit(2 + i*6);
        let b3 = input.get_bit(3 + i*6);
        let b4 = input.get_bit(4 + i*6);
        let index1: usize = ((b1 << 3) | (b2 << 2) | (b3 << 1) | b4) as usize;
        let index2: usize = ((a1 << 1) | a2) as usize;
        //println!("{}, {}, {}", index1, index2, i);
        let part:u32 =  TABLES[i][index2][index1] as u32;
        bi = bi ^ (part << 4*(7-i));
    }
    //println!("{:b}", bi);
    bi
}
///функция конечной перестановки
fn p(string : u32) -> u32{
    let mut result = 0u32;
    let pattern = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25];
    for (i, &bit_pos) in pattern.iter().enumerate() {
        let bit = (string >> (bit_pos - 1)) & 1;
        result |= bit << i;
    }
    result
}
///функция f
fn f(input:U48, block: u32) -> u32{
    let first:U48 = e(block);
    print!("After_e: ");
    first.print_bits();
    println!();
    let second:U48 = first.xor(&input); //xor, без функции
    print!("After_xor: ");
    second.print_bits();
    println!();
    let third:u32 = s(second);
    println!("After_s: {:032b}", third);
    println!();
    let result:u32 = p(third);
    println!("Result: {:032b}", result);
    println!();
    result
}
///прямое шифрование
fn forward(input:u64, key:U48) -> u64{
    let left = (input >> 32) as u32;
    let right = input as u32;
    let newleft = right;
    let newright = left ^ f(key, right);
    let res = ((newleft as u64) << 32) | (newright as u64);
    res
}
///обратное шифрование
fn backward(input:u64, key:U48) -> u64{
    let left = (input >> 32) as u32;
    let right = input as u32;
    let newright = left;
    let newleft = right ^ f(key, left);
    let res = ((newleft as u64) << 32) | (newright as u64);
    res
}

fn main() {
    let rkey = U48::random_pseudo();
    print!("Key : ");
    rkey.print_bits();
    println!();
    let block : u64 = 0b1001010100100100000010111100101001010010101010101010010101000111;

    let forward_round = forward(block, rkey);
    println!("Forward  round result: {:064b}", forward_round);
    println!();
    let backward_round = backward(block, rkey);
    println!("Backward round result: {:064b}", backward_round);
    println!("Ура)");
}
