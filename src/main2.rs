use std::println;

fn main() {
    println("Hello world")
}







/*
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric; // Added import for rand::distributions::Alphanumeric
use std::fs::File;
use std::io::{self, Read};
use std::thread;
use std::time::Duration;
use std::collections::HashMap;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn generate_key_iv() -> (Vec<u8>, Vec<u8>) {
    let key: Vec<u8> = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .collect();
    
    let iv: Vec<u8> = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .collect();
    
    (key, iv)
}

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.encrypt_vec(data)
}

fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.decrypt_vec(encrypted_data).unwrap()
}


fn read_file_contents(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn parse_csv_line(line: &str) -> Vec<String> {
    line.split(',')
        .map(|s| s.trim().to_string())
        .collect()
}

fn divide(numerator: f64, denominator: f64) -> Option<f64> {
    if denominator == 0.0 {
        None
    } else {
        Some(numerator / denominator)
    }
}

fn count_words(text: &str) -> HashMap<&str, i32> {
    let mut map = HashMap::new();
    for word in text.split_whitespace() {
        let count = map.entry(word).or_insert(0);
        *count += 1;
    }
    map
}




// fn main() {}
fn main() {
    let handle = thread::spawn(|| {
        for i in 1..=10 {
            println!("Thread: {}", i);
            thread::sleep(Duration::from_millis(1));
        }
    });

    for i in 1..=5 {
        println!("Main: {}", i);
        thread::sleep(Duration::from_millis(2));
    }

    handle.join().unwrap();
}


// fn main() {
//     let data = fs::read_to_string(".env").expect("Unable to read .env file");
    
//     let (key, iv) = generate_key_iv();
//     let encrypted_data = encrypt(data.as_bytes(), &key, &iv);
//     fs::write(".env.encrypted", &encrypted_data).expect("Unable to write encrypted data");

//     let decrypted_data = decrypt(&encrypted_data, &key, &iv);
//     println!("Decrypted data: {}", String::from_utf8(decrypted_data).unwrap());
// }
*/