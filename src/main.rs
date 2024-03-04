std::env

fn main() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    println!("Using database URL: {}", database_url);
    for i in 1..=10 { // Adjust the range based on your needs
        let key = format!("SERVICE{}_URL", i);
        match std::env::var(&key) {
            Ok(val) => println!("{}: {}", key, val),
            Err(_) => break, // Assumes sequential service vars; stops at the first missing
        }
    }
}