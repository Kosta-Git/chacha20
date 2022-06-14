use chacha20::chacha20::ChaCha20;

fn main() {
    let key = ChaCha20::create_key("01234567890123456789012345678901");
    let nonce = ChaCha20::create_nonce("12 length k]");
    let mut chacha = ChaCha20::new(&key, &nonce, 0 );

    println!("{:?}", chacha);
    for i in 0..10 {
        println!("{:?}", chacha.next());
    }
}
