use popsec::dbus::Client;

fn main() {
    let client = Client::new().unwrap();
    println!("{:#?}", client.tpm2_totp_show());
}
