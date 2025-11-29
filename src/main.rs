//! tls loiter

const CA: &'static str = "certs/ca.rsa4096.crt";
//const CA: &'static str = "certs/ca.ed25519.crt";
//const CA: &'static str = "certs/ca.prime256v1.crt";

const CERT: &'static str = "certs/rustcryp.to.rsa4096.ca_signed.crt";
//const CERT: &'static str = "certs/rustcryp.to.ed25519.ca_signed.crt";
//const CERT: &'static str = "certs/rustcryp.to.prime256v1.ca_signed.crt";

const KEY: &'static str = "certs/rustcryp.to.rsa4096.key";
//const KEY: &'static str = "certs/rustcryp.to.ed25519.key";
//const KEY: &'static str = "certs/rustcryp.to.prime256v1.pem";

use rustls::{ServerConfig, ServerConnection};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::io::BufRead;

fn load_file(f: &'static str) -> Vec<u8> {
    let mut f = File::open(Path::new(f)).unwrap();
    let mut d: Vec<u8> = vec![];
    f.read_to_end(&mut d).unwrap();
    d
}

fn main() {
    //let provider = rustls_graviola::default_provider();
    let provider = rustls_rustcrypto::provider();
    let rustls_config = ServerConfig::builder_with_provider(Arc::new(provider));

    let rustls_config = rustls_config.with_safe_default_protocol_versions().unwrap();

    let rustls_config = rustls_config.with_no_client_auth();

    let cert = CertificateDer::from_pem_slice(load_file(CERT).as_slice()).unwrap();
    let ca_cert = CertificateDer::from_pem_slice(load_file(CA).as_slice()).unwrap();

    let all_certs = vec![cert, ca_cert];

    let key = PrivateKeyDer::from_pem_file(KEY).unwrap();

    let rustls_config = rustls_config.with_single_cert(all_certs, key).unwrap();

    let listener = TcpListener::bind("127.0.0.1:8282").unwrap();

    let (mut sock, addr) = listener.accept().unwrap();

    let mut sconn = ServerConnection::new(Arc::new(rustls_config)).unwrap();

    let out = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nUwU";
    let mut req_received = false;
    let mut sent_out = false;

    loop {
        let incoming = sconn.read_tls(&mut sock).unwrap();
        let io_state = sconn.process_new_packets().unwrap();
        
        println!("Incoming tls = {incoming}, io_state = {:?}", io_state);
        
        if io_state.peer_has_closed() {
            println!("Peer goodbye.");
            break;
        }
        
        if !sconn.is_handshaking() {
            let mut reader = sconn.reader();
            //let mut rbuf: Vec<u8> = Vec::with_capacity(8192);
            //let read_in = reader.read(&mut rbuf).unwrap();

            match reader.fill_buf() {
                Ok(rbuf) => {
                    println!("Read in = {:?}", core::str::from_utf8(&rbuf));
                    if rbuf.starts_with(b"GET") {
                        req_received = true;
                    }
                }
                Err(e) => {},
            }                    
        }

        if req_received && !sent_out {
            let mut writer = sconn.writer();

            let total_out = writer.write(&out.as_bytes()).unwrap();
            writer.flush().unwrap();
            sent_out = true;
        }

        while sconn.wants_write() {
            sconn.write_tls(&mut sock).unwrap();
        }
    }
}
