#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate openssl;

use openssl::ssl::{SslConnectorBuilder, SslMethod};

// should probably go into hyper openssl

fuzz_target!(|data: &[u8]| {
    let ssl = SslConnectorBuilder::new(SslMethod::tls());
    let mut core = Core::new().unwrap();

    let client = Client::configure()
        .connector(HttpsConnector::new(4, &core.handle()).unwrap())
        .build(&core.handle());

    let res = core.run(client.get("https://hyper.rs".parse().unwrap())).unwrap();
});
