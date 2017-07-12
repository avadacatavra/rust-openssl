// This is a test shim for the OpenSSL test suite
// https://boringssl.googlesource.com/boringssl/+/master/ssl/test
//

extern crate openssl;
extern crate env_logger;

use std::env;
use std::process;
use std::net;
use std::fs;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::{Write, Read};
use std::sync::Arc;
use openssl::ssl;
use std::ffi;
use openssl::ssl::{SslMethod, SslContextBuilder, SslConnectorBuilder};
use openssl::x509::X509_FILETYPE_PEM;
use openssl::ssl::{SslAcceptorBuilder, SslStream};
use std::net::{TcpListener, TcpStream};
use openssl::pkey::{PKey, PKeyRef};
use openssl::pkcs12::Pkcs12;
use openssl::pkcs12::ParsedPkcs12;
use openssl::x509::X509;
use openssl::ssl::Error;
use std::ops::Deref;
use openssl::ssl::HandshakeError;

static BOGO_NACK: i32 = 89;

macro_rules! println_err(
    ($($arg:tt)*) => { {
        write!(&mut ::std::io::stderr(), $($arg)*).unwrap();
    } }
    );

#[derive(Debug)]
struct Options {
    port: u16,
    server: bool,
    resumes: usize,
    require_any_client_cert: bool, // #ToDo
    offer_no_client_cas: bool, //#ToDo
    tickets: bool, // #ToDo
    queue_data: bool, //#ToDo
    host_name: String,
    key_file: String,
    cert_file: String,
    protocols: Vec<String>, //#ToDo
    support_tls13: bool,
    support_tls12: bool,
    //min_version: Option<ProtocolVersion>, // #ToDo
    //max_version: Option<ProtocolVersion>, // #ToDo
    expect_curve: u16, // #ToDo
}

impl Options {
    fn new() -> Options {
        Options {
            port: 0,
            server: false,
            resumes: 0,
            tickets: true,
            host_name: "example.com".to_string(),
            queue_data: false,
            require_any_client_cert: false,
            offer_no_client_cas: false,
            key_file: "".to_string(),
            cert_file: "".to_string(),
            protocols: vec![],
            support_tls13: true,
            support_tls12: true,
            //min_version: None,
            //max_version: None,
            expect_curve: 0,
        }
    }
    /*  #ToDo : Still need to check for various versions supported. 
    fn version_allowed(&self, vers: ProtocolVersion) -> bool {
       (self.min_version.is_none() || vers.get_u16() >= self.min_version.unwrap().get_u16()) &&
       (self.max_version.is_none() || vers.get_u16() <= self.max_version.unwrap().get_u16())
    }

    fn tls13_supported(&self) -> bool {
        self.support_tls13 && (self.version_allowed(ProtocolVersion::TLSv1_3) ||
                               self.version_allowed(ProtocolVersion::Unknown(0x7f12)))
    }

    fn tls12_supported(&self) -> bool {
        self.support_tls12 && self.version_allowed(ProtocolVersion::TLSv1_2)
    }
    */
}

/* #ToDo: Still need to handle splitting protocols for alpn and using alpn
fn split_protocols(protos: &str) -> Vec<String> {
    let mut ret = Vec::new();

    let mut offs = 0;
    while offs < protos.len() {
        let len = protos.as_bytes()[offs] as usize;
        let item = protos[offs + 1..offs + 1 + len].to_string();
        ret.push(item);
        offs += 1 + len;
    }

    ret
}
#ToDo : Still need to handle certificate verification
struct NoVerification {}

impl rustls::ClientCertVerifier for NoVerification {
    fn verify_client_cert(&self,
                          _roots: &rustls::RootCertStore,
                          _certs: &[rustls::Certificate]) -> Result<(), rustls::TLSError> {
        Ok(())
    }
}

impl rustls::ServerCertVerifier for NoVerification {
    fn verify_server_cert(&self,
                          _roots: &rustls::RootCertStore,
                          _certs: &[rustls::Certificate],
                          _hostname: &str) -> Result<(), rustls::TLSError> {
        Ok(())
    }
} */

// This specifies the server configuration.
// It does this by creating a pkcs12 object
// which sets the provided certificate and private key
// We are expecting private keys and certificates provided
// to be in PEM format.
fn make_server_cfg(opts: &Options) -> ParsedPkcs12 {
    let mut key = vec![];
    let mut cert = vec![];
    let subject_name = "www.google.com";
    let mut certfile = fs::File::open(&opts.cert_file).expect("cannot open certificate file");
    let mut keyfile = fs::File::open(&opts.key_file).expect("cannot open key file");
    keyfile.read_to_end(&mut key).unwrap();
    certfile.read_to_end(&mut cert).unwrap();
    let pkey = PKey::private_key_from_pem(&mut key).unwrap();
    // #ToDo : Still need to set certificate chains
    //let cert_chain = X509::stack_from_pem(&mut cert).unwrap();
    //let certificate = X509::from_pem(&mut cert).unwrap(); // confirm this
    let certificate = X509::from_pem(&mut cert).unwrap();
    let pkcs12_builder = Pkcs12::builder();
    /*let pkcs12 = pkcs12_builder
        .build("checkopenssl123", subject_name, &pkey, &certificate)
        .unwrap()*/
    let pkcs12 = pkcs12_builder
        .build("checkopenssl123", subject_name, &pkey, &certificate)
        .unwrap();
    //let pkcs12 = pkcs12_builder.ca(&cert_chain); // need to understand how to pass a certificate chain
    let der = pkcs12.to_der().unwrap();
    let pkcs12 = Pkcs12::from_der(&der).unwrap();
    let parsed = pkcs12.parse("checkopenssl123");
    let identity = pkcs12.parse("checkopenssl123").unwrap();
    identity
}
// Make the context builder here. ContextBuilder--> ConnectorBuilder-->Connector-->Stream. Initialize the connector builder once we have the connection request.
fn make_client_cfg(opts: &Options) -> Arc<openssl::ssl::SslConnector> {
    // #Remember:: No scope for errors here.
    let mut connector_builder = openssl::ssl::SslConnectorBuilder::new(SslMethod::tls()).unwrap();
    {
        let context_builder = connector_builder.builder_mut();
        context_builder.set_certificate_file(&opts.cert_file, X509_FILETYPE_PEM);
        context_builder.set_certificate_chain_file(&opts.cert_file);
        context_builder.set_private_key_file(&opts.key_file, X509_FILETYPE_PEM);
    }
    let connector: openssl::ssl::SslConnector = connector_builder.build();
    Arc::new(connector)
}
/*
fn make_client_cfg(opts: &Options) -> Arc<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::new();
    let persist = rustls::ClientSessionMemoryCache::new(32);
    cfg.set_persistence(persist);
    cfg.root_store.add(&load_cert("cert.pem")[0]).unwrap(); -- need this to add the certificate to list of root certificates

    if !opts.cert_file.is_empty() && !opts.key_file.is_empty() {
        let cert = load_cert(&opts.cert_file);
        let key = load_key(&opts.key_file.replace(".pem", ".rsa"));
        cfg.set_single_client_cert(cert, key);
    }

    cfg.dangerous()
        .set_certificate_verifier(Box::new(NoVerification {}));

    if !opts.protocols.is_empty() {
        cfg.set_protocols(&opts.protocols);
    }

    cfg.versions.clear();

    if opts.tls12_supported() {
        cfg.versions.push(ProtocolVersion::TLSv1_2);
    }

    if opts.tls13_supported() {
        cfg.versions.push(ProtocolVersion::TLSv1_3);
    }

    Arc::new(cfg)
}
*/
//#ToDo : This
fn quit(why: &str) -> ! {
    println_err!("{}", why);
    process::exit(0)
}
// This handles the incoming client streams.
// Checks whether there is data to be read
// Reads data if there is any and acts as an echo
// server on the client side
fn handle_client(mut stream: SslStream<TcpStream>) {
    // #MyNotes:
    //ssl_read : returns errors of type ssl :: Error and not Error. Handle them accordingly
    // read : simply returns and writes into a buffer. Pointless for identifying errors , but you can use it to get your client information
    // read_to_end : returns errors and writes result into vector buffer. USE this to identify IO errors and write to buffer
    // #FIXME: There is definitely some issue on the SSL session being closed on the other end. Its giving an unexpected error
    loop {
        stream.flush();
        let mut buf = [0u8; 128];
        let bytes_read = match stream.ssl_read(&mut buf) // returns openssl::ssl::Error
        {
            Ok(bytes_read) => bytes_read,
            Err(err) => {
                match err{
                    openssl::ssl::Error::ZeroReturn=>quit("ssl_read_errors"),
                    openssl::ssl::Error:: WantRead(err)=>quit("ssl_read_errors"),
                    openssl::ssl::Error::WantWrite(err)=>quit("ssl_read_errors"),
                    openssl::ssl::Error::WantX509Lookup=>quit("ssl_read_errors"),
                    openssl::ssl::Error::Stream(err)=>quit("ssl_read_errors"),
                    openssl::ssl::Error::Ssl(err)=>quit("ssl_read_errors"),
                }
            }
        };
        //println!("{} bytes were read", bytes_read);
        if bytes_read == 0 {
            println_err!("Reached EOF");
            process::exit(0)
        }
        stream.write(&buf[..bytes_read]);
        for b in buf.iter_mut() {
            *b ^= 0xff;
        }
    }
}

fn exec_client(opts: &Options, connector: &openssl::ssl::SslConnector) {
    let stream = net::TcpStream::connect(("127.0.0.1", opts.port)).expect("cannot connect");
    let mut stream = match connector.connect("google.com", stream) {
        Ok(stream) => stream,
        Err(err) => {
            match err {
                openssl::ssl::HandshakeError::SetupFailure { .. } => quit("HANDSHAKE_ERROR"),
                openssl::ssl::HandshakeError::Failure { .. } => quit("HANDSHAKE_ERROR"),
                openssl::ssl::HandshakeError::Interrupted { .. } => quit("HANDSHAKE_ERROR"),  
            }
        }
    }; // This gives a handshake error. Need to map this to different types
    //let mut stream = connector.connect("google.com", stream).unwrap(); //this gives a handshake error. you need to catch it as an enum and classify it
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n");
    let mut res = vec![];
    stream.read_to_end(&mut res);
    println!("{}", String::from_utf8_lossy(&res));
}
// This creates an acceptor on the server
// and accepts incoming streams
fn exec_server(opts: &Options, identity: &ParsedPkcs12) {
    let acceptor = SslAcceptorBuilder::mozilla_intermediate(SslMethod::tls(),
                                                            &identity.pkey,
                                                            &identity.cert,
                                                            &identity.chain)
            .unwrap()
            .build(); // openssl::error::ErrorStack This gives an error. Might have to map it.
    match net::TcpStream::connect(("127.0.0.1", opts.port)) {
        Ok(stream) => {
            let acceptor = acceptor.clone();
            let stream = match acceptor.accept(stream) { // This also gives handshake error. openssl::ssl::HandshakeError . Need to map this
                Ok(stream) => stream,
                Err(err) => {
                    match err {
                        openssl::ssl::HandshakeError::SetupFailure { .. } => {
                            quit("HANDSHAKE_ERROR")
                        }
                        openssl::ssl::HandshakeError::Failure { .. } => quit("HANDSHAKE_ERROR"),
                        openssl::ssl::HandshakeError::Interrupted { .. } => quit("HANDSHAKE_ERROR"),  
                    }
                }
            };
            handle_client(stream);
            drop(acceptor);
        }
        Err(e) => {
            panic!("Connection has failed {:?}", e);
        } 
    }
}
fn main() {
    let mut args: Vec<_> = env::args().collect();
    env_logger::init().unwrap();

    args.remove(0);
    println!("options: {:?}", args);

    let mut opts = Options::new();
    while !args.is_empty() {
        let arg = args.remove(0);
        match arg.as_ref() {
            "-port" => {
                opts.port = args.remove(0).parse::<u16>().unwrap();
            }
            "-server" => {
                opts.server = true;
            }
            "-key-file" => {
                opts.key_file = args.remove(0);
            }
            "-cert-file" => {
                opts.cert_file = args.remove(0);
            }
            "-resume-count" => {
                opts.resumes = args.remove(0).parse::<usize>().unwrap();
            }
            /*
            "-no-tls13" => {
                opts.support_tls13 = false; // specific to implementation, probably make this true
            }
            "-no-tls12" => {
                opts.support_tls12 = false; // specific to implementation, make this true
            }*/
            "-no-tls13"|
            "-no-tls12"|
            "-min-version" |
            "-max-version" |
            "-max-cert-list" |
            "-expect-curve-id" |
            "-expect-peer-signature-algorithm" |
            "-expect-advertised-alpn" |
            "-expect-alpn" |
            "-expect-server-name" |
            "-expect-certificate-types"|
            // ToDo: This needs to be implemented
            "-select-alpn" |
            "-require-any-client-certificate"|
            "-shim-writes-first" |
            "-host-name"|
            "-advertise-alpn"|
            "-use-null-client-ca-list"
            => {
                println!("not checking {} {}; NYI", arg, args.remove(0));
            }
            /*
            "-select-alpn" => {
                opts.protocols.push(args.remove(0));
            }
            "-require-any-client-certificate" => {
                opts.require_any_client_cert = true;
            }
            "-shim-writes-first" => {
                opts.queue_data = true;
            }
            "-host-name" => {
                opts.host_name = args.remove(0);
            }
            /*"-advertise-alpn" => {
                opts.protocols = split_protocols(&args.remove(0));
            }*/
            "-use-null-client-ca-list" => {
                opts.offer_no_client_cas = true;
            }
            */

            // defaults:
            "-enable-all-curves" |
            "-renegotiate-ignore" |
            "-no-tls11" |
            "-no-tls1" |
            "-no-ssl3" |
            "-decline-alpn" |
            "-expect-no-session" |
            "-expect-session-miss" |
            "-expect-extended-master-secret" |
            "-expect-ticket-renewal" |
            // internal openssl details:
            "-async" |
            "-implicit-handshake" |
            "-use-old-client-cert-callback" |
            "-use-early-callback" => {}

            // Not implemented things
            "-dtls" | // this is probably there as a type in open ssl check on that ---exists
            "-enable-ocsp-stapling" | //exists
            "-cipher" |
            "-psk" |
            "-renegotiate-freely" |   //check
            "-false-start" | 
            "-fallback-scsv" | //disabled checks
            "-fail-early-callback" |
            "-fail-cert-callback" |
            "-install-ddos-callback" |
            "-enable-signed-cert-timestamps" |
            "-ocsp-response" |
            "-advertise-npn" |
            "-verify-fail" |
            "-verify-peer" |
            "-expect-channel-id" |
            "-shim-shuts-down" |
            "-check-close-notify" |
            "-send-channel-id" |
            "-select-next-proto" |
            "-p384-only" |
            "-expect-verify-result" |
            "-send-alert" |
            "-signing-prefs" |
            "-digest-prefs" |
            "-export-keying-material" |
            "-use-exporter-between-reads" |
            "-ticket-key" |
            "-tls-unique" |
            "-enable-server-custom-extension" |
            "-enable-client-custom-extension" |
            "-expect-dhe-group-size" |
            "-use-ticket-callback" |
            "-enable-grease" |
            "-enable-channel-id" |
            "-expect-resume-curve-id" |
            "-resumption-delay" |
            "-expect-early-data-info" |
            "-enable-early-data" |
            "-expect-cipher-aes" |
            "-retain-only-sha256-client-cert-initial" |
            "-expect-peer-cert-file" |
            "-signed-cert-timestamps"|
            "rsa_chain_cert.pem"|
            "-enable-short-header" => {
                println!("NYI option {:?}", arg);
                process::exit(BOGO_NACK);
            }

            _ => {
                println!("unhandled option {:?}", arg);
                //process::exit(1);
                process::exit(0);
            }
        }
    }
    // #Uncomment this later
    //println!("opts {:?}", opts);

    // configuring the settings for the server
    let pkcs12 = if opts.server {
        Some(make_server_cfg(&opts)) // create the pkcs object here
    } else {
        None
    };
    let connector = if !opts.server {
        Some(make_client_cfg(&opts))
    } else {
        None
    };
    //println!("moving to establishing a connection");
    /*
    This represents a single TLS server session.
    Send TLS-protected data to the peer using the io::Write trait implementation. Read data from the peer using the io::Read trait implementation.
    */

    for _ in 0..opts.resumes + 1 {
        if opts.server {
            exec_server(&opts, pkcs12.as_ref().unwrap());
        } else {
            exec_client(&opts, connector.as_ref().unwrap());
        }
    }
}
