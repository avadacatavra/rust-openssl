// This is a test shim for the BoringSSL-Go ('bogo') TLS
// test suite. See bogo/ for this in action.
//
// https://boringssl.googlesource.com/boringssl/+/master/ssl/test
//

extern crate openssl;
extern crate webpki;
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

static BOGO_NACK: i32 = 89;

macro_rules! println_err(
    ($($arg:tt)*) => { {
        writeln!(&mut ::std::io::stderr(), $($arg)*).unwrap();
    } }
    );

#[derive(Debug)]
struct Options {
    port: u16, // provided by the shim
    server: bool,
    resumes: usize, //??
    require_any_client_cert: bool, //??
    offer_no_client_cas: bool, //??
    tickets: bool, //??
    queue_data: bool, //??
    host_name: String,
    key_file: String,
    cert_file: String,
    protocols: Vec<String>, // check later
    support_tls13: bool,
    support_tls12: bool,
    //min_version: Option<ProtocolVersion>,
    //max_version: Option<ProtocolVersion>,
    expect_curve: u16, //??
}

impl Options {
    fn new() -> Options {
        Options {
            port: 0,
            server: false, // because the shim always connects as a client
            resumes: 0, // ??
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
    /*  
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
/*
 this needs to be modified using open ssl simplementation of reading certificates. use set_ca_cert
 */
/*fn load_cert(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}            

fn load_key(filename: &str) -> rustls::PrivateKey {
    if filename.contains("ecdsa") {
        println_err!("No ECDSA key support");
        process::exit(BOGO_NACK);
    }

    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    //set_private_key_file()
    let keys = rustls::internal::pemfile::rsa_private_keys(&mut reader).unwrap();
    assert!(keys.len() == 1);
    keys[0].clone()
} */
/*
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
// Create a configuration for the server first
// Establish Session
// create a context SslContextBuilder
// supply it as an argument to the acceptor builder
fn make_server_cfg(opts: &Options) -> ParsedPkcs12 {
    //Arc<openssl::ssl::SslAcceptor> {

    let mut key = vec![];
    let mut cert = vec![];
    let subject_name = "www.google.com";
    let mut certfile = fs::File::open(&opts.cert_file).expect("cannot open certificate file");
    let mut keyfile = fs::File::open(&opts.key_file).expect("cannot open key file");
    keyfile.read_to_end(&mut key).unwrap();
    certfile.read_to_end(&mut cert).unwrap();
    let pkey = PKey::private_key_from_pem(&mut key).unwrap();
    let cert_chain = X509::stack_from_pem(&mut cert).unwrap();
    let certificate = X509::from_pem(&mut cert).unwrap(); // confirm this
    let pkcs12_builder = Pkcs12::builder();
    let pkcs12 = pkcs12_builder
        .build("checkopenssl123", subject_name, &pkey, &certificate)
        .unwrap();
    //let pkcs12 = pkcs12_builder.ca(&cert_chain); // need to understand how to pass a certificate chain
    let der = pkcs12.to_der().unwrap();
    let pkcs12 = Pkcs12::from_der(&der).unwrap();
    let parsed = pkcs12.parse("checkopenssl123").unwrap();
    let identity = pkcs12.parse("checkopenssl123").unwrap();
    println!("identity aquired");
    identity
}
// Make the context builder here. ContextBuilder--> ConnectorBuilder-->Connector-->Stream. Initialize the connector builder once we have the connection request.
fn make_client_cfg(opts: &Options) -> Arc<openssl::ssl::SslConnector> {
    /*let mut context_builder = openssl::ssl::SslContextBuilder::new(SslMethod::tls()).unwrap();
    context_builder.set_certificate_file(&opts.cert_file, X509_FILETYPE_PEM);
    context_builder.set_certificate_chain_file(&opts.cert_file);
    context_builder.set_private_key_file(&opts.key_file, X509_FILETYPE_PEM);
    Arc::new(context_builder)*/
    let mut connector_builder = openssl::ssl::SslConnectorBuilder::new(SslMethod::tls()).unwrap();

    {
        let context_builder = connector_builder.builder_mut();
        context_builder.set_certificate_file(&opts.cert_file, X509_FILETYPE_PEM);
        context_builder.set_certificate_chain_file(&opts.cert_file);
        context_builder.set_private_key_file(&opts.key_file, X509_FILETYPE_PEM);
    }
    let connector: openssl::ssl::SslConnector = connector_builder.build();
    //context
    Arc::new(connector)
    //connector_builder
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

fn quit(why: &str) -> ! {
    println_err!("{}", why);
    process::exit(0)
}

fn handle_err(err: rustls::TLSError) -> ! {
    use rustls::TLSError;
    use rustls::internal::msgs::enums::{AlertDescription, ContentType};

    println!("TLS error: {:?}", err);

    match err {
        TLSError::InappropriateHandshakeMessage { .. } |
        TLSError::InappropriateMessage { .. } => quit(":UNEXPECTED_MESSAGE:"),
        TLSError::AlertReceived(AlertDescription::RecordOverflow) => {
            quit(":TLSV1_ALERT_RECORD_OVERFLOW:")
        }
        TLSError::AlertReceived(AlertDescription::HandshakeFailure) => quit(":HANDSHAKE_FAILURE:"),
        TLSError::CorruptMessagePayload(ContentType::Alert) => quit(":BAD_ALERT:"),
        TLSError::CorruptMessagePayload(ContentType::ChangeCipherSpec) => {
            quit(":BAD_CHANGE_CIPHER_SPEC:")
        }
        TLSError::CorruptMessagePayload(ContentType::Handshake) => quit(":BAD_HANDSHAKE_MSG:"),
        TLSError::CorruptMessagePayload(ContentType::Unknown(42)) => {
            quit(":GARBAGE:")
        }
        TLSError::CorruptMessage => quit(":GARBAGE:"),
        TLSError::DecryptError => quit(":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"),
        TLSError::PeerIncompatibleError(_) => quit(":INCOMPATIBLE:"),
        TLSError::PeerMisbehavedError(_) => quit(":PEER_MISBEHAVIOUR:"),
        TLSError::NoCertificatesPresented => quit(":NO_CERTS:"),
        TLSError::AlertReceived(AlertDescription::UnexpectedMessage) => {
            quit(":BAD_ALERT:")
        }
        TLSError::WebPKIError(webpki::Error::InvalidSignatureForPublicKey) => {
            quit(":BAD_SIGNATURE:")
        }
        TLSError::WebPKIError(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey) => {
            quit(":WRONG_SIGNATURE_TYPE:")
        }
        _ => {
            println_err!("unhandled error: {:?}", err);
            quit(":FIXME:")
        }
    }
}
*/
// create error condition defintions.
// create client connection model for sending out connections
fn exec_server(opts: &Options, identity: &ParsedPkcs12) {
    println!("creating acceptor object");
    let acceptor = SslAcceptorBuilder::mozilla_intermediate(SslMethod::tls(),
                                                            &identity.pkey,
                                                            &identity.cert,
                                                            &identity.chain)
            .unwrap()
            .build();
    let acceptor = Arc::new(acceptor);
    let listener = TcpListener::bind(("0.0.0.0", opts.port)).expect("port not available"); // binding a listener on this port
    for stream in listener.incoming() {
        // for every incoming stream on this port
        match stream {
            Ok(stream) => {
                let acceptor = acceptor.clone(); // creates a clone of the configuration
                let stream = acceptor.accept(stream).unwrap();
                handle_client(stream); // this is where reads and writes will take place for every connection established. Need to handle this.
                drop(acceptor);
            }
            Err(e) => {
                panic!("Connection has failed {:?}", e);
            } 
        }
    }
}
fn handle_client(mut stream: SslStream<TcpStream>) {
    // lets first handle errors
    //ssl_read : returns errors of type ssl :: Error and not Error. Handle them accordingly
    // read : simply returns and writes into a buffer. Pointless for identifying errors , but you can use it to get your client information
    // read_to_end : returns errors and writes result into vector buffer. USE this to identify IO errors and write to buffer
    loop {
        stream.flush();
        let mut buf = [0u8; 128];
        //let mut check_buf = vec![];
        let bytes_read = stream.ssl_read(&mut buf).unwrap(); // read returns errors of ssl
        println!("{} bytes were read", bytes_read);
        if bytes_read == 0 {
            // This handles 0 bytes being read. ctrl+c for some reason. ctrl+d is another system defined error and we need to handle it.
            println!("Reached EOF");
            process::exit(0)
        }
        stream.write(&buf[..bytes_read]).unwrap();
        for b in buf.iter_mut() {
            *b ^= 0xff;
        }
    }
}

fn exec_client(opts: &Options, connector: &openssl::ssl::SslConnector) {
    //let stream = net::TcpStream::connect("127.0.0.1", opts.port).unwrap();
    let stream = net::TcpStream::connect(("127.0.0.1", opts.port)).expect("cannot connect");
    let mut stream = connector.connect("google.com", stream).unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut res = vec![];
    stream.read_to_end(&mut res).unwrap();
    println!("{}", String::from_utf8_lossy(&res));
}

fn main() {

    //Colect environment variables from the runner
    let mut args: Vec<_> = env::args().collect(); // returns the arguments that this program was started with. Depends on the runner
    env_logger::init().unwrap(); // initializes the logger for errors if any. unwrap is used to handle either  options or errors

    args.remove(0); // removes the element at position 0, i.e the path
    println!("options: {:?}", args); // prints the. options

    let mut opts = Options::new();
    // Provide command line arguments
    // Note: try and find a certificate file and key pair to provide to ssl and establish a connection
    while !args.is_empty() {
        let arg = args.remove(0); // works as a switch case
        match arg.as_ref() {
            "-port" => {
                opts.port = args.remove(0).parse::<u16>().unwrap();
            }
            "-server" => {
                opts.server = true;
            }
            "-key-file" => {
                opts.key_file = args.remove(0); // provide a key string
            }
            "-cert-file" => {
                opts.cert_file = args.remove(0);  // provide a string
            }
            "-resume-count" => {
                opts.resumes = args.remove(0).parse::<usize>().unwrap();
            }
            "-no-tls13" => {
                opts.support_tls13 = false; // specific to implementation, probably make this true
            }
            "-no-tls12" => {
                opts.support_tls12 = false; // specific to implementation, make this true
            }
            /*"-min-version" => {
                let min = args.remove(0).parse::<u16>().unwrap();
                opts.min_version = Some(ProtocolVersion::Unknown(min));
            }
            "-max-version" => {
                let max = args.remove(0).parse::<u16>().unwrap();
                opts.max_version = Some(ProtocolVersion::Unknown(max));
            } */
            "-max-cert-list" |
            "-expect-curve-id" |
            "-expect-peer-signature-algorithm" |
            "-expect-advertised-alpn" |
            "-expect-alpn" |
            "-expect-server-name" |
            "-expect-certificate-types" => {
                println!("not checking {} {}; NYI", arg, args.remove(0));
            }

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
            "-dtls" | // this is probably there as a type in open ssl check on that
            "-enable-ocsp-stapling" |
            "-cipher" |
            "-psk" |
            "-renegotiate-freely" |
            "-false-start" |
            "-fallback-scsv" |
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
            "-signed-cert-timestamps" => {
                println!("NYI option {:?}", arg);
                process::exit(BOGO_NACK);
            }

            _ => {
                println!("unhandled option {:?}", arg);
                process::exit(1);
            }
        }
    }
    println!("opts {:?}", opts);

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

    /*
    This represents a single TLS server session.
    Send TLS-protected data to the peer using the io::Write trait implementation. Read data from the peer using the io::Read trait implementation.
    */
    /* We have the server configuration in the acceptor.
       When we have the resume count, create a listener.
       for us the execute will be the listening part.
       We will find a way later to combine the reads and writes for the client and server
     */

    for _ in 0..opts.resumes + 1 {
        if opts.server {
            exec_server(&opts, pkcs12.as_ref().unwrap());
        } else {
            exec_client(&opts, connector.as_ref().unwrap());
        }
    }
}
