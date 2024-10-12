// server.rs

#![deny(warnings, clippy::pedantic)]

use std::{
    io::Cursor,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use bhttp::{Message, Mode, StatusCode};
use log::{error, info};
use ohttp::{
    hpke::{Aead, Kdf, Kem},
    KeyConfig, Server as OhttpServer, SymmetricSuite,
};
use structopt::StructOpt;
use warp::Filter;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, StructOpt)]
#[structopt(name = "ohttp-server", about = "Serve oblivious HTTP requests.")]
struct Args {
    /// The address to bind to.
    #[structopt(default_value = "127.0.0.1:8900")]
    address: SocketAddr,

    /// When creating message/bhttp, use the indeterminate-length form.
    #[structopt(long, short = "n", alias = "indefinite")]
    indeterminate: bool,
}

impl Args {
    fn mode(&self) -> Mode {
        if self.indeterminate {
            Mode::IndeterminateLength
        } else {
            Mode::KnownLength
        }
    }
}

fn generate_reply(
    ohttp_ref: &Arc<Mutex<OhttpServer>>,
    enc_request: &[u8],
    mode: Mode,
) -> Res<Vec<u8>> {
    let ohttp = ohttp_ref.lock().unwrap();
    let (request, server_response) = ohttp.decapsulate(enc_request)?;
    let bin_request = Message::read_bhttp(&mut Cursor::new(&request[..]))?;

    // Extract the request body
    let request_body = String::from_utf8(bin_request.content().to_vec()).unwrap_or_default();
    // Parse the body as URL-encoded form data
    let params: Vec<(String, String)> = url::form_urlencoded::parse(request_body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    // Find the 'name' parameter
    let name_param = params.iter().find(|(key, _)| key == "name");

    let mut bin_response = Message::response(StatusCode::OK);
    if let Some((_, name)) = name_param {
        bin_response.write_content(format!("Hello, {}!\r\n", name).as_bytes());
    } else {
        bin_response.write_content(b"Hello, unknown user!\r\n");
    }

    let mut response = Vec::new();
    bin_response.write_bhttp(mode, &mut response)?;
    let enc_response = server_response.encapsulate(&response)?;
    Ok(enc_response)
}

#[allow(clippy::unused_async)]
async fn serve(
    body: warp::hyper::body::Bytes,
    ohttp: Arc<Mutex<OhttpServer>>,
    mode: Mode,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    info!("Received request with body size: {} bytes", body.len());

    match generate_reply(&ohttp, &body[..], mode) {
        Ok(resp) => {
            info!(
                "Request processed successfully. Response size: {} bytes",
                resp.len()
            );
            Ok(warp::http::Response::builder()
                .header("Content-Type", "message/ohttp-res")
                .body(resp))
        }
        Err(e) => {
            let error_message = format!("{:?}", e);
            if let Ok(oe) = e.downcast::<::ohttp::Error>() {
                error!("OHTTP Error: {:?}", oe);
                Ok(warp::http::Response::builder()
                    .status(422)
                    .body(Vec::from(format!("Error: {oe:?}").as_bytes())))
            } else {
                error!("Request error: {}", error_message);
                Ok(warp::http::Response::builder()
                    .status(400)
                    .body(Vec::from(&b"Request error"[..])))
            }
        }
    }
}

fn with_ohttp(
    ohttp: Arc<Mutex<OhttpServer>>,
) -> impl Filter<Extract = (Arc<Mutex<OhttpServer>>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || Arc::clone(&ohttp))
}

#[tokio::main]
async fn main() -> Res<()> {
    let args = Args::from_args();
    ::ohttp::init();
    env_logger::try_init().unwrap();

    let config = KeyConfig::new(
        0,
        Kem::X25519Sha256,
        vec![
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
        ],
    )?;
    let ohttp = OhttpServer::new(config)?;
    println!(
        "Config: {}",
        hex::encode(KeyConfig::encode_list(&[ohttp.config()])?)
    );
    let mode = args.mode();

    let filter = warp::post()
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(with_ohttp(Arc::new(Mutex::new(ohttp))))
        .and(warp::any().map(move || mode))
        .and_then(serve);

    warp::serve(filter).run(args.address).await;

    Ok(())
}
