use std::time::Duration;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use isahc::{AsyncReadResponseExt, HttpClient, Request};
use isahc::http::header::{ACCEPT, CONTENT_TYPE};
use rand::Rng;
use sha2::{Sha256, Digest};
use tokio::sync::mpsc::Sender;
use serde::Deserialize;
use serde_json::json;

const CLIENT_ID: &str = "f00ad152-9a55-4fc3-9af8-e44430d30cef";
const REDIRECT_URI: &str = "http://localhost:27134";

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const PASSWORD_LEN: usize = 60;

#[tokio::main]
async fn main() {
    let state = generate_secret(7);
    let pkce_secret = generate_secret(PASSWORD_LEN);
    let pkce_hash = generate_hash256(&pkce_secret);
    let (pkce_hash, _) = pkce_hash.split_at(43);
    let request_uri = format!("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_id={}&response_type=code&redirect_uri={}&scope=XboxLive.signin%20offline_access&state={}&code_challenge={}&code_challenge_method=S256", CLIENT_ID, REDIRECT_URI, state, pkce_hash);

    let (code_tx, mut code_rx) = tokio::sync::mpsc::channel(2);

    tokio::task::spawn_blocking(move || start_localhost(code_tx, state));
    println!("Server launched!");

    if let Err(error) = webbrowser::open(&request_uri) {
        println!("Error while opening browser: {}", error);
        return;
    }

    let code = code_rx.recv().await;
    if code.is_none() {
        println!("No code received!");
        return;
    }
    let code = code.unwrap();
    println!("Received code!! {}", code);

    let request_uri = format!("https://login.microsoftonline.com/consumers/oauth2/v2.0/token");
    let request_params = format!("client_id={}&code={}&redirect_uri={}&grant_type=authorization_code&code_verifier={}", CLIENT_ID, code, REDIRECT_URI, pkce_secret);
    let client = HttpClient::new().unwrap();
    let request = Request::post(request_uri)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(request_params).unwrap();
    let mut response = client.send_async(request).await.unwrap();
    let auth_tokens: AuthTokenResponse = response.json().await.unwrap();
    println!("Successful Auth token response: {:?}", auth_tokens);

    let rps_ticket = String::from("d=") + &auth_tokens.access_token;
    let xbox_body = json!({
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": rps_ticket
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    });
    let xbox_str = serde_json::to_string(&xbox_body).unwrap();
    let request = Request::post("https://user.auth.xboxlive.com/user/authenticate")
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .body(xbox_str).unwrap();
    let response = client.send_async(request).await;
    if let Err(error) = response {
        println!("ERror while sending request: {}", error);
        return;
    }
    let mut response = response.unwrap();
    println!("Message sent!");
    let xbox_resp: XblResponse = response.json().await.unwrap();
    println!("Response: {:?}", xbox_resp);

    let xsts_body = json!({
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [
                xbox_resp.token
            ]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    });
    let request = Request::post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .body(serde_json::to_string(&xsts_body).unwrap())
        .unwrap();
    let mut response = client.send_async(request).await.unwrap();
    let resp_str = response.text().await.unwrap();
    println!("Xsts: {}", resp_str);

    tokio::time::sleep(Duration::from_secs(4)).await;
}

#[derive(Debug, Deserialize)]
struct AuthTokenResponse {
    access_token: String,
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XblResponse {
    token: String,
    display_claims: DisplayClaims,
}

#[derive(Debug, Deserialize)]
struct DisplayClaims {
    xui: Vec<Xui>,
}
#[derive(Debug, Deserialize)]
struct Xui {
    uhs: String,
}

#[derive(Clone)]
struct AppState {
    code_tx: Sender<String>,
    stop_tx: Sender<()>,
    state: String,
}

#[actix_web::main]
async fn start_localhost(code_tx: Sender<String>, state: String) {
    let (stop_tx, mut stop_rx) = tokio::sync::mpsc::channel(1);
    let data = web::Data::new(AppState {
        code_tx,
        stop_tx,
        state,
    });
    tokio::select! {
        _ = HttpServer::new(move || {
            App::new()
            .app_data(data.clone())
            .service(redirect_uri)
        }).bind("127.0.0.1:27134").unwrap().run() => {}
        _ = stop_rx.recv() => {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

#[derive(Deserialize)]
struct AuthCode {
    code: String,
    state: String,
}

#[get("/")]
async fn redirect_uri(auth_code: web::Query<AuthCode>, data: web::Data<AppState>) -> impl Responder {
    if auth_code.state != data.state {
        HttpResponse::BadRequest().body("Invalid state, malicious redirect?")
    } else {
        data.code_tx.send(auth_code.code.clone()).await;
        data.stop_tx.send(()).await;
        HttpResponse::Ok().body("Successful authorization! Return to the application!")
    }
}

fn generate_secret(len: usize) -> String {
    let mut rng = rand::thread_rng();

    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn generate_hash256(secret: &str) -> String {
    let hash = Sha256::digest(<str as AsRef<[u8]>>::as_ref(secret));
    base64_url::encode(&hash)
}
