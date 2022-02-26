use std::time::Duration;
use isahc::{AsyncReadResponseExt, HttpClient, Request};
use isahc::http::header::CONTENT_TYPE;
use rand::Rng;
use serde::Deserialize;
use sha2::{Sha256, Digest};
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use warp::{Filter, reply};
use warp::http::StatusCode;
use crate::error::MicrosoftAuthError;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const PASSWORD_LEN: usize = 100;

#[derive(Debug, Deserialize)]
pub struct MicrosoftAuthData {
    access_token: String,
    refresh_token: String,
}

impl MicrosoftAuthData {
    pub fn new(access_token: String, refresh_token: String) -> Self {
        MicrosoftAuthData {
            access_token,
            refresh_token
        }
    }

    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }
}

/// `redirect_uri` should be https://localhost:<port>
pub async fn authenticate_or_refresh_microsoft(old_data: &mut Option<MicrosoftAuthData>, client_id: &str, redirect_uri: &str, port: u16, http_client: &HttpClient) -> Result<(), MicrosoftAuthError> {
    match old_data {
        None => {
            let (code, secret): (String, String) = retrieve_auth_code(client_id, redirect_uri, port).await?;
            let (access_token, refresh_token) = retrieve_access_token(AuthOrRefresh::Authenticate, &code, Some(secret), client_id, redirect_uri, http_client.clone()).await?;
            *old_data = Some(MicrosoftAuthData::new(access_token, refresh_token));
            Ok(())
        }
        Some(old_data) => {
            let (access_token, refresh_token) = retrieve_access_token(AuthOrRefresh::Refresh, &old_data.refresh_token, None, client_id, redirect_uri, http_client.clone()).await?;
            old_data.access_token = access_token;
            old_data.refresh_token = refresh_token;
            Ok(())
        }
    }
}

/// `redirect_uri` should be https://localhost:<port>
///
/// Returns (<auth_code>, <PKCE_secret>)
async fn retrieve_auth_code(client_id: &str, redirect_uri: &str, port: u16) -> Result<(String, String), MicrosoftAuthError> {
    let state = generate_secret(7);
    let secret = generate_secret(PASSWORD_LEN);
    let secret_hash = generate_hash256(&secret);
    let request_uri = format!("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_id={}&response_type=code&redirect_uri={}&scope=XboxLive.signin%20offline_access&state={}&code_challenge={}&code_challenge_method=S256", client_id, redirect_uri, state, secret_hash);

    let (code_tx, mut code_rx) = tokio::sync::mpsc::channel(1);
    let local_server = start_localhost(state, code_tx, port);
    debug!("localhost listener is up");

    webbrowser::open(&request_uri)?;

    let code = code_rx.recv().await.ok_or(MicrosoftAuthError::NoAuthCodeReceived)?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    local_server.abort();
    Ok((code, secret))
}

enum AuthOrRefresh {
    Authenticate,
    Refresh,
}

/// for refreshing, put the refresh token in  `auth_code`
///
async fn retrieve_access_token(auth_or_refresh: AuthOrRefresh, auth_code: &str, secret: Option<String>, client_id: &str, redirect_uri: &str, client: HttpClient) -> Result<(String, String), MicrosoftAuthError> {
    let request_uri = format!("https://login.microsoftonline.com/consumers/oauth2/v2.0/token");
    let request_params = match auth_or_refresh {
        AuthOrRefresh::Authenticate => format!("client_id={}&code={}&redirect_uri={}&grant_type=authorization_code&code_verifier={}", client_id, auth_code, redirect_uri, secret.unwrap()),
        AuthOrRefresh::Refresh => format!("client_id={}&refresh_token={}&redirect_uri={}&grant_type=refresh_token", client_id, auth_code, redirect_uri),
    };
    let response = client.send_async(
        Request::post(request_uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(request_params).unwrap()
    ).await?.json::<TokenResponse>().await?;
    match response {
        TokenResponse::Success(data) => Ok((data.access_token, data.refresh_token)),
        TokenResponse::Error(error) => Err(MicrosoftAuthError::TokenResponseError { cause: error }),
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TokenResponse {
    Success(TokenResponseSuccess),
    Error(TokenResponseError)
}

#[derive(Deserialize)]
struct TokenResponseSuccess {
    access_token: String,
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponseError {
    error: String,
    error_description: String,
}

impl TokenResponseError {
    pub fn error(&self) -> &str {
        &self.error
    }

    pub fn description(&self) -> &str {
        &self.error_description
    }
}

fn start_localhost(state: String, code_tx: Sender<String>, port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let warp_filter = warp::any()
            .and(warp::query::query::<AuthResponseQuery>())
            .map(move |auth_response: AuthResponseQuery| {
                if auth_response.state != state {
                    reply::with_status(
                        reply::html("Invalid state, malicious redirect?"),
                        StatusCode::BAD_REQUEST,
                    )
                } else {
                    code_tx.try_send(auth_response.code.clone()).unwrap();
                    reply::with_status(
                        reply::html("Successful authorization! You can close this window."),
                        StatusCode::OK,
                    )
                }
            });
        warp::serve(warp_filter)
            .run(([127, 0, 0, 1], port))
            .await;
    })
}

#[derive(Deserialize)]
struct AuthResponseQuery {
    code: String,
    state: String,
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
