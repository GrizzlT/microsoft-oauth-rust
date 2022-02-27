use std::time::Duration;
use base64ct::Encoding;
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
pub async fn authenticate_or_refresh_microsoft(old_data: &mut Option<MicrosoftAuthData>, client_id: &str, redirect_uri: &str, port: u16, http_client: &HttpClient, application_name: String) -> Result<(), MicrosoftAuthError> {
    match old_data {
        None => {
            let (code, secret): (String, String) = retrieve_auth_code(client_id, redirect_uri, port, application_name).await?;
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
async fn retrieve_auth_code(client_id: &str, redirect_uri: &str, port: u16, application_name: String) -> Result<(String, String), MicrosoftAuthError> {
    let state = generate_secret(7);
    let secret = generate_secret(PASSWORD_LEN);
    let secret_hash = generate_hash256(&secret);
    let request_uri = format!("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_id={}&response_type=code&redirect_uri={}&scope=XboxLive.signin%20offline_access&state={}&code_challenge={}&code_challenge_method=S256", client_id, redirect_uri, state, secret_hash);

    let (code_tx, mut code_rx) = tokio::sync::mpsc::channel(1);
    let local_server = start_localhost(state, code_tx, port, application_name);
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

fn start_localhost(state: String, code_tx: Sender<String>, port: u16, application_name: String) -> JoinHandle<()> {
    tokio::spawn(async move {
        let warp_filter = warp::any()
            .and(warp::query::query::<AuthCodeResponse>())
            .map(move |auth_response: AuthCodeResponse| {
                match auth_response {
                    AuthCodeResponse::Success(query) => {
                        if query.state != state {
                            reply::with_status(
                                reply::html(create_html_response(false, "Invalid state, malicious redirect?", &application_name)),
                                StatusCode::BAD_REQUEST,
                            )
                        } else {
                            code_tx.try_send(query.code.clone()).unwrap();
                            reply::with_status(
                                reply::html(create_html_response(true, "Successful authorization! You can close this window.", &application_name)),
                                StatusCode::OK,
                            )
                        }
                    }
                    AuthCodeResponse::Error(error) => {
                        reply::with_status(
                            reply::html(create_html_response(false, &format!("{} - {}", error.error, error.error_description), &application_name)),
                            StatusCode::BAD_REQUEST,
                        )
                    }
                }
            });
        warp::serve(warp_filter)
            .run(([127, 0, 0, 1], port))
            .await;
    })
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AuthCodeResponse {
    Success(AuthResponseQuery),
    Error(TokenResponseError),
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
    base64ct::Base64UrlUnpadded::encode_string(&hash)
}

fn create_html_response(is_success: bool, message: &str, application_name: &str) -> String {
    let color = if is_success { "8bc34a" } else { "c34a4a" };
    let title = if is_success { "Successful authorization" } else { "Response error" };
    let svg_style = if is_success {
        r##"<svg
          version="1.1"
          id="checkmark"
          xmlns="http://www.w3.org/2000/svg"
          xmlns:xlink="http://www.w3.org/1999/xlink"
          x="0px"
          y="0px"
          xml:space="preserve"
        >
        <path
          d="M131.583,92.152l-0.026-0.041c-0.713-1.118-2.197-1.447-3.316-0.734l-31.782,20.257l-4.74-12.65
	c-0.483-1.29-1.882-1.958-3.124-1.493l-0.045,0.017c-1.242,0.465-1.857,1.888-1.374,3.178l5.763,15.382
	c0.131,0.351,0.334,0.65,0.579,0.898c0.028,0.029,0.06,0.052,0.089,0.08c0.08,0.073,0.159,0.147,0.246,0.209
	c0.071,0.051,0.147,0.091,0.222,0.133c0.058,0.033,0.115,0.069,0.175,0.097c0.081,0.037,0.165,0.063,0.249,0.091
	c0.065,0.022,0.128,0.047,0.195,0.063c0.079,0.019,0.159,0.026,0.239,0.037c0.074,0.01,0.147,0.024,0.221,0.027
	c0.097,0.004,0.194-0.006,0.292-0.014c0.055-0.005,0.109-0.003,0.163-0.012c0.323-0.048,0.641-0.16,0.933-0.346l34.305-21.865
	C131.967,94.755,132.296,93.271,131.583,92.152z"
        />
        <circle
            fill="none"
            stroke="#ffffff"
            stroke-width="5"
            stroke-miterlimit="10"
            cx="109.486"
            cy="104.353"
            r="32.53"
          />
        </svg>
        "##
    } else {
        r#"
        <svg class="svg-icon" viewBox="0 0 20 20">
        <path
          d="M10.185,1.417c-4.741,0-8.583,3.842-8.583,8.583c0,4.74,3.842,8.582,8.583,8.582S18.768,14.74,18.768,10C18.768,5.259,14.926,1.417,10.185,1.417 M10.185,17.68c-4.235,0-7.679-3.445-7.679-7.68c0-4.235,3.444-7.679,7.679-7.679S17.864,5.765,17.864,10C17.864,14.234,14.42,17.68,10.185,17.68 M10.824,10l2.842-2.844c0.178-0.176,0.178-0.46,0-0.637c-0.177-0.178-0.461-0.178-0.637,0l-2.844,2.841L7.341,6.52c-0.176-0.178-0.46-0.178-0.637,0c-0.178,0.176-0.178,0.461,0,0.637L9.546,10l-2.841,2.844c-0.178,0.176-0.178,0.461,0,0.637c0.178,0.178,0.459,0.178,0.637,0l2.844-2.841l2.844,2.841c0.178,0.178,0.459,0.178,0.637,0c0.178-0.176,0.178-0.461,0-0.637L10.824,10z"
        ></path>
        </svg>
        "#
    };
    format!(r#"
<!DOCTYPE html>
<html lang="en">
  <head>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Josefin+Sans&display=swap"
      rel="stylesheet"
    />
    <link
      rel="shortcut icon"
      href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAB11BMVEUAAABCQz5DQD2RlJD8///EysmYlppnYm2qLypsbnuaJCKBaXSTJCNGPjBIPy6np6mmpqhQPidFOitaSzqpjTg5LBp6bUp3Z2qYiH2WlpOVlpPO3NzFxse5uLiysbKuq62lODWMKSihe3rd2trf3d/R0dLBwMGurK2SNDWVKyqeKierMS3S0tK+vr+pqKiRNTWMJyecKSaqLihra2ucNjaUKiqkKiVzHB2SIyE3IRM6KRg/KxY/MBo3IBI4KBc7Lx9cVElNPitHOypWQiFFLBZPJxY2IBI3Jxc9MB9MST1OOx83JxZINR5LMhtRKxk3IBI4Lx1TTD1EMiVVQSI3KRdaRidTRCY5LBx2aUduYEPu7u+dMS6ZVVTEqanl4uPo6eunKyagKSaoMC2bJiONJSSVUFC4nJ28urqRk5KmKSScJiKVIyGUIiGSISGPISCTIh+DGxlgGhpdTk5fX15PS0OsLCaoKiSYJCKTIiGRISGPICCKHh58GhtjFRZJDxA8Dw1ALyhBNic9LxlYFBNnFxaEHx6WJCGLHx+AHB1lFRZIDxA7Dg02FQ5XMRxWHBVaFRRmFhd9HByAHBxlFhZLEBBRGxRXFBNMEBE9EA05Fg5DIBROPyD///9Ke2B1AAAAWnRSTlMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAELT6VyGgxQtPX80W8aDFG39vzQdwxQt/b+DU/2v/Xik7G944srAgoM/vv144srAnZrSKj05SsCCa1wWacvAQR2sKI+AAAAAWJLR0SccbzCJwAAAAd0SU1FB+YCGhMIAnEaQKkAAADHSURBVBjTY2DABRiZJKWYEVwWVmkZWTl5BjYIl51DQVFJOUpFVU0dxOXk0tDU0o6OiY2L19HVY+Dm0TcwNEpITEpOSU1LzzBmMDE1NMvMys7JzcsvKCwqLmEwtygtK6+orKquqa2rb2hsYmhuaW0rr2zv6Ozq7rG0srZh6O3rnzBx0uQp3T22dvYOjk4Mzi6uU6dNnzHTzd3DkxdkqZe3j6/fLH+7gEA+iKP4BQSDgmeHMAghnC0sEhoWLorsL7GISHEJnL4GAJvWMbE9a0B8AAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDIyLTAyLTI2VDE5OjA4OjAyKzAwOjAwTwfq4wAAACV0RVh0ZGF0ZTptb2RpZnkAMjAyMi0wMi0yNlQxOTowODowMiswMDowMD5aUl8AAABXelRYdFJhdyBwcm9maWxlIHR5cGUgaXB0YwAAeJzj8gwIcVYoKMpPy8xJ5VIAAyMLLmMLEyMTS5MUAxMgRIA0w2QDI7NUIMvY1MjEzMQcxAfLgEigSi4A6hcRdPJCNZUAAAAASUVORK5CYII="
    />
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="author" content="Arthur#6708" />
    <meta
      name="description"
      content="{0}: {1}"
    />
    <title>{0}: {3}</title>
  </head>
  <body>
    <div id="card" class="animated fadeIn">
      <div id="upper-side">
        <?xml version="1.0" encoding="utf-8"?>
        <!-- Generator: Adobe Illustrator 17.1.0, SVG Export Plug-In . SVG Version: 6.00 Build 0)  -->
        <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
        {2}
        <h3 id="status">{3}</h3>
      </div>
      <div id="lower-side">
        <p id="message">{1}
        <a id="logo">{0}</a>
      </div>
    </div>
    <style>
      {5}
      body {{
        background: rgb(199, 199, 199);
      }}
      #card {{
        position: relative;
        width: 320px;
        display: block;
        margin: 40px auto;
        text-align: center;
        font-family: "Source Sans Pro", sans-serif;
      }}
      #upper-side {{
        padding: 2em;
        background-color: #{4};
        display: block;
        color: #fff;
        border-top-right-radius: 8px;
        border-top-left-radius: 8px;
      }}
      #checkmark {{
        font-weight: lighter;
        fill: #fff;
        margin: -3.5em auto auto 20px;
      }}
      #status {{
        font-weight: lighter;
        text-transform: uppercase;
        letter-spacing: 2px;
        font-size: 1em;
        margin-top: -0.2em;
        margin-bottom: 0;
      }}
      #lower-side {{
        padding: 3em 2em 2em 2em;
        background: #fff;
        display: block;
        border-bottom-right-radius: 8px;
        border-bottom-left-radius: 8px;
      }}
      #message {{
        margin-top: -0.5em;
        color: #757575;
        letter-spacing: 1px;
      }}
      #logo {{
        font-size: 1.2em;
        font-family: "Josefin Sans", sans-serif;
        color: gray;
        display: inline-block;
        position: relative;
        text-decoration: none;
        padding-top: 5vh;
        user-select: none;
      }}
      #logo:after {{
        content: "";
        position: absolute;
        width: 100%;
        transform: scaleX(0);
        height: 2px;
        bottom: 0;
        left: 0;
        background-color: gray;
        transform-origin: bottom right;
        transition: transform 0.25s ease-out;
      }}
      #logo:hover:after {{
        transform: scaleX(1);
        transform-origin: bottom left;
      }}
    </style>
  </body>
</html>
    "#, application_name, message, svg_style, title, color, if !is_success {
        r#"
        .svg-icon {{
        width: 5em;
        height: 5em;
        margin-bottom: 2vh;
      }}
      .svg-icon path,
      .svg-icon polygon,
      .svg-icon rect {{
        fill: #ffffff;
      }}
      .svg-icon circle {{
        stroke: #ffffff;
        stroke-width: 1;
      }}
        "#
    } else {""})
}
