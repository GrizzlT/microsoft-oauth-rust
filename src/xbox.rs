use isahc::{AsyncReadResponseExt, HttpClient, Request};
use isahc::http::header::{ACCEPT, CONTENT_TYPE};
use serde_json::json;
use serde::Deserialize;
use crate::DisplayClaims;
use crate::error::MicrosoftAuthError;

#[derive(Debug)]
pub struct XblAuthData {
    token: String,
    user_hash: String,
}

impl XblAuthData {
    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn user_hash(&self) -> &str {
        &self.user_hash
    }
}

pub async fn authenticate_xbox_live(access_token: &str, http_client: &HttpClient) -> Result<XblAuthData, MicrosoftAuthError> {
    let rps_ticket = String::from("d=") + access_token;
    let xbox_body = json!({
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": rps_ticket
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    });
    let request_body = serde_json::to_string(&xbox_body).unwrap();
    let mut response = http_client.send_async(Request::post("https://user.auth.xboxlive.com/user/authenticate")
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .body(request_body).unwrap()
    ).await?;

    let response = response.json::<XblResponse>().await;
    match response {
        Ok(data) => {
            let user_hash = data.display_claims.xui.get(0).unwrap().uhs.clone();
            Ok(XblAuthData {
                token: data.token,
                user_hash
            })
        }
        Err(_) => Err(MicrosoftAuthError::XblResponseError)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XblResponse {
    token: String,
    display_claims: DisplayClaims,
}