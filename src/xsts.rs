use isahc::{AsyncReadResponseExt, HttpClient, Request};
use isahc::http::header::{ACCEPT, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::json;
use crate::DisplayClaims;
use crate::error::MicrosoftAuthError;

#[derive(Debug)]
pub struct XstsAuthData {
    token: String,
    user_hash: String,
}

impl XstsAuthData {
    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn user_hash(&self) -> &str {
        &self.user_hash
    }
}

pub async fn authenticate_xsts(xbl_token: &str, http_client: &HttpClient) -> Result<XstsAuthData, MicrosoftAuthError> {
    let xsts_body = json!({
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [
                xbl_token
            ]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    });
    let request_body = serde_json::to_string(&xsts_body).unwrap();
    let mut response = http_client.send_async(Request::post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .body(request_body).unwrap()
    ).await?;

    let response = response.json::<XstsResponse>().await;
    match response {
        Ok(data) => {
            let user_hash = data.display_claims.xui.get(0).unwrap().uhs.clone();
            Ok(XstsAuthData {
                token: data.token,
                user_hash
            })
        }
        Err(_) => Err(MicrosoftAuthError::XstsResponseError)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XstsResponse {
    token: String,
    display_claims: DisplayClaims,
}