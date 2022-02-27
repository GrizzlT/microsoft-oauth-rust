#[macro_use]
extern crate tracing;

use isahc::HttpClient;
use serde::Deserialize;

pub use auth::{authenticate_or_refresh_microsoft, MicrosoftAuthData, TokenResponseError};
pub use xbox::{authenticate_xbox_live, XblAuthData};
pub use xsts::{authenticate_xsts, XstsAuthData};
pub use error::MicrosoftAuthError;

mod error;
mod auth;
mod xbox;
mod xsts;

/// Authenticates with microsoft and returns
/// an XSTS-token.
///
/// * `old_data` will get updated
/// * `redirect_uri` should be `http://localhost:<port>`
pub async fn auth_microsoft_to_xsts(old_data: &mut Option<MicrosoftAuthData>, client_id: &str, redirect_uri: &str, port: u16, application_name: String) -> Result<XstsAuthData, MicrosoftAuthError> {
    let client = HttpClient::new().unwrap();
    authenticate_or_refresh_microsoft(old_data, client_id, redirect_uri, port, &client, application_name).await?;
    let auth_data = old_data.as_ref().unwrap();
    let xbox_data = authenticate_xbox_live(auth_data.access_token(), &client).await?;
    authenticate_xsts(xbox_data.token(), &client).await
}

#[derive(Debug, Deserialize)]
pub(crate) struct DisplayClaims {
    pub(crate) xui: Vec<Xui>,
}
#[derive(Debug, Deserialize)]
pub(crate) struct Xui {
    pub(crate) uhs: String,
}

#[test]
pub fn test_auth() {
    tokio_test::block_on(async move {
        const CLIENT_ID: &str = "f00ad152-9a55-4fc3-9af8-e44430d30cef";
        const REDIRECT_URI: &str = "http://localhost:27134";

        let mut old_data = None;
        let application_name = String::from("BwTuiTalker");
        let xsts_data = auth_microsoft_to_xsts(&mut old_data, CLIENT_ID, REDIRECT_URI, 27134, application_name).await.unwrap();
        println!("Data: {:?}", xsts_data);
    });
}