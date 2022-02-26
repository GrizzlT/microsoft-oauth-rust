use thiserror::Error;
use crate::auth::TokenResponseError;

#[derive(Debug, Error)]
pub enum MicrosoftAuthError {
    #[error("The authentication process returned an empty authorization code")]
    NoAuthCodeReceived,
    #[error("Received error while requesting token! Cat: {}, Desc: {}", .cause.error(), .cause.description())]
    TokenResponseError { cause: TokenResponseError },
    #[error("XBL could not be authorized!")]
    XblResponseError,
    #[error("XSTS could not be authorized!")]
    XstsResponseError,
    #[error("Could not parse to expected type: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("The authentication process returned an io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Isach returned an error: {0}")]
    IsahcError(#[from] isahc::error::Error),
}