use thiserror::Error;
use crate::auth::TokenResponseError;

#[derive(Debug, Error)]
pub enum MicrosoftAuthError {
    #[error("The authentication process returned an empty authorization code")]
    NoAuthCodeReceived,
    #[error("Received error while requesting token! CAT: {0.error}, DESC: {0.error_description}")]
    TokenResponseError(TokenResponseError),
    #[error("Could not parse to expected type: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("The authentication process returned an io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Isach returned an error: {0}")]
    IsahcError(#[from] isahc::error::Error),
}