#[macro_use]
extern crate tracing;

use serde::Deserialize;

pub use auth::{authenticate_or_refresh_microsoft, MicrosoftAuthData, TokenResponseError};
pub use xbox::{authenticate_xbox_live, XblAuthData};
pub use xsts::{authenticate_xsts, XstsAuthData};

pub mod error;
mod auth;
mod xbox;
mod xsts;

#[derive(Debug, Deserialize)]
pub(crate) struct DisplayClaims {
    pub(crate) xui: Vec<Xui>,
}
#[derive(Debug, Deserialize)]
pub(crate) struct Xui {
    pub(crate) uhs: String,
}