#[macro_use]
extern crate tracing;

use std::time::Duration;

use isahc::{AsyncReadResponseExt, HttpClient, Request};
use isahc::http::header::{ACCEPT, CONTENT_TYPE};
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::Sender;
use microsoft_oauth_lib::{authenticate_or_refresh_microsoft, authenticate_xbox_live, authenticate_xsts};

const CLIENT_ID: &str = "f00ad152-9a55-4fc3-9af8-e44430d30cef";
const REDIRECT_URI: &str = "http://localhost:27134";

#[tokio::main]
async fn main() {
    let client = HttpClient::new().unwrap();
    let mut auth_data = None;
    authenticate_or_refresh_microsoft(&mut auth_data, CLIENT_ID, REDIRECT_URI, 27134, &client).await.unwrap();
    // authenticate_or_refresh(Some(&mut auth_data), CLIENT_ID, REDIRECT_URI, 27134, client.clone()).await.unwrap();
    let auth_data = auth_data.unwrap();
    println!("Successful Auth token response: {:?}", auth_data);

    let xbox_data = authenticate_xbox_live(auth_data.access_token(), &client).await.unwrap();
    println!("Successful Xbox Live token response: {:?}", xbox_data);

    let xsts_data = authenticate_xsts(xbox_data.token(), &client).await.unwrap();
    println!("Successful XSTS token authorization: {:?}", xsts_data);

    tokio::time::sleep(Duration::from_secs(1)).await;
}