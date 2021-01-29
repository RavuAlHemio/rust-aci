use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use async_trait::async_trait;
use hyper::{Body, StatusCode};
use hyper::client::Client;
use json::{self, JsonValue};
use url::Url;

use crate::conn;
use crate::error::ApicCommError;


/// Data returned from the APIC authenticator to the APIC connection.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApicAuthenticatorData {
    apic_cookie: String,
    apic_challenge: Option<String>,
}
impl ApicAuthenticatorData {
    /// Creates a new instance of ApicAuthenticatorData.
    pub fn new(
        apic_cookie: String,
        apic_challenge: Option<String>,
    ) -> ApicAuthenticatorData {
        ApicAuthenticatorData {
            apic_cookie,
            apic_challenge,
        }
    }

    /// Returns the value of the APIC cookie.
    pub fn apic_cookie(&self) -> &str {
        &self.apic_cookie
    }

    /// Returns the value of the APIC challenge (used for stronger security), or None if no
    /// challenge has been provided by the server.
    pub fn apic_challenge(&self) -> Option<&str> {
        self.apic_challenge.as_deref()
    }

    /// Returns the authenticator data as headers than can be sent to the HTTP server.
    pub fn as_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Cookie".into(), format!("APIC-cookie={}", self.apic_cookie()));
        if let Some(ac) = self.apic_challenge() {
            headers.insert("APIC-challenge".into(), ac.into());
        }
        headers
    }
}

/// Implementors of this trait can login to an Application Policy Infrastructure Controller (APIC).
#[async_trait]
pub trait ApicAuthenticator<E: Error> {
    async fn login<C>(
        &self,
        client: &Client<C, Body>,
        base_uri: &Url,
    ) -> Result<ApicAuthenticatorData, E>
        where
            C: 'static + Clone + hyper::client::connect::Connect + Send + Sync;

    async fn refresh<C>(
        &self,
        client: &Client<C, Body>,
        base_uri: &Url,
        current_data: &ApicAuthenticatorData,
    ) -> Result<ApicAuthenticatorData, E>
        where
            C: 'static + Clone + hyper::client::connect::Connect + Send + Sync;
}

/// An error produced by username-and-password authentication.
#[derive(Debug)]
pub enum ApicUsernamePasswordError {
    /// An error that can also happen during normal communication with the APIC.
    ApicCommError(ApicCommError),

    /// The supplied credentials were incorrect.
    InvalidCredentials,

    /// The expected token value was missing from the APIC response.
    MissingToken(JsonValue),
}
impl fmt::Display for ApicUsernamePasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            ApicUsernamePasswordError::ApicCommError(e)
                => e.fmt(f),
            ApicUsernamePasswordError::InvalidCredentials
                => write!(f, "invalid credentials supplied"),
            ApicUsernamePasswordError::MissingToken(doc)
                => write!(f, "response missing a required token: {}", doc),
        }
    }
}
impl From<ApicCommError> for ApicUsernamePasswordError {
    fn from(e: ApicCommError) -> Self {
        ApicUsernamePasswordError::ApicCommError(e)
    }
}
impl Error for ApicUsernamePasswordError {
}

/// An authenticator that logs into the Application Policy Infrastructure Controller (APIC) using
/// a username and a password.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApicUsernamePasswordAuth {
    username: String,
    password: String,
}
impl ApicUsernamePasswordAuth {
    /// Creates a new instance of the authenticator for username-password authentication.
    pub fn new(
        username: String,
        password: String,
    ) -> ApicUsernamePasswordAuth {
        ApicUsernamePasswordAuth {
            username,
            password,
        }
    }

    /// Returns the username stored in this authenticator.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the password stored in this authenticator.
    pub fn password(&self) -> &str {
        &self.password
    }
}
#[async_trait]
impl ApicAuthenticator<ApicUsernamePasswordError> for ApicUsernamePasswordAuth {
    async fn login<C>(
        &self,
        client: &Client<C, Body>,
        base_uri: &Url,
    ) -> Result<ApicAuthenticatorData, ApicUsernamePasswordError>
        where
            C: 'static + Clone + hyper::client::connect::Connect + Send + Sync {
        let uri = base_uri.join("api/aaaLogin.json?gui-token-request=yes")
            .map_err(|e| ApicCommError::InvalidUri(e))?;

        let req_body = json::object! {
            aaaUser: {
                attributes: {
                    name: self.username.clone(),
                    pwd: self.password.clone(),
                }
            }
        };

        let response_json_res = conn::perform_json_request(
            client,
            uri,
            "POST",
            &HashMap::new(),
            Some(req_body),
        ).await;
        let response_json = match response_json_res {
            Ok(r) => r,
            Err(ApicCommError::ErrorResponse(resp)) => {
                if resp.status() == StatusCode::FORBIDDEN {
                    return Err(ApicUsernamePasswordError::InvalidCredentials);
                } else {
                    return Err(ApicCommError::ErrorResponse(resp).into());
                }
            },
            Err(e) => {
                return Err(e.into());
            },
        };

        let attribs = &response_json["imdata"][0]["aaaLogin"]["attributes"];
        if !attribs.is_object() {
            return Err(ApicUsernamePasswordError::MissingToken(response_json));
        }
        let token = match attribs["token"].as_str() {
            Some(s) => String::from(s),
            None => return Err(ApicUsernamePasswordError::MissingToken(response_json)),
        };
        let url_token = attribs["urlToken"]
            .as_str()
            .map(String::from);

        Ok(ApicAuthenticatorData::new(
            token,
            url_token,
        ))
    }

    async fn refresh<C>(
        &self,
        client: &Client<C, Body>,
        base_uri: &Url,
        current_data: &ApicAuthenticatorData,
    ) -> Result<ApicAuthenticatorData, ApicUsernamePasswordError>
            where C: 'static + Clone + hyper::client::connect::Connect + Send + Sync {
        let uri = base_uri.join("api/aaaRefresh.json")
            .map_err(|e| ApicCommError::InvalidUri(e))?;

        let req_body = json::object! {
            aaaUser: {
                attributes: {
                    name: self.username.clone(),
                    pwd: self.password.clone(),
                }
            }
        };

        let response_json_res = conn::perform_json_request(
            client,
            uri,
            "POST",
            &HashMap::new(),
            Some(req_body),
        ).await;
        let response_json = match response_json_res {
            Ok(r) => r,
            Err(ApicCommError::ErrorResponse(resp)) => {
                if resp.status() == StatusCode::FORBIDDEN {
                    return Err(ApicUsernamePasswordError::InvalidCredentials);
                } else {
                    return Err(ApicCommError::ErrorResponse(resp).into());
                }
            },
            Err(e) => {
                return Err(e.into());
            },
        };

        let attribs = &response_json["imdata"][0]["aaaLogin"]["attributes"];
        if !attribs.is_object() {
            return Err(ApicUsernamePasswordError::MissingToken(response_json));
        }

        let mut token = String::from(current_data.apic_cookie());
        let mut url_token = current_data.apic_challenge().map(String::from);

        if let Some(t) = attribs["token"].as_str() {
            if t.len() > 0 {
                token = String::from(t);
            }
        }
        if let Some(ut) = attribs["urlToken"].as_str() {
            if ut.len() > 0 {
                url_token = Some(String::from(ut));
            }
        }

        Ok(ApicAuthenticatorData::new(
            token,
            url_token,
        ))
    }
}
