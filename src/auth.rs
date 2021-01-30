use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use hyper::{Body, StatusCode};
use hyper::client::Client;
use json;
use log::debug;
use url::Url;

use crate::conn;
use crate::error::ApicCommError;


/// Data returned from the APIC authenticator to the APIC connection.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApicAuthenticatorData {
    apic_cookie: String,
    apic_challenge: Option<String>,
    refresh_timeout: Duration,
}
impl ApicAuthenticatorData {
    /// Creates a new instance of ApicAuthenticatorData.
    pub fn new(
        apic_cookie: String,
        apic_challenge: Option<String>,
        refresh_timeout: Duration,
    ) -> ApicAuthenticatorData {
        ApicAuthenticatorData {
            apic_cookie,
            apic_challenge,
            refresh_timeout,
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

    /// Returns the duration after which the login session to the APIC must be refreshed.
    pub fn refresh_timeout(&self) -> Duration {
        self.refresh_timeout
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
impl Default for ApicAuthenticatorData {
    fn default() -> Self {
        Self {
            apic_cookie: String::new(),
            apic_challenge: None,
            refresh_timeout: Duration::from_nanos(0),
        }
    }
}

/// Implementors of this trait can login to an Application Policy Infrastructure Controller (APIC).
#[async_trait]
pub trait ApicAuthenticator {
    async fn login<C>(
        &self,
        client: &Client<C, Body>,
        base_uri: &Url,
        timeout: Duration,
    ) -> Result<ApicAuthenticatorData, ApicCommError>
        where
            C: 'static + Clone + hyper::client::connect::Connect + Send + Sync;

    async fn refresh<C>(
        &self,
        client: &Client<C, Body>,
        base_uri: &Url,
        timeout: Duration,
        current_data: &ApicAuthenticatorData,
    ) -> Result<ApicAuthenticatorData, ApicCommError>
        where
            C: 'static + Clone + hyper::client::connect::Connect + Send + Sync;
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
impl ApicAuthenticator for ApicUsernamePasswordAuth {
    async fn login<C>(
        &self,
        client: &Client<C, Body>,
        base_uri: &Url,
        timeout: Duration,
    ) -> Result<ApicAuthenticatorData, ApicCommError>
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
            timeout,
        ).await;
        let response_json = match response_json_res {
            Ok(r) => r,
            Err(ApicCommError::ErrorResponse(resp)) => {
                if resp.status() == StatusCode::FORBIDDEN {
                    return Err(ApicCommError::InvalidCredentials);
                } else {
                    return Err(ApicCommError::ErrorResponse(resp));
                }
            },
            Err(e) => {
                return Err(e);
            },
        };

        let attribs = &response_json["imdata"][0]["aaaLogin"]["attributes"];
        debug!("login attributes: {}", attribs);
        if !attribs.is_object() {
            return Err(ApicCommError::MissingSessionToken(response_json));
        }
        let token = match attribs["token"].as_str() {
            Some(s) => String::from(s),
            None => return Err(ApicCommError::MissingSessionToken(response_json)),
        };
        let url_token = attribs["urlToken"]
            .as_str()
            .map(String::from);
        let refresh_timeout = attribs["refreshTimeoutSeconds"].as_str()
            .map(|rts| rts.parse::<u64>().ok())
            .flatten()
            .map(|i| Duration::from_secs(i))
            .unwrap_or(Duration::from_secs(600));

        Ok(ApicAuthenticatorData::new(
            token,
            url_token,
            refresh_timeout,
        ))
    }

    async fn refresh<C>(
        &self,
        client: &Client<C, Body>,
        base_uri: &Url,
        timeout: Duration,
        current_data: &ApicAuthenticatorData,
    ) -> Result<ApicAuthenticatorData, ApicCommError>
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
            timeout,
        ).await;
        let response_json = match response_json_res {
            Ok(r) => r,
            Err(ApicCommError::ErrorResponse(resp)) => {
                if resp.status() == StatusCode::FORBIDDEN {
                    return Err(ApicCommError::InvalidCredentials);
                } else {
                    return Err(ApicCommError::ErrorResponse(resp));
                }
            },
            Err(e) => {
                return Err(e);
            },
        };

        let attribs = &response_json["imdata"][0]["aaaLogin"]["attributes"];
        debug!("refreshed login attributes: {}", attribs);
        if !attribs.is_object() {
            return Err(ApicCommError::MissingSessionToken(response_json));
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
        let refresh_timeout = attribs["refreshTimeoutSeconds"].as_str()
            .map(|rts| rts.parse::<u64>().ok())
            .flatten()
            .map(|i| Duration::from_secs(i))
            .unwrap_or(Duration::from_secs(600));

        Ok(ApicAuthenticatorData::new(
            token,
            url_token,
            refresh_timeout,
        ))
    }
}
