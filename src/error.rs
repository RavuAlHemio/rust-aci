use std::error::Error;
use std::fmt;
use std::str::Utf8Error;

use crate::AciObjectError;

/// An error that occurred during communication with the Application Policy Infrastructure
/// Controller (APIC).
#[derive(Debug)]
pub enum ApicCommError {
    /// Constructing the login URI failed.
    InvalidUri(url::ParseError),

    /// The APIC has rejected the credentials.
    InvalidCredentials,

    /// The expected token value was missing from the APIC response during authentication.
    MissingSessionToken(json::JsonValue),

    /// An error occurred while assembling the HTTP request.
    ErrorAssemblingRequest(hyper::http::Error),

    /// An error occurred when obtaining the HTTP response.
    ErrorObtainingResponse(hyper::Error),

    /// An error response has been returned by the APIC.
    ErrorResponse(hyper::Response<hyper::Body>),

    /// The APIC response is not valid UTF-8.
    InvalidUtf8(Utf8Error),

    /// The APIC response is not valid JSON.
    InvalidJson(json::Error),

    /// An invalid ACI object has been returned.
    InvalidAciObject(AciObjectError),

    /// The operation took too long to complete.
    Timeout,

    /// No APIC has been specified.
    NoApicSpecified,
}
impl fmt::Display for ApicCommError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            ApicCommError::InvalidUri(u)
                => write!(f, "invalid URI: {}", u),
            ApicCommError::InvalidCredentials
                => write!(f, "invalid credentials"),
            ApicCommError::MissingSessionToken(v)
                => write!(f, "missing session token in response {}", v),
            ApicCommError::ErrorAssemblingRequest(e)
                => write!(f, "error assembling request: {}", e),
            ApicCommError::ErrorObtainingResponse(e)
                => write!(f, "error obtaining response: {}", e),
            ApicCommError::ErrorResponse(_e)
                => write!(f, "server returned negative response"),
            ApicCommError::InvalidUtf8(e)
                => write!(f, "server returned response that was not valid UTF-8: {}", e),
            ApicCommError::InvalidJson(e)
                => write!(f, "server returned response that was not valid JSON: {}", e),
            ApicCommError::InvalidAciObject(e)
                => write!(f, "server returned an invalid ACI object: {}", e),
            ApicCommError::Timeout
                => write!(f, "request timed out"),
            ApicCommError::NoApicSpecified
                => write!(f, "no APIC specified"),
        }
    }
}
impl Error for ApicCommError {
}
