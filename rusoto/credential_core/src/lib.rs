#![doc(
    html_logo_url = "https://raw.githubusercontent.com/rusoto/rusoto/master/assets/logo-square.png"
)]
#![cfg_attr(feature = "nightly-testing", feature(plugin))]
#![cfg_attr(not(feature = "unstable"), deny(warnings))]
#![deny(missing_docs)]

//! Types for loading and managing AWS access credentials for API requests.

pub use crate::secrets::Secret;
pub use crate::variable::Variable;

pub mod claims;
mod secrets;
#[cfg(test)]
pub(crate) mod test_utils;
mod variable;

use async_trait::async_trait;
use std::collections::BTreeMap;
use std::env::VarError;
use std::error::Error;
use std::fmt;
use std::io::Error as IoError;
use std::string::FromUtf8Error;
use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, ParseError, Utc};
use hyper::Error as HyperError;
use serde::Deserialize;
use tokio::sync::Mutex;

/// Representation of anonymity
pub trait Anonymous {
    /// Return true if a type is anonymous, false otherwise
    fn is_anonymous(&self) -> bool;
}

impl Anonymous for AwsCredentials {
    fn is_anonymous(&self) -> bool {
        self.aws_access_key_id().is_empty() && self.aws_secret_access_key().is_empty()
    }
}

/// AWS API access credentials, including access key, secret key, token (for IAM profiles),
/// expiration timestamp, and claims from federated login.
///
/// # Anonymous example
///
/// Some AWS services, like [s3](https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html) do
/// not require authenticated credentials. For these cases you can use `AwsCredentials::default`
/// with `StaticProvider`.
#[derive(Clone, Deserialize, Default)]
pub struct AwsCredentials {
    #[serde(rename = "AccessKeyId")]
    key: String,
    #[serde(rename = "SecretAccessKey")]
    secret: String,
    #[serde(rename = "SessionToken", alias = "Token")]
    token: Option<String>,
    #[serde(rename = "Expiration")]
    expires_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    claims: BTreeMap<String, String>,
}

impl AwsCredentials {
    /// Create a new `AwsCredentials` from a key ID, secret key, optional access token, and expiry
    /// time.
    pub fn new<K, S>(
        key: K,
        secret: S,
        token: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> AwsCredentials
    where
        K: Into<String>,
        S: Into<String>,
    {
        AwsCredentials {
            key: key.into(),
            secret: secret.into(),
            token,
            expires_at,
            claims: BTreeMap::new(),
        }
    }

    /// Get a reference to the access key ID.
    pub fn aws_access_key_id(&self) -> &str {
        &self.key
    }

    /// Get a reference to the secret access key.
    pub fn aws_secret_access_key(&self) -> &str {
        &self.secret
    }

    /// Get a reference to the expiry time.
    pub fn expires_at(&self) -> &Option<DateTime<Utc>> {
        &self.expires_at
    }

    /// Get a reference to the access token.
    pub fn token(&self) -> &Option<String> {
        &self.token
    }

    /// Determine whether or not the credentials are expired.
    fn credentials_are_expired(&self) -> bool {
        match self.expires_at {
            Some(ref e) =>
            // This is a rough hack to hopefully avoid someone requesting creds then sitting on them
            // before issuing the request:
            {
                *e < Utc::now() + ChronoDuration::seconds(20)
            }
            None => false,
        }
    }

    /// Get the token claims
    pub fn claims(&self) -> &BTreeMap<String, String> {
        &self.claims
    }

    /// Get the mutable token claims
    pub fn claims_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.claims
    }

    /// Set expires at, intended to be used by AwsCredentialsProvider
    pub fn set_expires_at(&mut self, expires_at: Option<DateTime<Utc>>) {
        self.expires_at = expires_at;
    }
}

impl fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("key", &self.key)
            .field("secret", &"**********")
            .field("token", &self.token.as_ref().map(|_| "**********"))
            .field("expires_at", &self.expires_at)
            .field("claims", &self.claims)
            .finish()
    }
}

/// Represents an Error that has occured during the fetching Credentials Phase.
///
/// This generally is an error message from one of our underlying libraries, however
/// we wrap it up with this type so we can export one single error type.
#[derive(Clone, Debug, PartialEq)]
pub struct CredentialsError {
    /// The underlying error message for the credentials error.
    pub message: String,
}

impl CredentialsError {
    /// Creates a new Credentials Error.
    ///
    /// * `message` - The Error message for this CredentialsError.
    pub fn new<S>(message: S) -> CredentialsError
    where
        S: ToString,
    {
        CredentialsError {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for CredentialsError {}

impl From<ParseError> for CredentialsError {
    fn from(err: ParseError) -> CredentialsError {
        CredentialsError::new(err)
    }
}

impl From<IoError> for CredentialsError {
    fn from(err: IoError) -> CredentialsError {
        CredentialsError::new(err)
    }
}

impl From<HyperError> for CredentialsError {
    fn from(err: HyperError) -> CredentialsError {
        CredentialsError::new(format!("Couldn't connect to credentials provider: {}", err))
    }
}

impl From<serde_json::Error> for CredentialsError {
    fn from(err: serde_json::Error) -> CredentialsError {
        CredentialsError::new(err)
    }
}

impl From<VarError> for CredentialsError {
    fn from(err: VarError) -> CredentialsError {
        CredentialsError::new(err)
    }
}

impl From<FromUtf8Error> for CredentialsError {
    fn from(err: FromUtf8Error) -> CredentialsError {
        CredentialsError::new(err)
    }
}

/// A trait for types that produce `AwsCredentials`.
#[async_trait]
pub trait ProvideAwsCredentials {
    /// Produce a new `AwsCredentials` future.
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError>;
}

#[async_trait]
impl<P: ProvideAwsCredentials + Send + Sync> ProvideAwsCredentials for Arc<P> {
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        P::credentials(self).await
    }
}

/// Wrapper for `ProvideAwsCredentials` that caches the credentials returned by the
/// wrapped provider.  Each time the credentials are accessed, they are checked to see if
/// they have expired, in which case they are retrieved from the wrapped provider again.
///
/// In order to access the wrapped provider, for instance to set a timeout, the `get_ref`
/// and `get_mut` methods can be used.
#[derive(Debug, Clone)]
pub struct AutoRefreshingProvider<P: ProvideAwsCredentials + 'static> {
    credentials_provider: P,
    current_credentials: Arc<Mutex<Option<Result<AwsCredentials, CredentialsError>>>>,
}

impl<P: ProvideAwsCredentials + 'static> AutoRefreshingProvider<P> {
    /// Create a new `AutoRefreshingProvider` around the provided base provider.
    pub fn new(provider: P) -> Result<AutoRefreshingProvider<P>, CredentialsError> {
        Ok(AutoRefreshingProvider {
            credentials_provider: provider,
            current_credentials: Arc::new(Mutex::new(None)),
        })
    }

    /// Get a shared reference to the wrapped provider.
    pub fn get_ref(&self) -> &P {
        &self.credentials_provider
    }

    /// Get a mutable reference to the wrapped provider.
    ///
    /// This can be used to call `set_timeout` on the wrapped
    /// provider.
    pub fn get_mut(&mut self) -> &mut P {
        &mut self.credentials_provider
    }
}

#[async_trait]
impl<P: ProvideAwsCredentials + Send + Sync + 'static> ProvideAwsCredentials
    for AutoRefreshingProvider<P>
{
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        loop {
            let mut guard = self.current_credentials.lock().await;
            match guard.as_ref() {
                // no result from the future yet, let's keep using it
                None => {
                    let res = self.credentials_provider.credentials().await;
                    *guard = Some(res);
                }
                Some(Err(e)) => return Err(e.clone()),
                Some(Ok(creds)) => {
                    if creds.credentials_are_expired() {
                        *guard = None;
                    } else {
                        return Ok(creds.clone());
                    };
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::test_utils::{is_secret_hidden_behind_asterisks, SECRET};
    use quickcheck::quickcheck;

    use super::*;

    #[test]
    fn default_empty_credentials_are_considered_anonymous() {
        assert!(AwsCredentials::default().is_anonymous())
    }

    #[test]
    fn credentials_with_values_are_not_considered_anonymous() {
        assert!(!AwsCredentials::new("foo", "bar", None, None).is_anonymous())
    }

    #[cfg(test)]
    quickcheck! {
        fn test_aws_credentials_secrets_not_in_debug(
            key: String,
            valid_for: Option<i64>,
            token: Option<()>
        ) -> bool {
            let creds = AwsCredentials::new(
                key,
                SECRET.to_owned(),
                token.map(|_| test_utils::SECRET.to_owned()),
                valid_for.map(|v| Utc::now() + ChronoDuration::seconds(v)),
            );
            is_secret_hidden_behind_asterisks(&creds)
        }
    }
}
