#![doc(
    html_logo_url = "https://raw.githubusercontent.com/rusoto/rusoto/master/assets/logo-square.png"
)]
#![cfg_attr(feature = "nightly-testing", feature(plugin))]
#![cfg_attr(not(feature = "unstable"), deny(warnings))]
#![deny(missing_docs)]

//! Types for loading and managing AWS access credentials for API requests.

pub use crate::container::ContainerProvider;
pub use crate::environment::EnvironmentProvider;
pub use crate::instance_metadata::InstanceMetadataProvider;
pub use crate::profile::ProfileProvider;
pub use crate::secrets::Secret;
pub use crate::static_provider::StaticProvider;
pub use crate::variable::Variable;

pub mod claims;
mod container;
mod environment;
mod instance_metadata;
mod profile;
mod request;
mod secrets;
mod static_provider;
#[cfg(test)]
pub(crate) mod test_utils;
mod variable;

use async_trait::async_trait;
use std::env::var as env_var;
use std::time::Duration;

pub use rusoto_credential_core::{AwsCredentials, CredentialsError, ProvideAwsCredentials, AutoRefreshingProvider};

/// Wraps a `ChainProvider` in an `AutoRefreshingProvider`.
///
/// The underlying `ChainProvider` checks multiple sources for credentials, and the `AutoRefreshingProvider`
/// refreshes the credentials automatically when they expire.
///
/// # Warning
///
/// This provider allows the [`credential_process`][credential_process] option in the AWS config
/// file (`~/.aws/config`), a method of sourcing credentials from an external process. This can
/// potentially be dangerous, so proceed with caution. Other credential providers should be
/// preferred if at all possible. If using this option, you should make sure that the config file
/// is as locked down as possible using security best practices for your operating system.
///
/// [credential_process]: https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
#[derive(Clone)]
pub struct DefaultCredentialsProvider(AutoRefreshingProvider<ChainProvider>);

impl DefaultCredentialsProvider {
    /// Creates a new thread-safe `DefaultCredentialsProvider`.
    pub fn new() -> Result<DefaultCredentialsProvider, CredentialsError> {
        let inner = AutoRefreshingProvider::new(ChainProvider::new())?;
        Ok(DefaultCredentialsProvider(inner))
    }
}

#[async_trait]
impl ProvideAwsCredentials for DefaultCredentialsProvider {
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        self.0.credentials().await
    }
}

/// Provides AWS credentials from multiple possible sources using a priority order.
///
/// The following sources are checked in order for credentials when calling `credentials`:
///
/// 1. Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
/// 2. `credential_process` command in the AWS config file, usually located at `~/.aws/config`.
/// 3. AWS credentials file. Usually located at `~/.aws/credentials`.
/// 4. IAM instance profile. Will only work if running on an EC2 instance with an instance profile/role.
///
/// If the sources are exhausted without finding credentials, an error is returned.
///
/// The provider has a default timeout of 30 seconds. While it should work well for most setups,
/// you can change the timeout using the `set_timeout` method.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
///
/// use rusoto_credential::ChainProvider;
///
/// let mut provider = ChainProvider::new();
/// // you can overwrite the default timeout like this:
/// provider.set_timeout(Duration::from_secs(60));
/// ```
///
/// # Warning
///
/// This provider allows the [`credential_process`][credential_process] option in the AWS config
/// file (`~/.aws/config`), a method of sourcing credentials from an external process. This can
/// potentially be dangerous, so proceed with caution. Other credential providers should be
/// preferred if at all possible. If using this option, you should make sure that the config file
/// is as locked down as possible using security best practices for your operating system.
///
/// [credential_process]: https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
#[derive(Debug, Clone)]
pub struct ChainProvider {
    environment_provider: EnvironmentProvider,
    instance_metadata_provider: InstanceMetadataProvider,
    container_provider: ContainerProvider,
    profile_provider: Option<ProfileProvider>,
}

impl ChainProvider {
    /// Set the timeout on the provider to the specified duration.
    pub fn set_timeout(&mut self, duration: Duration) {
        self.instance_metadata_provider.set_timeout(duration);
        self.container_provider.set_timeout(duration);
    }
}

async fn chain_provider_credentials(
    provider: ChainProvider,
) -> Result<AwsCredentials, CredentialsError> {
    if let Ok(creds) = provider.environment_provider.credentials().await {
        return Ok(creds);
    }
    if let Some(ref profile_provider) = provider.profile_provider {
        if let Ok(creds) = profile_provider.credentials().await {
            return Ok(creds);
        }
    }
    if let Ok(creds) = provider.container_provider.credentials().await {
        return Ok(creds);
    }
    if let Ok(creds) = provider.instance_metadata_provider.credentials().await {
        return Ok(creds);
    }
    Err(CredentialsError::new(
        "Couldn't find AWS credentials in environment, credentials file, or IAM role.",
    ))
}

#[async_trait]
impl ProvideAwsCredentials for ChainProvider {
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        chain_provider_credentials(self.clone()).await
    }
}

impl ChainProvider {
    /// Create a new `ChainProvider` using a `ProfileProvider` with the default settings.
    pub fn new() -> ChainProvider {
        ChainProvider {
            environment_provider: EnvironmentProvider::default(),
            profile_provider: ProfileProvider::new().ok(),
            instance_metadata_provider: InstanceMetadataProvider::new(),
            container_provider: ContainerProvider::new(),
        }
    }

    /// Create a new `ChainProvider` using the provided `ProfileProvider`.
    pub fn with_profile_provider(profile_provider: ProfileProvider) -> ChainProvider {
        ChainProvider {
            environment_provider: EnvironmentProvider::default(),
            profile_provider: Some(profile_provider),
            instance_metadata_provider: InstanceMetadataProvider::new(),
            container_provider: ContainerProvider::new(),
        }
    }
}

impl Default for ChainProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// This is a helper function as Option<T>::filter is not yet stable (see issue #45860).
/// <https://github.com/rust-lang/rfcs/issues/2036> also affects the implementation of this.
fn non_empty_env_var(name: &str) -> Option<String> {
    match env_var(name) {
        Ok(value) => {
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        }
        Err(_) => None,
    }
}

/// Parses the response from an AWS Metadata Service, either from an IAM Role, or a Container.
fn parse_credentials_from_aws_service(response: &str) -> Result<AwsCredentials, CredentialsError> {
    Ok(serde_json::from_str::<AwsCredentials>(response)?)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::Read;
    use std::path::Path;

    use crate::test_utils::{is_secret_hidden_behind_asterisks, lock_env, SECRET};
    use quickcheck::quickcheck;
    use chrono::{DateTime, Duration as ChronoDuration, Utc};

    use super::*;


    #[test]
    fn providers_are_send_and_sync() {
        fn is_send_and_sync<T: Send + Sync>() {}

        is_send_and_sync::<ChainProvider>();
        is_send_and_sync::<AutoRefreshingProvider<ChainProvider>>();
        is_send_and_sync::<DefaultCredentialsProvider>();
    }

    #[tokio::test]
    async fn profile_provider_finds_right_credentials_in_file() {
        let _guard = lock_env();
        let profile_provider = ProfileProvider::with_configuration(
            "tests/sample-data/multiple_profile_credentials",
            "foo",
        );

        let credentials = profile_provider.credentials().await.expect(
            "Failed to get credentials from profile provider using tests/sample-data/multiple_profile_credentials",
        );

        assert_eq!(credentials.aws_access_key_id(), "foo_access_key");
        assert_eq!(credentials.aws_secret_access_key(), "foo_secret_key");
    }

    #[test]
    fn parse_iam_task_credentials_sample_response() {
        fn read_file_to_string(file_path: &Path) -> String {
            match fs::metadata(file_path) {
                Ok(metadata) => {
                    if !metadata.is_file() {
                        panic!("Couldn't open file");
                    }
                }
                Err(_) => panic!("Couldn't stat file"),
            };

            let mut file = File::open(file_path).unwrap();
            let mut result = String::new();
            file.read_to_string(&mut result).ok();

            result
        }

        let response = read_file_to_string(Path::new(
            "tests/sample-data/iam_task_credentials_sample_response",
        ));

        let credentials = parse_credentials_from_aws_service(&response);

        assert!(credentials.is_ok());
        let credentials = credentials.unwrap();

        assert_eq!(credentials.aws_access_key_id(), "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            credentials.aws_secret_access_key(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert!(credentials.token().is_some());

        assert_eq!(
            credentials.expires_at().expect(""),
            DateTime::parse_from_rfc3339("2016-11-18T01:50:39Z").expect("")
        );
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
