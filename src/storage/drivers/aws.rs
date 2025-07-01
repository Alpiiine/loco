use opendal::{services::S3, Operator};

use super::{opendal_adapter::OpendalAdapter, StoreDriver};
use crate::storage::StorageResult;

/// A set of AWS security credentials
#[derive(Debug)]
pub struct Credential {
    /// `AWS_ACCESS_KEY_ID`
    pub key_id: String,
    /// `AWS_SECRET_ACCESS_KEY`
    pub secret_key: String,
    /// `AWS_SESSION_TOKEN`
    pub token: Option<String>,
}

/// Create new AWS s3 storage with bucket and region.
///
/// # Examples
///```
/// use loco_rs::storage::drivers::aws;
/// let aws_driver = aws::new("bucket_name", "region");
/// ```
///
/// # Errors
///
/// When could not initialize the client instance
pub fn new(bucket_name: &str, region: &str) -> StorageResult<Box<dyn StoreDriver>> {
    let s3 = S3::default().bucket(bucket_name).region(region);

    Ok(Box::new(OpendalAdapter::new(Operator::new(s3)?.finish())))
}

/// Create new AWS s3 storage with bucket, region and credentials.
///
/// # Examples
///```
/// use loco_rs::storage::drivers::aws;
/// let credential = aws::Credential {
///    key_id: "".to_string(),
///    secret_key: "".to_string(),
///    token: None
/// };
/// let aws_driver = aws::with_credentials("bucket_name", "region", credential);
/// ```
///
/// # Errors
///
/// When could not initialize the client instance
pub fn with_credentials(
    bucket_name: &str,
    region: &str,
    credentials: Credential,
) -> StorageResult<Box<dyn StoreDriver>> {
    let mut s3 = S3::default()
        .bucket(bucket_name)
        .region(region)
        .access_key_id(&credentials.key_id)
        .secret_access_key(&credentials.secret_key);
    if let Some(token) = credentials.token {
        s3 = s3.session_token(&token);
    }
    Ok(Box::new(OpendalAdapter::new(Operator::new(s3)?.finish())))
}

/// Build store with failure
///
/// # Panics
///
/// Panics if cannot build store
#[cfg(test)]
#[must_use]
pub fn with_failure() -> Box<dyn StoreDriver> {
    let s3 = S3::default()
        .bucket("loco-test")
        .region("ap-south-1")
        .allow_anonymous()
        .disable_ec2_metadata();

    Box::new(OpendalAdapter::new(Operator::new(s3).unwrap().finish()))
}

/// Create new S3-compatible storage with a custom endpoint.
///
/// This helper can be used to connect to AWS-compatible object stores (Cloudflare R2, MinIO,
/// Wasabi, DigitalOcean Spaces, etc.) that expose an S3 API but require a dedicated endpoint.
///
/// # Examples
/// ```
/// use loco_rs::storage::drivers::aws;
/// let driver = aws::new_with_endpoint("bucket", "auto", "https://<ACCOUNT_ID>.r2.cloudflarestorage.com");
/// ```
///
/// # Errors
/// Returns an error if the underlying [`Operator`] cannot be initialised.
pub fn new_with_endpoint(
    bucket_name: &str,
    region: &str,
    endpoint: &str,
) -> StorageResult<Box<dyn StoreDriver>> {
    let s3 = S3::default()
        .bucket(bucket_name)
        .region(region)
        .endpoint(endpoint);

    Ok(Box::new(OpendalAdapter::new(Operator::new(s3)?.finish())))
}

/// Create new S3-compatible storage with custom endpoint **and** credentials.
///
/// # Examples
/// ```
/// use loco_rs::storage::drivers::aws;
/// let credential = aws::Credential {
///     key_id: "AKIA".to_string(),
///     secret_key: "SECRET".to_string(),
///     token: None,
/// };
/// let driver = aws::with_credentials_and_endpoint(
///     "bucket",
///     "auto",
///     "https://<ACCOUNT_ID>.r2.cloudflarestorage.com",
///     credential,
/// );
/// ```
///
/// # Errors
/// Returns an error if the underlying [`Operator`] cannot be initialised.
pub fn with_credentials_and_endpoint(
    bucket_name: &str,
    region: &str,
    endpoint: &str,
    credentials: Credential,
) -> StorageResult<Box<dyn StoreDriver>> {
    let mut s3 = S3::default()
        .bucket(bucket_name)
        .region(region)
        .endpoint(endpoint)
        .access_key_id(&credentials.key_id)
        .secret_access_key(&credentials.secret_key);

    if let Some(token) = credentials.token {
        s3 = s3.session_token(&token);
    }

    Ok(Box::new(OpendalAdapter::new(Operator::new(s3)?.finish())))
}
