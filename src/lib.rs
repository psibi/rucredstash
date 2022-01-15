#![allow(clippy::field_reassign_with_default, clippy::too_many_arguments)]

pub mod crypto;
use base64::{decode, encode, DecodeError};
use bytes::Bytes;
use crypto::Crypto;
use futures::future::join_all;
use hex::FromHexError;
use ring::hmac::{sign, Algorithm, Key};
use rusoto_core::{region::Region, request::TlsError, Client, HttpClient, RusotoError};
use rusoto_credential::{CredentialsError, DefaultCredentialsProvider, ProfileProvider};
use rusoto_dynamodb::{
    AttributeDefinition, AttributeValue, CreateTableError, CreateTableInput, CreateTableOutput,
    DeleteItemError, DeleteItemInput, DeleteItemOutput, DescribeTableError, DescribeTableInput,
    DynamoDb, DynamoDbClient, GetItemError, GetItemInput, KeySchemaElement, ProvisionedThroughput,
    PutItemError, PutItemInput, PutItemOutput, QueryError, QueryInput, QueryOutput, ScanError,
    ScanInput, Tag,
};
use rusoto_kms::{
    DecryptError, DecryptRequest, DecryptResponse, GenerateDataKeyError, GenerateDataKeyRequest,
    GenerateDataKeyResponse, Kms, KmsClient,
};
use rusoto_sts::{StsAssumeRoleSessionCredentialsProvider, StsClient};
use std::collections::HashMap;

const PAD_LEN: usize = 19;

/// CredStash client. This Struct internally handles the KMS and
/// DynamoDB client connections and their credentials. Note that the
/// client will use the default credentials provider and tls client.
pub struct CredStashClient {
    dynamo_client: DynamoDbClient,
    kms_client: KmsClient,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CredStashCredential {
    /// Provides AWS credentials from multiple possible sources using a priority order.
    ///
    /// The following sources are checked in order for credentials when calling `credentials`:
    ///
    /// 1. Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
    /// 2. `credential_process` command in the AWS config file, usually located at `~/.aws/config`.
    /// 3. AWS credentials file. Usually located at `~/.aws/credentials`.
    /// 4. IAM instance profile. Will only work if running on an EC2 instance with an instance profile/role.
    ///
    /// Note that this credential will also automatically refresh the credentials when they expire.
    DefaultCredentialsProvider,
    /// Provides AWS credentials from a profile in a credentials file, or from a credential process.
    DefaultProfile(Option<String>),
    /// Use STS to assume role. The first argument is the ARN of the
    /// role to assume. The second tuple consiste of an optional MFA
    /// hardware device serial number or virtual device ARN and the
    /// associated MFA code.
    DefaultAssumeRole((String, Option<(String, String)>)),
}

/// Represents the Decrypted row for the `credential_name`
#[derive(Debug, Clone)]
pub struct CredstashItem {
    /// HMAC signing key with digest algorithm and the key value
    pub hmac_key: Key,
    /// Credential name which has been stored.
    pub credential_name: String,
    /// Decrypted credential value. This corresponds with the `credential_name`.
    pub credential_value: Vec<u8>,
    /// HMAC Digest of the encrypted text
    pub hmac_digest: Vec<u8>,
    /// Digest algorithm used for computation of HMAC
    pub digest_algorithm: Algorithm,
    /// The version of the `CredstashItem`
    pub version: String,
    /// Optional comment for the `CredstashItem`
    pub comment: Option<String>,
}

/// Represents only the Credential without the decrypted text.
#[derive(Debug, Clone)]
pub struct CredstashKey {
    /// Credential name which has been stored.
    pub name: String,
    /// The version of the `CredstashKey`
    pub version: String,
    /// Optional comment for the `CredstashKey`
    pub comment: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum CredStashClientError {
    NoKeyFound,
    AWSDynamoError(String),
    AWSKMSError(String),
    CredstashDecodeFalure(DecodeError),
    CredstashHexFailure(FromHexError),
    HMacMismatch,
    ParseError(String),
    CredentialsError(String),
    TlsError(String),
    DigestAlgorithmNotSupported(String),
}

fn put_helper(
    query_output: GenerateDataKeyResponse,
    digest_algorithm: Algorithm,
    table_name: String,
    credential_value: String,
    credential_name: String,
    version: Option<u64>,
    comment: Option<String>,
) -> Result<PutItemInput, CredStashClientError> {
    let mut hmac_key: Bytes = match query_output.plaintext {
        None => return Err(CredStashClientError::NoKeyFound),
        Some(val) => val,
    };
    let aes_key = hmac_key.split_to(32); // First 32 bytes will be aes_key, remaining hmac_key
    let hmac_ring_key = Key::new(digest_algorithm, hmac_key.as_ref());
    let crypto_context = Crypto::new();
    let ciphertext =
        crypto_context.aes_encrypt_ctr(credential_value.as_bytes().to_owned(), aes_key); // Encrypted text of value part
    let hmac_ciphertext = sign(&hmac_ring_key, &ciphertext); // HMAC of encrypted text
    let data_key_ciphertext = query_output
        .ciphertext_blob
        .ok_or_else(|| CredStashClientError::AWSKMSError("ciphertext_blob is empty".to_string()))?
        .to_vec();
    let base64_ciphertext = encode(&ciphertext); // Base64 of encrypted text
    let base64_data_key_ciphertext = encode(&data_key_ciphertext); // Encoding of full key encrypted with master key
    let hex_hmac_ciphertext = hex::encode(hmac_ciphertext);

    let mut put_item: PutItemInput = Default::default();
    put_item.table_name = table_name;

    let mut attr_names = HashMap::new();
    attr_names.insert("#n".to_string(), "name".to_string());

    put_item.expression_attribute_names = Some(attr_names);
    put_item.condition_expression = Some("attribute_not_exists(#n)".to_string());

    let mut item = HashMap::new();
    let mut item_name = AttributeValue::default();
    item_name.s = Some(credential_name);
    item.insert("name".to_string(), item_name);
    let mut item_version = AttributeValue::default();
    item_version.s = version.map_or(Some(1), Some).map(pad_integer);
    item.insert("version".to_string(), item_version);
    let mut nitem = comment.map_or(item.clone(), |com| {
        let mut item_comment = AttributeValue::default();
        item_comment.s = Some(com);
        item.insert("comment".to_string(), item_comment);
        item
    });
    let mut item_key = AttributeValue::default();
    item_key.s = Some(base64_data_key_ciphertext);
    nitem.insert("key".to_string(), item_key);
    let mut item_contents = AttributeValue::default();
    item_contents.s = Some(base64_ciphertext);
    nitem.insert("contents".to_string(), item_contents);
    let mut item_hmac = AttributeValue::default();
    item_hmac.b = Some(Bytes::from(hex_hmac_ciphertext));
    nitem.insert("hmac".to_string(), item_hmac);
    let mut item_digest = AttributeValue::default();
    item_digest.s = Some(get_algorithm(digest_algorithm));
    nitem.insert("digest".to_string(), item_digest);
    put_item.item = nitem;
    Ok(put_item)
}

fn get_key(
    decrypt_output: DecryptResponse,
    digest_algorithm: Algorithm,
) -> Result<(Key, Bytes), CredStashClientError> {
    let mut hmac_key: Bytes = match decrypt_output.plaintext {
        None => return Err(CredStashClientError::NoKeyFound),
        Some(val) => val,
    };
    let aes_key: Bytes = hmac_key.split_to(32);
    let hmac_ring_key: Key = Key::new(digest_algorithm, hmac_key.as_ref());
    let result: (Key, Bytes) = (hmac_ring_key, aes_key);
    Ok(result)
}

fn get_version(query_output: QueryOutput) -> Result<u64, CredStashClientError> {
    let dynamo_result = query_output.items.ok_or_else(|| {
        CredStashClientError::AWSDynamoError("items column is missing".to_string())
    })?;
    let item: HashMap<String, AttributeValue> = dynamo_result
        .into_iter()
        .next()
        .ok_or_else(|| CredStashClientError::AWSDynamoError("items is Empty".to_string()))?;
    let dynamo_version: &AttributeValue = item.get("version").ok_or_else(|| {
        CredStashClientError::AWSDynamoError("version column is missing".to_string())
    })?;
    Ok(dynamo_version
        .s
        .as_ref()
        .ok_or_else(|| {
            CredStashClientError::AWSDynamoError("version column value not present".to_string())
        })?
        .to_owned()
        .parse::<u64>()?)
}

fn pad_integer(num: u64) -> String {
    let num_str = num.to_string();
    if num_str.len() >= PAD_LEN {
        num_str
    } else {
        let remaining = PAD_LEN - num_str.len();
        let mut zeros: String = "0".to_string().repeat(remaining);
        zeros.push_str(&num_str);
        zeros
    }
}

#[test]
fn pad_integer_check() {
    assert_eq!(pad_integer(1), "0000000000000000001".to_string());
}

#[test]
fn pad_integer_check_big_num() {
    assert_eq!(pad_integer(123), "0000000000000000123".to_string());
}

fn get_algorithm(algorithm: Algorithm) -> String {
    if algorithm == ring::hmac::HMAC_SHA384 {
        return "SHA384".to_string();
    }
    if algorithm == ring::hmac::HMAC_SHA256 {
        return "SHA256".to_string();
    }
    if algorithm == ring::hmac::HMAC_SHA512 {
        "SHA512".to_string()
    } else {
        "SHA1".to_string()
    }
}

#[test]
fn get_algo512_check() {
    assert_eq!(get_algorithm(ring::hmac::HMAC_SHA512), "SHA512".to_string());
}

#[test]
fn get_algo256_check() {
    assert_eq!(get_algorithm(ring::hmac::HMAC_SHA256), "SHA256".to_string());
}

impl From<std::num::ParseIntError> for CredStashClientError {
    fn from(error: std::num::ParseIntError) -> Self {
        CredStashClientError::ParseError(error.to_string())
    }
}

impl From<TlsError> for CredStashClientError {
    fn from(error: TlsError) -> Self {
        CredStashClientError::TlsError(error.to_string())
    }
}

impl From<RusotoError<DescribeTableError>> for CredStashClientError {
    fn from(error: RusotoError<DescribeTableError>) -> Self {
        CredStashClientError::AWSDynamoError(error.to_string())
    }
}

impl From<RusotoError<GetItemError>> for CredStashClientError {
    fn from(error: RusotoError<GetItemError>) -> Self {
        CredStashClientError::AWSDynamoError(error.to_string())
    }
}

impl From<RusotoError<CreateTableError>> for CredStashClientError {
    fn from(error: RusotoError<CreateTableError>) -> Self {
        CredStashClientError::AWSDynamoError(error.to_string())
    }
}

impl From<RusotoError<GenerateDataKeyError>> for CredStashClientError {
    fn from(error: RusotoError<GenerateDataKeyError>) -> Self {
        CredStashClientError::AWSKMSError(error.to_string())
    }
}

impl From<RusotoError<PutItemError>> for CredStashClientError {
    fn from(error: RusotoError<PutItemError>) -> Self {
        CredStashClientError::AWSDynamoError(error.to_string())
    }
}

impl From<DecodeError> for CredStashClientError {
    fn from(error: DecodeError) -> Self {
        CredStashClientError::CredstashDecodeFalure(error)
    }
}

impl From<FromHexError> for CredStashClientError {
    fn from(error: FromHexError) -> Self {
        CredStashClientError::CredstashHexFailure(error)
    }
}

impl From<RusotoError<DeleteItemError>> for CredStashClientError {
    fn from(error: RusotoError<DeleteItemError>) -> Self {
        CredStashClientError::AWSDynamoError(error.to_string())
    }
}

impl From<RusotoError<QueryError>> for CredStashClientError {
    fn from(error: RusotoError<QueryError>) -> Self {
        CredStashClientError::AWSDynamoError(error.to_string())
    }
}

impl From<RusotoError<ScanError>> for CredStashClientError {
    fn from(error: RusotoError<ScanError>) -> Self {
        CredStashClientError::AWSDynamoError(error.to_string())
    }
}

impl From<RusotoError<DecryptError>> for CredStashClientError {
    fn from(error: RusotoError<DecryptError>) -> Self {
        CredStashClientError::AWSKMSError(error.to_string())
    }
}

impl From<(RusotoError<DecryptError>, Vec<(String, String)>)> for CredStashClientError {
    fn from(error: (RusotoError<DecryptError>, Vec<(String, String)>)) -> Self {
        let enc_context = error.1;
        let msg;
        if !enc_context.is_empty() {
            msg = "Could not decrypt hmac key with KMS. The encryption context provided may not match the one used when the credential was stored.";
        } else {
            msg = "Could not decrypt hmac key with KMS. The credential may require that an encryption context be provided to decrypt it."
        }
        CredStashClientError::AWSKMSError(msg.to_string())
    }
}

impl From<CredentialsError> for CredStashClientError {
    fn from(error: CredentialsError) -> Self {
        CredStashClientError::CredentialsError(error.to_string())
    }
}

impl CredStashClient {
    /// Creates a new client backend. Note that this uses the default
    /// AWS credential provider and the tls client.
    pub fn new(
        credential: CredStashCredential,
        region: Option<Region>,
    ) -> Result<CredStashClient, CredStashClientError> {
        Self::new_from(credential, region)
    }

    fn new_from(
        credential: CredStashCredential,
        region: Option<Region>,
    ) -> Result<CredStashClient, CredStashClientError> {
        let default_region = region.map_or(Region::default(), |item| item);
        let provider = match credential {
            CredStashCredential::DefaultCredentialsProvider => {
                let client =
                    Client::new_with(DefaultCredentialsProvider::new()?, HttpClient::new()?);
                let dynamo_client =
                    DynamoDbClient::new_with_client(client.clone(), default_region.clone());
                let kms_client = KmsClient::new_with_client(client.clone(), default_region);
                (dynamo_client, kms_client)
            }
            CredStashCredential::DefaultAssumeRole((assume_role_arn, mfa_field)) => {
                let sts = StsClient::new_with(
                    HttpClient::new()?,
                    DefaultCredentialsProvider::new()?,
                    default_region.clone(),
                );
                let mfa = mfa_field.clone().map(|(mfa, _)| mfa);
                let mut sts_role_provider = StsAssumeRoleSessionCredentialsProvider::new(
                    sts.clone(),
                    assume_role_arn.clone(),
                    "default".to_owned(),
                    None,
                    None,
                    None,
                    mfa.clone(),
                );
                match mfa_field {
                    None => (),
                    Some((_, code)) => {
                        sts_role_provider.set_mfa_code(code.clone());
                    }
                }
                let client = Client::new_with(sts_role_provider, HttpClient::new()?);
                let dynamo_client =
                    DynamoDbClient::new_with_client(client.clone(), default_region.clone());
                let kms_client = KmsClient::new_with_client(client, default_region);
                (dynamo_client, kms_client)
            }
            CredStashCredential::DefaultProfile(profile) => {
                let mut profile_provider = ProfileProvider::new()?;
                match profile {
                    None => (),
                    Some(pr) => {
                        profile_provider.set_profile(pr);
                    }
                }
                let client = Client::new_with(profile_provider, HttpClient::new()?);
                let dynamo_client =
                    DynamoDbClient::new_with_client(client.clone(), default_region.clone());
                let kms_client = KmsClient::new_with_client(client, default_region);
                (dynamo_client, kms_client)
            }
        };
        let (dynamo_client, kms_client) = provider;
        Ok(CredStashClient {
            dynamo_client,
            kms_client,
        })
    }

    /// Returns all the Credential name stored in the DynamoDB table.
    ///
    /// # Arguments
    ///
    /// * `table_name`: The name of the table from which to list `CredstashKey`
    ///
    pub async fn list_secrets(
        &self,
        table_name: String,
    ) -> Result<Vec<CredstashKey>, CredStashClientError> {
        let mut last_eval_key: Option<HashMap<String, AttributeValue>> = None;
        let mut vec_key = vec![];
        loop {
            let mut scan_query: ScanInput = Default::default();
            scan_query.projection_expression = Some("#n, version, #c".to_string());

            let mut attr_names = HashMap::new();
            attr_names.insert("#n".to_string(), "name".to_string());
            attr_names.insert("#c".to_string(), "comment".to_string());
            scan_query.expression_attribute_names = Some(attr_names);
            scan_query.table_name = table_name.clone();
            if last_eval_key
                .as_ref()
                .map_or(false, |hmap| !hmap.is_empty())
            {
                scan_query.exclusive_start_key = last_eval_key;
            }

            let dynamo_result = self.dynamo_client.scan(scan_query).await?;
            let result_items = dynamo_result.items;
            let mut test_vec: Vec<CredstashKey> = match result_items {
                Some(items) => {
                    let new_vecs: Vec<CredstashKey> = items
                        .into_iter()
                        .map(|elem| self.attribute_to_attribute_item(elem))
                        .filter_map(Result::ok)
                        .collect();
                    new_vecs
                }
                None => vec![],
            };
            vec_key.append(&mut test_vec);
            last_eval_key = dynamo_result.last_evaluated_key;
            if last_eval_key.is_none() {
                break;
            }
        }
        Ok(vec_key)
    }

    fn attribute_to_attribute_item(
        &self,
        item: HashMap<String, AttributeValue>,
    ) -> Result<CredstashKey, CredStashClientError> {
        let dynamo_name = item.get("name").ok_or_else(|| {
            CredStashClientError::AWSDynamoError("name column is missing".to_string())
        })?;
        let dynamo_version: &AttributeValue = item.get("version").ok_or_else(|| {
            CredStashClientError::AWSDynamoError("version column is missing".to_string())
        })?;
        let comment: Option<&AttributeValue> = item.get("comment");

        let name = dynamo_name
            .s
            .as_ref()
            .ok_or_else(|| {
                CredStashClientError::AWSDynamoError("name column value not present".to_string())
            })?
            .to_owned();
        let version = dynamo_version
            .s
            .as_ref()
            .ok_or_else(|| {
                CredStashClientError::AWSDynamoError("version column value not present".to_string())
            })?
            .to_owned();
        let comment: Option<String> = match comment.map(|item| item.s.as_ref()) {
            None => None,
            Some(None) => None,
            Some(Some(c)) => Some(c.to_string()),
        };
        Ok(CredstashKey {
            name,
            version,
            comment,
        })
    }

    /// Inserts new credential in the DynamoDB table. This is same as
    /// `put_secret` but it also increments the version of the
    /// credential_name automatically.
    ///
    /// # Arguments
    ///
    /// * `table_name`: Name of the DynamoDB table against which the API operates.
    /// * `credential_name`: Credential name to store.
    /// * `credential_value`: Credential secret value which has to be
    /// encrypted and stored securely.

    /// * `key_id`: The unique identifier for the customer master key
    /// (CMK) for which to cancel deletion.
    ///  Specify the key ID or the Amazon Resource Name (ARN) of the CMK. <p>For example:</p> <ul> <li> <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code> </p> </li> <li> <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code> </p> </li> </ul> <p>To get the key ID and key ARN for a CMK, use <a>ListKeys</a> or <a>DescribeKey</a>.</p>
    /// * `encryption_context`: Name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the <code>Decrypt</code> API or decryption will fail. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context">Encryption Context</a>.
    /// * `comment`: Optional comment to specify for the credential.
    /// * `digest_algorithm`: The digest algorithm that should be used
    /// for computing the HMAC of the encrypted text.
    pub async fn put_secret_auto_version(
        &self,
        table_name: String,
        credential_name: String,
        credential_value: String,
        key_id: Option<String>,
        encryption_context: Vec<(String, String)>,
        comment: Option<String>,
        digest_algorithm: Algorithm,
    ) -> Result<PutItemOutput, CredStashClientError> {
        let highest_version = self
            .get_highest_version(table_name.clone(), credential_name.clone())
            .await;
        let result = match highest_version {
            Err(_err) => self.put_secret(
                table_name.clone(),
                credential_name.clone(),
                credential_value.clone(),
                key_id.clone(),
                encryption_context.clone(),
                None,
                comment.clone(),
                digest_algorithm,
            ),
            Ok(version) => self.put_secret(
                table_name,
                credential_name,
                credential_value,
                key_id,
                encryption_context,
                Some(version + 1),
                comment,
                digest_algorithm,
            ),
        };
        result.await
    }

    /// Get the latest version of the credential in the DynamoDB table.
    /// credential_name automatically.
    ///
    /// # Arguments
    ///
    /// * `table_name`: Name of the DynamoDB table against which the API operates.
    /// * `credential_name`: Credential name to store.
    pub async fn get_highest_version(
        &self,
        table_name: String,
        credential_name: String,
    ) -> Result<u64, CredStashClientError> {
        let mut query: QueryInput = Default::default();
        query.scan_index_forward = Some(false);
        query.limit = Some(1);
        query.consistent_read = Some(true);
        let cond: String = "#n = :nameValue".to_string();
        query.key_condition_expression = Some(cond);

        let mut attr_names = HashMap::new();
        attr_names.insert("#n".to_string(), "name".to_string());
        query.expression_attribute_names = Some(attr_names);

        let mut str_attr: AttributeValue = AttributeValue::default();
        str_attr.s = Some(credential_name);

        let mut attr_values = HashMap::new();
        attr_values.insert(":nameValue".to_string(), str_attr);
        query.expression_attribute_values = Some(attr_values);
        query.table_name = table_name;

        query.projection_expression = Some("version".to_string());
        let dynamo_result = self.dynamo_client.query(query).await?;
        get_version(dynamo_result)
    }

    async fn get_items(
        &self,
        table_name: String,
        credential: String,
    ) -> Result<Vec<HashMap<String, AttributeValue>>, CredStashClientError> {
        let mut last_eval_key: Option<HashMap<String, AttributeValue>> = None;
        let mut vec_key = vec![];
        loop {
            let mut query: QueryInput = Default::default();
            let cond: String = "#n = :nameValue".to_string();
            query.key_condition_expression = Some(cond);

            let mut attr_names = HashMap::new();
            attr_names.insert("#n".to_string(), "name".to_string());
            query.expression_attribute_names = Some(attr_names);

            query.projection_expression = Some("#n, version".to_string());

            let mut str_attr: AttributeValue = AttributeValue::default();
            str_attr.s = Some(credential.clone());

            let mut attr_values = HashMap::new();
            attr_values.insert(":nameValue".to_string(), str_attr);
            query.expression_attribute_values = Some(attr_values);
            query.table_name = table_name.clone();
            if last_eval_key
                .as_ref()
                .map_or(false, |hmap| !hmap.is_empty())
            {
                query.exclusive_start_key = last_eval_key;
            }
            let dynamo_result = self.dynamo_client.query(query).await?;
            let mut test_vec = match dynamo_result.items {
                Some(items) => items,
                None => vec![],
            };
            vec_key.append(&mut test_vec);
            last_eval_key = dynamo_result.last_evaluated_key;
            if last_eval_key.is_none() {
                break;
            }
        }
        Ok(vec_key)
    }

    /// Delete the credential from the DynamoDB table.
    ///
    /// # Arguments
    ///
    /// * `table_name`: Name of the DynamoDB table against which the API operates.
    /// * `credential_name`: Credential name to store.
    ///
    pub async fn delete_secret<'a>(
        &self,
        table_name: String,
        credential_name: String,
    ) -> Result<Vec<DeleteItemOutput>, CredStashClientError> {
        let result = self.get_items(table_name.clone(), credential_name).await?;
        let mut del_query: DeleteItemInput = Default::default();
        del_query.table_name = table_name;
        del_query.return_values = Some("ALL_OLD".to_string());
        let items: Vec<Result<DeleteItemOutput, RusotoError<DeleteItemError>>> =
            join_all(result.into_iter().map(|item| {
                let mut delq = del_query.clone();
                delq.key = item;
                self.dynamo_client.delete_item(delq)
            }))
            .await;
        let result: Result<Vec<_>, RusotoError<_>> = items.into_iter().collect();
        Ok(result?)
    }

    /// Inserts new credential in the DynamoDB table.
    ///
    /// # Arguments
    ///
    /// * `table_name`: Name of the DynamoDB table against which the API operates.
    /// * `credential_name`: Credential name to store.
    /// * `credential_value`: Credential secret value which has to be
    /// encrypted and stored securely.

    /// * `key_id`: The unique identifier for the customer master key
    /// (CMK) for which to cancel deletion.
    ///  Specify the key ID or the Amazon Resource Name (ARN) of the CMK. <p>For example:</p> <ul> <li> <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code> </p> </li> <li> <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code> </p> </li> </ul> <p>To get the key ID and key ARN for a CMK, use <a>ListKeys</a> or <a>DescribeKey</a>.</p>
    /// * `encryption_context`: Name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the <code>Decrypt</code> API or decryption will fail. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context">Encryption Context</a>.
    /// * `comment`: Optional comment to specify for the credential.
    /// * `digest_algorithm`: The digest algorithm that should be used
    /// for computing the HMAC of the encrypted text.
    pub async fn put_secret(
        &self,
        table_name: String,
        credential_name: String,
        credential_value: String,
        key_id: Option<String>,
        encryption_context: Vec<(String, String)>,
        version: Option<u64>,
        comment: Option<String>,
        digest_algorithm: Algorithm,
    ) -> Result<PutItemOutput, CredStashClientError> {
        let result = self
            .generate_key_via_kms(64, encryption_context, key_id)
            .await?;
        let put_result = put_helper(
            result,
            digest_algorithm,
            table_name,
            credential_value,
            credential_name,
            version,
            comment,
        )?;
        let dynamo_result = self.dynamo_client.put_item(put_result).await?;
        Ok(dynamo_result)
    }

    /// Creates the necessary table for the credential to be stored in
    /// future. Note that this API is an asynchronous operatio. Upon
    /// receiving a CreateTable request, DynamoDB immediately returns
    /// a response with a TableStatus of CREATING. After the table is
    /// created, DynamoDB sets the TableStatus to ACTIVE. You can
    /// perform read and write operations only on an ACTIVE table.
    /// # Arguments
    ///
    /// * `table_name`: Name of the DynamoDB table against which the API operates.
    /// * `tags`: Tags to associate with the table.
    ///
    pub async fn create_db_table(
        &self,
        table_name: String,
        tags: Vec<(String, String)>,
    ) -> Result<CreateTableOutput, CredStashClientError> {
        let mut query: DescribeTableInput = Default::default();
        query.table_name = table_name.clone();
        let table_result = self.dynamo_client.describe_table(query).await;
        let table_status: Result<(), CredStashClientError> = match table_result {
            Ok(value) => {
                if value.table.is_some() {
                    Err(CredStashClientError::AWSDynamoError(
                        "table already exists".to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
            Err(RusotoError::Service(DescribeTableError::ResourceNotFound(_))) => Ok(()),
            Err(err) => Err(CredStashClientError::AWSDynamoError(err.to_string())),
        };

        table_status?;

        let mut create_query: CreateTableInput = Default::default();
        create_query.table_name = table_name;

        let mut name_attribute: KeySchemaElement = Default::default();
        name_attribute.attribute_name = "name".to_string();
        name_attribute.key_type = "HASH".to_string();
        let mut version_attribute: KeySchemaElement = Default::default();
        version_attribute.attribute_name = "version".to_string();
        version_attribute.key_type = "RANGE".to_string();
        create_query.key_schema = vec![name_attribute, version_attribute];

        let mut name_definition: AttributeDefinition = Default::default();
        name_definition.attribute_name = "name".to_string();
        name_definition.attribute_type = "S".to_string();
        let mut version_definition: AttributeDefinition = Default::default();
        version_definition.attribute_name = "version".to_string();
        version_definition.attribute_type = "S".to_string();
        create_query.attribute_definitions = vec![name_definition, version_definition];

        let mut throughput: ProvisionedThroughput = Default::default();
        throughput.read_capacity_units = 1;
        throughput.write_capacity_units = 1;
        create_query.provisioned_throughput = Some(throughput);

        let table_tags: Vec<Tag> = tags
            .into_iter()
            .map(|(name, value)| {
                let mut tag: Tag = Default::default();
                tag.key = name;
                tag.value = value;
                tag
            })
            .collect();

        create_query.tags = if !table_tags.is_empty() {
            Some(table_tags)
        } else {
            None
        };
        let result = self.dynamo_client.create_table(create_query).await?;
        Ok(result)
    }

    /// Get all the secrets present in the DynamoDB table.
    ///
    /// # Arguments
    ///
    /// * `table_name`: Name of the DynamoDB table against which the API operates.
    /// * `encryption_context`: Name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the <code>Decrypt</code> API or decryption will fail. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context">Encryption Context</a>.
    /// * `version`: The version of the credential which has to be
    /// retrieved. By default, it will retrieve the latest version.
    pub async fn get_all_secrets(
        &self,
        table_name: String,
        encryption_context: Vec<(String, String)>,
        version: Option<u64>,
    ) -> Result<Vec<CredstashItem>, CredStashClientError> {
        let credstash_keys: Vec<CredstashKey> = self.list_secrets(table_name.clone()).await?;
        let items = join_all(credstash_keys.into_iter().map(|item| {
            self.get_secret(
                table_name.clone(),
                item.name,
                encryption_context.clone(),
                version,
            )
        }));
        let result: Vec<Result<CredstashItem, CredStashClientError>> = items.await;
        let credstash_items: Result<Vec<CredstashItem>, CredStashClientError> =
            result.into_iter().collect();
        Ok(credstash_items?)
    }

    async fn to_dynamo_result(
        &self,
        query_output: Option<Vec<HashMap<String, AttributeValue>>>,
        encryption_context: Vec<(String, String)>,
    ) -> Result<CredstashItem, CredStashClientError> {
        let dynamo_result: Vec<_> = query_output.ok_or_else(|| {
            CredStashClientError::AWSDynamoError("items column is missing".to_string())
        })?;
        let item: HashMap<String, AttributeValue> = dynamo_result
            .into_iter()
            .next()
            .ok_or_else(|| CredStashClientError::AWSDynamoError("items is Empty".to_string()))?;
        let dynamo_key: &AttributeValue = item.get("key").ok_or_else(|| {
            CredStashClientError::AWSDynamoError("key column is missing".to_string())
        })?;
        let dynamo_contents: &AttributeValue = item.get("contents").ok_or_else(|| {
            CredStashClientError::AWSDynamoError("key column is missing".to_string())
        })?;
        let dynamo_hmac: &AttributeValue = item.get("hmac").ok_or_else(|| {
            CredStashClientError::AWSDynamoError("hmac column is missing".to_string())
        })?;
        let dynamo_version: &AttributeValue = item.get("version").ok_or_else(|| {
            CredStashClientError::AWSDynamoError("version column is missing".to_string())
        })?;
        let dynamo_digest: &AttributeValue = item.get("digest").ok_or_else(|| {
            CredStashClientError::AWSDynamoError("digest column is missing".to_string())
        })?;
        let key: &String = dynamo_key.s.as_ref().ok_or_else(|| {
            CredStashClientError::AWSDynamoError("key column value not present".to_string())
        })?;
        let item_contents = decode(dynamo_contents.s.as_ref().ok_or_else(|| {
            CredStashClientError::AWSDynamoError("contents column value not present".to_string())
        })?)?;
        let item_hmac = dynamo_hmac
            .b
            .as_ref()
            .map(hex::decode)
            .or_else(|| dynamo_hmac.s.as_ref().map(hex::decode))
            .ok_or_else(|| {
                CredStashClientError::AWSDynamoError("hmac column value not present".to_string())
            })??;
        let dynamo_name = item.get("name").ok_or_else(|| {
            CredStashClientError::AWSDynamoError("name column is missing".to_string())
        })?;
        let decoded_key: Vec<u8> = decode(key)?;
        let algorithm = dynamo_digest
            .s
            .as_ref()
            .to_owned()
            .map_or(Ok(ring::hmac::HMAC_SHA256), |item| {
                to_algorithm(item.to_owned())
            })?;
        let (hmac_key, aes_key) = self
            .decrypt_via_kms(algorithm, decoded_key, encryption_context)
            .await?;
        let crypto_context = Crypto::new();
        let verified = Crypto::verify_ciphertext_integrity(&hmac_key, &item_contents, &item_hmac);
        if !verified {
            return Err(CredStashClientError::HMacMismatch);
        }
        let contents = crypto_context.aes_decrypt_ctr(item_contents, aes_key);
        Ok(CredstashItem {
            hmac_key,
            credential_value: contents,
            hmac_digest: item_hmac,
            digest_algorithm: algorithm,
            version: dynamo_version
                .s
                .as_ref()
                .ok_or_else(|| {
                    CredStashClientError::AWSDynamoError(
                        "version column value not present".to_string(),
                    )
                })?
                .to_owned(),
            comment: None,
            credential_name: dynamo_name
                .s
                .as_ref()
                .ok_or_else(|| {
                    CredStashClientError::AWSDynamoError(
                        "digest column value not present".to_string(),
                    )
                })?
                .to_owned(),
        })
    }

    /// Get a specific secret present in the DynamoDB table.
    ///
    /// # Arguments
    ///
    /// * `table_name`: Name of the DynamoDB table against which the API operates.
    /// * `credential_name`: Credential name which has to be retrieved.
    /// * `encryption_context`: Name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the <code>Decrypt</code> API or decryption will fail. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context">Encryption Context</a>.
    /// * `version`: The version of the credential which has to be
    /// retrieved. By default, it will retrieve the latest version.
    pub async fn get_secret(
        &self,
        table_name: String,
        credential_name: String,
        encryption_context: Vec<(String, String)>,
        version: Option<u64>,
    ) -> Result<CredstashItem, CredStashClientError> {
        let mut query: QueryInput = Default::default();
        query.scan_index_forward = Some(false);
        query.limit = Some(1);
        query.consistent_read = Some(true);
        let cond: String = "#n = :nameValue".to_string();
        query.key_condition_expression = Some(cond);

        let mut attr_names = HashMap::new();
        attr_names.insert("#n".to_string(), "name".to_string());
        query.expression_attribute_names = Some(attr_names.clone());

        let mut str_attr: AttributeValue = AttributeValue::default();
        str_attr.s = Some(credential_name.clone());

        let mut attr_values = HashMap::new();
        attr_values.insert(":nameValue".to_string(), str_attr);
        query.expression_attribute_values = Some(attr_values.clone());
        query.table_name = table_name.clone();

        let item = match version {
            None => {
                let dynamo_result = self.dynamo_client.query(query).await?;
                self.to_dynamo_result(dynamo_result.items, encryption_context)
                    .await?
            }
            Some(ver) => {
                let mut get_item_input: GetItemInput = Default::default();
                get_item_input.table_name = table_name;
                let mut key = HashMap::new();
                let mut name_attr = AttributeValue::default();
                name_attr.s = Some(credential_name);
                let mut version_attr = AttributeValue::default();
                version_attr.s = Some(pad_integer(ver));
                key.insert("name".to_string(), name_attr);
                key.insert("version".to_string(), version_attr);
                get_item_input.key = key;
                let dynamo_result = self.dynamo_client.get_item(get_item_input).await?;
                let result = dynamo_result.item.map(|item| vec![item]);
                self.to_dynamo_result(result, encryption_context).await?
            }
        };
        Ok(item)
    }

    async fn generate_key_via_kms(
        &self,
        number_of_bytes: i64,
        encryption_context: Vec<(String, String)>,
        key_id: Option<String>,
    ) -> Result<GenerateDataKeyResponse, RusotoError<GenerateDataKeyError>> {
        let mut query: GenerateDataKeyRequest = Default::default();
        query.key_id = key_id.map_or("alias/credstash".to_string(), |item| item);
        query.number_of_bytes = Some(number_of_bytes);
        let mut hash_map = HashMap::new();
        if !encryption_context.is_empty() {
            for (context_key, context_value) in encryption_context {
                hash_map.insert(context_key, context_value);
            }
            query.encryption_context = Some(hash_map);
        }
        self.kms_client.generate_data_key(query).await
    }

    async fn decrypt_via_kms(
        &self,
        digest_algorithm: Algorithm,
        cipher: Vec<u8>,
        encryption_context: Vec<(String, String)>,
    ) -> Result<(Key, Bytes), CredStashClientError> {
        let mut query: DecryptRequest = Default::default();
        let mut context = HashMap::new();
        query.ciphertext_blob = Bytes::from(cipher);
        for (c1, c2) in encryption_context.clone() {
            context.insert(c1, c2);
        }
        if encryption_context.is_empty() {
            query.encryption_context = None;
        } else {
            query.encryption_context = Some(context);
        }
        let kms_result = self.kms_client.decrypt(query).await?;
        let result = get_key(kms_result, digest_algorithm)?;
        Ok(result)
    }
}

fn to_algorithm(digest: String) -> Result<Algorithm, CredStashClientError> {
    match digest.as_ref() {
        "SHA1" => Ok(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
        "SHA256" => Ok(ring::hmac::HMAC_SHA256),
        "SHA384" => Ok(ring::hmac::HMAC_SHA384),
        "SHA512" => Ok(ring::hmac::HMAC_SHA512),
        _ => Err(CredStashClientError::DigestAlgorithmNotSupported(format!(
            "Unsupported digest algorithm: {}",
            digest
        ))),
    }
}
