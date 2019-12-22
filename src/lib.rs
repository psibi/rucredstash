extern crate base64;
extern crate futures;
extern crate hex;
extern crate rusoto_core;
extern crate rusoto_dynamodb;
extern crate rusoto_credential;
extern crate tokio_core;
extern crate rusoto_sts;

use rusoto_sts::{StsAssumeRoleSessionCredentialsProvider, StsClient};
use base64::{decode, encode, DecodeError};
use rusoto_credential::DefaultCredentialsProvider;
use bytes::Bytes;
use core::convert::From;
mod crypto;
pub use crate::crypto::credstash_crypto::Crypto;
use futures::future;
use futures::future::Future;
use futures::future::IntoFuture;
use futures::future::*;
use hex::FromHexError;
use ring;
use ring::hmac::{sign, Algorithm, Key};
use rusoto_core::region::Region;
use rusoto_core::RusotoError;
use rusoto_dynamodb::{
    AttributeDefinition, AttributeValue, CreateTableError, CreateTableInput, CreateTableOutput,
    DeleteItemError, DeleteItemInput, DeleteItemOutput, DescribeTableError, DescribeTableInput,
    DynamoDb, DynamoDbClient, GetItemError, GetItemInput, KeySchemaElement, ProvisionedThroughput,
    PutItemError, PutItemInput, PutItemOutput, QueryError, QueryInput, QueryOutput, ScanError,
    ScanInput, Tag,
};
use rusoto_kms::DecryptRequest;
use rusoto_kms::{
    DecryptError, DecryptResponse, GenerateDataKeyError, GenerateDataKeyRequest,
    GenerateDataKeyResponse, Kms, KmsClient,
};
use std::clone::Clone;
use std::collections::HashMap;
use std::iter::Iterator;
use std::result::Result;
use std::string::String;
use std::vec::Vec;

const PAD_LEN: usize = 19;

pub fn create_credential(iam_arn: Option<String>) -> AWSCredential{
    match iam_arn {
        Some(arn) => {
            // fix region
        let sts = StsClient::new(Region::EuWest1);
            let provider = StsAssumeRoleSessionCredentialsProvider::new(
                sts,
                arn,
                "default".to_owned(),
                None, None, None, None
            );
            AWSCredential::Sts(provider)
        }
        None => {
            let default_provider = DefaultCredentialsProvider::new();
            match default_provider {
                Ok(credential) => AWSCredential::Default(credential),
                Err(err) => panic!("Credential sourcing failed: {}", err)
            }
        }
    }
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
    let aes_key = hmac_key.split_to(32);
    let hmac_ring_key = Key::new(digest_algorithm, hmac_key.as_ref());
    let crypto_context = Crypto::new();
    let aes_enc = crypto_context.aes_encrypt_ctr(credential_value.as_bytes().to_owned(), aes_key); // Encrypted text of value part
    let hmac_en = sign(&hmac_ring_key, &aes_enc); // HMAC of encrypted text
    let ciphertext_blob = query_output
        .ciphertext_blob
        .ok_or(CredStashClientError::AWSKMSError(
            "ciphertext_blob is empty".to_string(),
        ))?
        .to_vec();
    let base64_aes_enc = encode(&aes_enc); // Base64 of encrypted text
    let base64_cipher_blob = encode(&ciphertext_blob); // Encoding of full key encrypted with master key
    let hex_hmac = hex::encode(hmac_en);
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
    item_version.s = version
        .map_or(Some(1), |ver| Some(ver))
        .map(|elem| pad_integer(elem));
    item.insert("version".to_string(), item_version);
    let mut nitem = comment.map_or(item.clone(), |com| {
        let mut item_comment = AttributeValue::default();
        item_comment.s = Some(com);
        item.insert("comment".to_string(), item_comment);
        item
    });
    let mut item_key = AttributeValue::default();
    item_key.s = Some(base64_cipher_blob);
    nitem.insert("key".to_string(), item_key);
    let mut item_contents = AttributeValue::default();
    item_contents.s = Some(base64_aes_enc);
    nitem.insert("contents".to_string(), item_contents);
    let mut item_hmac = AttributeValue::default();
    item_hmac.b = Some(Bytes::from(hex_hmac));
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
    let dynamo_result = query_output
        .items
        .ok_or(CredStashClientError::AWSDynamoError(
            "items column is missing".to_string(),
        ))?;
    let item: HashMap<String, AttributeValue> =
        dynamo_result
            .into_iter()
            .nth(0)
            .ok_or(CredStashClientError::AWSDynamoError(
                "items is Empty".to_string(),
            ))?;
    let dynamo_version: &AttributeValue =
        item.get("version")
            .ok_or(CredStashClientError::AWSDynamoError(
                "version column is missing".to_string(),
            ))?;
    Ok(dynamo_version
        .s
        .as_ref()
        .ok_or(CredStashClientError::AWSDynamoError(
            "version column value not present".to_string(),
        ))?
        .to_owned()
        .parse::<u64>()?)
}

fn pad_integer(num: u64) -> String {
    let num_str = num.to_string();
    if num_str.len() >= PAD_LEN {
        return num_str;
    } else {
        let remaining = PAD_LEN - num_str.len();
        let mut zeros: String = "0".to_string().repeat(remaining);
        zeros.push_str(&num_str);
        zeros
    }
}

fn get_algorithm(algorithm: Algorithm) -> String {
    if algorithm == ring::hmac::HMAC_SHA384 {
        return "SHA384".to_string();
    }
    if algorithm == ring::hmac::HMAC_SHA256 {
        return "SHA256".to_string();
    }
    if algorithm == ring::hmac::HMAC_SHA512 {
        return "SHA512".to_string();
    } else {
        return "SHA1".to_string();
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

#[test]
fn get_algo512_check() {
    assert_eq!(get_algorithm(ring::hmac::HMAC_SHA512), "SHA512".to_string());
}

#[test]
fn get_algo256_check() {
    assert_eq!(get_algorithm(ring::hmac::HMAC_SHA256), "SHA256".to_string());
}

pub struct CredStashClient {
    dynamo_client: DynamoDbClient,
    kms_client: KmsClient,
}

// todo: See if you can model put function input as a subset of this type
// todo: check if dynamo_hmac_key and digest_algorithm are same
// https://docs.rs/ring/0.16.9/ring/hmac/struct.Key.html
#[derive(Debug, Clone)]
pub struct CredstashItem {
    pub aes_key: Bytes,              // Key name
    pub dynamo_hmac_key: Key,        // Key name
    pub credential_value: Vec<u8>,   // Decrypted value
    pub hmac_digest: Vec<u8>,        // HMAC Digest
    pub digest_algorithm: Algorithm, // Digest type
    pub version: String,             // Version
    pub comment: Option<String>,
    pub credential_name: String,
}

#[derive(Debug, Clone)]
pub struct CredstashKey {
    pub name: String,
    pub version: String,
    pub comment: Option<String>,
}

pub enum AWSCredential {
    Sts(StsAssumeRoleSessionCredentialsProvider),
    Default(DefaultCredentialsProvider)
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
}

impl From<std::num::ParseIntError> for CredStashClientError {
    fn from(error: std::num::ParseIntError) -> Self {
        CredStashClientError::ParseError(error.to_string())
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

impl CredStashClient {
    pub fn new(region: Option<Region>) -> Self {
        Self::new_from(region)
    }

    fn new_from(region: Option<Region>) -> CredStashClient {
        let default_region = region.map_or(Region::default(), |item| item);
        let dynamo_client = DynamoDbClient::new(default_region.clone());

        let kms_client = KmsClient::new(default_region);
        CredStashClient {
            dynamo_client,
            kms_client,
        }
    }

    pub fn list_secrets<'a>(&'a self, table_name: String) -> impl Future<Item=Vec<CredstashKey>, Error=CredStashClientError> + 'a {
        let last_eval_key: Option<HashMap<String, AttributeValue>> = None;
        loop_fn((last_eval_key, vec![]), move |(last_key, mut vec_key)| {
            let mut scan_query: ScanInput = Default::default();
            scan_query.projection_expression = Some("#n, version, #c".to_string());

            let mut attr_names = HashMap::new();
            attr_names.insert("#n".to_string(), "name".to_string());
            attr_names.insert("#c".to_string(), "comment".to_string());
            scan_query.expression_attribute_names = Some(attr_names);
            scan_query.table_name = table_name.clone();
            if last_key.clone().map_or(false, |hmap| !hmap.is_empty()) {
                scan_query.exclusive_start_key = last_key;
            }

            self.dynamo_client.scan(scan_query).map_err(|err| From::from(err)).and_then(move |result| {
                let result_items = result.items;
                let mut test_vec: Vec<CredstashKey> = match result_items {
                    Some(items) => {
                        let new_vecs: Vec<CredstashKey> = items.into_iter().map(|elem| self.attribute_to_attribute_item(elem)).filter_map(|item| item.ok()).collect();
                        new_vecs
                    }
                    None => vec![]
                };
                test_vec.append(&mut vec_key);
                let cond = result.last_evaluated_key;
                if cond.is_none() {
                    Ok(Loop::Break(test_vec))
                } else {
                    Ok(Loop::Continue((cond, test_vec)))
                }
            })
        })
    }

    fn attribute_to_attribute_item(
        &self,
        item: HashMap<String, AttributeValue>,
    ) -> Result<CredstashKey, CredStashClientError> {
        let dynamo_name = item
            .get("name")
            .ok_or(CredStashClientError::AWSDynamoError(
                "name column is missing".to_string(),
            ))?;
        let dynamo_version: &AttributeValue =
            item.get("version")
                .ok_or(CredStashClientError::AWSDynamoError(
                    "version column is missing".to_string(),
                ))?;
        let comment: Option<&AttributeValue> = item.get("comment");

        let name = dynamo_name
            .s
            .as_ref()
            .ok_or(CredStashClientError::AWSDynamoError(
                "name column value not present".to_string(),
            ))?
            .to_owned();
        let version = dynamo_version
            .s
            .as_ref()
            .ok_or(CredStashClientError::AWSDynamoError(
                "version column value not present".to_string(),
            ))?
            .to_owned();
        let comment: Option<String> = match comment.map(|item| item.s.as_ref()) {
            None => None,
            Some(None) => None,
            Some(Some(c)) => Some(c.to_string()),
        };
        Ok(CredstashKey {
            name: name,
            version: version,
            comment: comment,
        })
    }

    pub fn put_secret_auto_version<'a>(
        &'a self,
        table_name: String,
        credential_name: String,
        credential_value: String,
        key_id: Option<String>,
        encryption_context: Option<(String, String)>,
        comment: Option<String>,
        digest_algorithm: Algorithm,
    ) -> impl Future<Item = PutItemOutput, Error = CredStashClientError> + 'a {
        self.get_highest_version(table_name.clone(), credential_name.clone())
            .then(move |result| match result {
                Err(_err) => self.put_secret(
                    table_name.clone(),
                    credential_name.clone(),
                    credential_value.clone(),
                    key_id.clone(),
                    encryption_context.clone(),
                    None,
                    comment.clone(),
                    digest_algorithm.clone(),
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
            })
    }

    pub fn get_highest_version(
        &self,
        table_name: String,
        credential_name: String,
    ) -> impl Future<Item = u64, Error = CredStashClientError> {
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
        self.dynamo_client
            .query(query)
            .map_err(|err| From::from(err))
            .and_then(|result| get_version(result))
            .into_future()
    }

    fn get_items<'a>(
        &'a self,
        table_name: String,
        credential: String,
    ) -> impl Future<Item = Vec<HashMap<String, AttributeValue>>, Error = CredStashClientError> + 'a {
        let last_eval_key: Option<HashMap<String, AttributeValue>> = None;
        loop_fn((last_eval_key, vec![]), move |(last_key, mut vec_key)| {
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
            if last_key.clone().map_or(false, |hmap| !hmap.is_empty()) {
                query.exclusive_start_key = last_key;
            }
            self.dynamo_client.query(query).map_err(|err| From::from(err)).and_then(move |result|  {
                let mut test_vec = match result.items {
                    Some(items) => items,
                    None => vec![]
                };
                test_vec.append(&mut vec_key);
                let cond = result.last_evaluated_key;
                if cond.is_none() {
                    Ok(Loop::Break(test_vec))
                } else {
                    Ok(Loop::Continue((cond, test_vec)))
                }
            })
        })
    }

    pub fn delete_secret<'a>(
        &'a self,
        table_name: String,
        credential: String,
    ) -> impl Future<Item = Vec<DeleteItemOutput>, Error = CredStashClientError> + 'a {
        self.get_items(table_name.clone(), credential).map_err(|err| From::from(err)).and_then(move |result| {
            let mut del_query: DeleteItemInput = Default::default();
            del_query.table_name = table_name;
            let items: Vec<_> = result.into_iter().map(|item| {
                let mut delq = del_query.clone();
                delq.key = item.clone();
                self
                    .dynamo_client
                    .delete_item(delq)
                    .map_err(|err| From::from(err))
                    .and_then(|delete_output| Ok(delete_output))
                    .into_future()
            }).collect();
            join_all(items)
        })
    }

    pub fn put_secret<'a>(
        &'a self,
        table_name: String,
        credential_name: String,
        credential_value: String,
        key_id: Option<String>,
        encryption_context: Option<(String, String)>,
        version: Option<u64>,
        comment: Option<String>,
        digest_algorithm: Algorithm,
    ) -> impl Future<Item = PutItemOutput, Error = CredStashClientError> + 'a {
        self.generate_key_via_kms(64, encryption_context, key_id)
            .map_err(|err| From::from(err))
            .and_then(move |result| {
                future::result(put_helper(
                    result,
                    digest_algorithm,
                    table_name,
                    credential_value,
                    credential_name,
                    version,
                    comment,
                ))
                .map_err(|err| From::from(err))
                .and_then(move |put_item| {
                    self.dynamo_client
                        .put_item(put_item)
                        .map_err(|err| From::from(err))
                        .and_then(|result| future::result(Ok(result)))
                        .into_future()
                })
            })
    }

    pub fn create_db_table<'a>(
        &'a self,
        table_name: String,
        tags: Option<Vec<(String, String)>>,
    ) -> impl Future<Item = CreateTableOutput, Error = CredStashClientError> + 'a {
        let mut query: DescribeTableInput = Default::default();
        query.table_name = table_name.clone();
        let table_result = self
            .dynamo_client
            .describe_table(query)
            .then(|table_result| {
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
                future::result(table_status)
            });

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

        let table_tags: Option<Vec<Tag>> = tags.map(|item| {
            item.into_iter()
                .map(|(name, value)| {
                    let mut tag: Tag = Default::default();
                    tag.key = name;
                    tag.value = value;
                    tag
                })
                .collect()
        });

        create_query.tags = table_tags;
        table_result
            .map_err(|err| From::from(err))
            .and_then(move |_result| {
                self.dynamo_client
                    .create_table(create_query)
                    .map_err(|err| From::from(err))
                    .and_then(|result| Ok(result))
            })
    }

    pub fn get_all_secrets<'a>(
        &'a self,
        table_name: String,
        encryption_context: Option<(String, String)>,
        version: Option<u64>,
    ) -> impl Future<Item = Vec<CredstashItem>, Error = CredStashClientError> + 'a {
        let table = table_name.clone();
        self.list_secrets(table).map_err(|err|From::from(err)).and_then(move |result| {
            let items: Vec<_> = result
            .into_iter()
            .map(|item| {
                self.get_secret(
                    table_name.clone(),
                    item.name,
                    encryption_context.clone(),
                    version,
                )
                .map_err(|err| From::from(err))
                .and_then(|result| Ok(result))
                .into_future()
            })
            .collect();
            join_all(items)
        })
    }

    fn to_dynamo_result<'a>(
        &'a self,
        query_output: Option<Vec<HashMap<String, AttributeValue>>>,
        encryption_context: Option<(String, String)>,
    ) -> impl Future<Item = CredstashItem, Error = CredStashClientError> + 'a {
        fn aux(
            items: Option<Vec<HashMap<String, AttributeValue>>>,
        ) -> Result<
            (
                AttributeValue,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                AttributeValue,
                AttributeValue,
            ),
            CredStashClientError,
        > {
            let dynamo_result = items.ok_or(CredStashClientError::AWSDynamoError(
                "items column is missing".to_string(),
            ))?;
            let item: HashMap<String, AttributeValue> =
                dynamo_result
                    .into_iter()
                    .nth(0)
                    .ok_or(CredStashClientError::AWSDynamoError(
                        "items is Empty".to_string(),
                    ))?;
            let dynamo_key: &AttributeValue = item.get("key").ok_or(
                CredStashClientError::AWSDynamoError("key column is missing".to_string()),
            )?;
            let dynamo_contents: &AttributeValue =
                item.get("contents")
                    .ok_or(CredStashClientError::AWSDynamoError(
                        "key column is missing".to_string(),
                    ))?;
            let dynamo_hmac: &AttributeValue =
                item.get("hmac")
                    .ok_or(CredStashClientError::AWSDynamoError(
                        "hmac column is missing".to_string(),
                    ))?;
            let dynamo_version: &AttributeValue =
                item.get("version")
                    .ok_or(CredStashClientError::AWSDynamoError(
                        "version column is missing".to_string(),
                    ))?;
            let dynamo_digest: &AttributeValue =
                item.get("digest")
                    .ok_or(CredStashClientError::AWSDynamoError(
                        "digest column is missing".to_string(),
                    ))?;
            let key: &String =
                dynamo_key
                    .s
                    .as_ref()
                    .ok_or(CredStashClientError::AWSDynamoError(
                        "key column value not present".to_string(),
                    ))?;
            let item_contents = decode(dynamo_contents.s.as_ref().ok_or(
                CredStashClientError::AWSDynamoError(
                    "contents column value not present".to_string(),
                ),
            )?)?;
            let item_hmac = hex::decode(dynamo_hmac.b.as_ref().ok_or(
                CredStashClientError::AWSDynamoError("hmac column value not present".to_string()),
            )?)?;
            let dynamo_name = item
                .get("name")
                .ok_or(CredStashClientError::AWSDynamoError(
                    "name column is missing".to_string(),
                ))?;
            let decoded_key: Vec<u8> = decode(key)?;
            Ok((
                dynamo_name.to_owned(),
                decoded_key,
                item_contents,
                item_hmac,
                dynamo_digest.to_owned(),
                dynamo_version.to_owned(),
            ))
        }
        let aux_future = future::result(aux(query_output));

        aux_future
            .map_err(|err| From::from(err))
            .and_then(move |result| {
                let (
                    dynamo_name,
                    decoded_key,
                    item_contents,
                    item_hmac,
                    dynamo_digest,
                    dynamo_version,
                ) = result;
                let algorithm = dynamo_digest
                    .s
                    .as_ref()
                    .to_owned()
                    .map_or(ring::hmac::HMAC_SHA256, |item| {
                        to_algorithm(item.to_owned())
                    });
                self.decrypt_via_kms(algorithm.clone(), decoded_key, encryption_context)
                    .map_err(|err| From::from(err))
                    .and_then(move |(hmac_key, aes_key)| {
                        let crypto_context = Crypto::new();
                        let verified = crypto_context.verify_ciphertext_integrity(
                            &hmac_key,
                            &item_contents,
                            &item_hmac,
                        );
                        if verified == false {
                            return Err(CredStashClientError::HMacMismatch);
                        }
                        let contents =
                            crypto_context.aes_decrypt_ctr(item_contents, aes_key.to_vec().clone());
                        Ok(CredstashItem {
                            aes_key: aes_key,
                            dynamo_hmac_key: hmac_key,
                            credential_value: contents,
                            hmac_digest: item_hmac,
                            digest_algorithm: algorithm,
                            version: dynamo_version
                                .s
                                .as_ref()
                                .ok_or(CredStashClientError::AWSDynamoError(
                                    "version column value not present".to_string(),
                                ))?
                                .to_owned(),
                            comment: None,
                            credential_name: dynamo_name
                                .s
                                .as_ref()
                                .ok_or(CredStashClientError::AWSDynamoError(
                                    "digest column value not present".to_string(),
                                ))?
                                .to_owned(),
                        })
                    })
            })
    }

    pub fn get_secret<'a>(
        &'a self,
        table_name: String,
        credential_name: String,
        encryption_context: Option<(String, String)>,
        version: Option<u64>,
    ) -> impl Future<Item = CredstashItem, Error = CredStashClientError> + 'a {
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
        // Have a different logic for version
        let get_future = match version {
            None => {
                let box_future: Box<dyn Future<Item = _, Error = _>> = Box::new(
                    self.dynamo_client
                        .query(query)
                        .map_err(|err| From::from(err))
                        .and_then(move |result| {
                            self.to_dynamo_result(result.items, encryption_context)
                        }),
                );
                box_future
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
                let box_future: Box<dyn Future<Item = _, Error = _>> = Box::new(
                    self.dynamo_client
                        .get_item(get_item_input)
                        .map_err(|err| From::from(err))
                        .and_then(move |result| {
                            let item = result.item;
                            let items = item.map(|hashmap| vec![hashmap]);
                            self.to_dynamo_result(items, encryption_context)
                        }),
                );
                box_future
            }
        };
        get_future
    }

    fn generate_key_via_kms(
        &self,
        number_of_bytes: i64,
        encryption_context: Option<(String, String)>,
        key_id: Option<String>,
    ) -> impl Future<Item = GenerateDataKeyResponse, Error = RusotoError<GenerateDataKeyError>>
    {
        let mut query: GenerateDataKeyRequest = Default::default();
        query.key_id = key_id.map_or("alias/credstash".to_string(), |item| item);
        query.number_of_bytes = Some(number_of_bytes);
        query.encryption_context = encryption_context.map(|(context_key, context_value)| {
            let mut hash_map = HashMap::new();
            hash_map.insert(context_key, context_value);
            hash_map
        });
        self.kms_client.generate_data_key(query)
    }

    fn decrypt_via_kms(
        &self,
        digest_algorithm: Algorithm,
        cipher: Vec<u8>,
        encryption_context: Option<(String, String)>,
    ) -> impl Future<Item = (Key, Bytes), Error = CredStashClientError> {
        let mut query: DecryptRequest = Default::default();
        let mut context = HashMap::new();

        query.ciphertext_blob = Bytes::from(cipher);
        match encryption_context {
            None => query.encryption_context = None,
            Some((c1, c2)) => {
                context.insert(c1, c2);
                query.encryption_context = Some(context);
            }
        }

        self.kms_client
            .decrypt(query)
            .map_err(|err| From::from(err))
            .and_then(move |result| get_key(result, digest_algorithm))
    }
}

fn to_algorithm(digest: String) -> Algorithm {
    match digest.as_ref() {
        "SHA1" => ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        "SHA256" => ring::hmac::HMAC_SHA256,
        "SHA384" => ring::hmac::HMAC_SHA384,
        "SHA512" => ring::hmac::HMAC_SHA512,
        _ => panic!("Unsupported digest algorithm: {}", digest),
    }
}
