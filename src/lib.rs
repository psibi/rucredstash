extern crate base64;
extern crate futures;
extern crate hex;
extern crate rusoto_core;
extern crate rusoto_dynamodb;
extern crate tokio_core;

use core::convert::From;
use futures::future;
use futures::future::Future;
use futures::future::IntoFuture;
use futures::future::*;
use futures::Stream;
use rusoto_core::region::Region;
use rusoto_core::RusotoError::*;
use rusoto_core::{RusotoError, RusotoFuture, RusotoResult};
use rusoto_dynamodb::{
    AttributeDefinition, AttributeValue, CreateTableError, CreateTableInput, CreateTableOutput,
    DeleteItemError, DeleteItemInput, DeleteItemOutput, DescribeTableError, DescribeTableInput,
    DescribeTableOutput, DynamoDb, DynamoDbClient, KeySchemaElement, ListTablesError,
    ListTablesInput, ListTablesOutput, ProvisionedThroughput, PutItemError, PutItemInput,
    PutItemOutput, QueryError, QueryInput, QueryOutput, ScanError, ScanInput, ScanOutput,
    TableDescription,
};
use rusoto_kms::DecryptRequest;
use rusoto_kms::{
    DecryptError, DecryptResponse, GenerateDataKeyError, GenerateDataKeyRequest,
    GenerateDataKeyResponse, Kms, KmsClient,
};
use std::clone::Clone;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::iter::Iterator;
use std::result::Result;
use std::string::String;
use std::vec::Vec;
use tokio_core::reactor::Core;
mod crypto;
use base64::{decode, encode, DecodeError};
use bytes::Bytes;
use futures::stream;
use hex::FromHexError;
use ring;
use ring::hmac::{sign, Algorithm, Key};

const PAD_LEN: usize = 19;

fn put_helper(
    query_output: GenerateDataKeyResponse,
    digest_algorithm: Algorithm,
    table_name: String,
    value: String,
    credential: String,
    version: Option<u64>,
    comment: Option<String>,
) -> Result<PutItemInput, CredStashClientError> {
    let mut hmac_key: Bytes = match query_output.plaintext {
        None => return Err(CredStashClientError::NoKeyFound),
        Some(val) => val,
    };
    let full_key = hmac_key.clone();
    let aes_key = hmac_key.split_to(32);
    let hmac_ring_key = Key::new(digest_algorithm, hmac_key.as_ref());
    let crypto_context = crypto::Crypto::new();
    let aes_enc = crypto_context.aes_encrypt_ctr(value.as_bytes().to_owned(), aes_key); // Encrypted text of value part
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
    item_name.s = Some(credential);
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

fn get_version(query_output: QueryOutput) -> Result<String, CredStashClientError> {
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
        .to_owned())
}

fn pad_integer(num: u64) -> String {
    let num_str = num.to_string();
    if (num_str.len() >= PAD_LEN) {
        return num_str;
    } else {
        let remaining = PAD_LEN - num_str.len();
        let mut zeros: String = "0".to_string().repeat(remaining);
        zeros.push_str(&num_str);
        zeros
    }
}

fn get_algorithm(algorithm: Algorithm) -> String {
    if (algorithm == ring::hmac::HMAC_SHA384) {
        return "SHA384".to_string();
    }
    if (algorithm == ring::hmac::HMAC_SHA256) {
        return "SHA256".to_string();
    }
    if (algorithm == ring::hmac::HMAC_SHA512) {
        return "SHA512".to_string();
    } else {
        return "SHA256".to_string();
    }
    // todo: handle everything
    // let algo = match algorithm {
    //     HMAC_SHA384 => "SHA384".to_string(),
    //     HMAC_SHA256 => "SHA256".to_string(),
    //     HMAC_SHA512 => "SHA512".to_string(),
    //     HMAC_SHA1_FOR_LEGACY_USE_ONLY => "SHA".to_string(),
    //     _ => panic!("fix me"),
    // };
    // algo
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

// Probably rename it to CredstashItem ?
#[derive(Debug, Clone)]
pub struct DynamoResult {
    pub dynamo_aes_key: Bytes,    // Key name
    dynamo_hmac_key: Key,         // Key name
    pub dynamo_contents: Vec<u8>, // Decrypted value
    dynamo_hmac: Vec<u8>,         // HMAC Digest
    dynamo_digest: String,        // Digest type
    dynamo_version: String,       // Version
    dynamo_comment: Option<String>,
    pub dynamo_name: String,
}

#[derive(Debug, Clone)]
pub struct CredstashKey {
    pub name: String,
    pub version: String,
    pub comment: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum CredStashClientError {
    NoKeyFound,
    KMSError(RusotoError<DecryptError>),
    KMSDataKeyError(RusotoError<GenerateDataKeyError>),
    DynamoError(RusotoError<QueryError>),
    DynamoError2(RusotoError<PutItemError>),
    AWSDynamoError(String),
    AWSKMSError(String),
    CredstashDecodeFalure(DecodeError),
    CredstashHexFailure(FromHexError),
    HMacMismatch,
}

impl From<RusotoError<DescribeTableError>> for CredStashClientError {
    fn from(error: RusotoError<DescribeTableError>) -> Self {
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
        CredStashClientError::KMSDataKeyError(error)
    }
}

impl From<RusotoError<PutItemError>> for CredStashClientError {
    fn from(error: RusotoError<PutItemError>) -> Self {
        CredStashClientError::DynamoError2(error)
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
    pub fn new() -> Self {
        Self::new_from()
    }

    fn new_from() -> CredStashClient {
        let default_region = Region::default();
        let dynamo_client = DynamoDbClient::new(default_region.clone());
        let kms_client = KmsClient::new(default_region);
        CredStashClient {
            dynamo_client,
            kms_client,
        }
    }

    pub fn list_secrets(&self, table: String) -> Result<Vec<CredstashKey>, CredStashClientError> {
        let mut last_eval_key = Some(HashMap::new());
        let mut items = vec![];
        while (last_eval_key.is_some()) {
            let mut scan_query: ScanInput = Default::default();

            scan_query.projection_expression = Some("#n, version, #c".to_string());

            let mut attr_names = HashMap::new();
            attr_names.insert("#n".to_string(), "name".to_string());
            attr_names.insert("#c".to_string(), "comment".to_string());
            scan_query.expression_attribute_names = Some(attr_names);
            scan_query.table_name = table.clone();
            if (last_eval_key.clone().map_or(false, |hmap| !hmap.is_empty())) {
                scan_query.exclusive_start_key = last_eval_key;
            }

            let result: ScanOutput = self.dynamo_client.scan(scan_query).sync()?;
            let mut result_items = result.items.ok_or(CredStashClientError::AWSDynamoError(
                "items value is empty".to_string(),
            ))?;
            items.append(&mut result_items);
            last_eval_key = result.last_evaluated_key;
        }
        let res: Result<Vec<CredstashKey>, CredStashClientError> = items
            .into_iter()
            .map(|item| self.attribute_to_attribute_item(item))
            .into_iter()
            .collect();
        res
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
        let dynamo_comment: Option<&AttributeValue> = item.get("comment");

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
        // todo: convert to use flatten once it is available in stable
        let comment: Option<String> = match dynamo_comment.map(|item| item.s.as_ref()) {
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

    pub fn get_highest_version(
        &self,
        table: String,
        key: String,
    ) -> impl Future<Item = String, Error = CredStashClientError> {
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
        str_attr.s = Some(key);

        let mut attr_values = HashMap::new();
        attr_values.insert(":nameValue".to_string(), str_attr);
        query.expression_attribute_values = Some(attr_values);
        query.table_name = table;

        query.projection_expression = Some("version".to_string());
        self.dynamo_client
            .query(query)
            .map_err(|err| From::from(err))
            .and_then(|result| get_version(result))
            .into_future()
    }

    pub fn delete_secret(
        &self,
        table_name: String,
        credential: String,
    ) -> impl Future<Item = Vec<DeleteItemOutput>, Error = CredStashClientError> {
        let mut last_eval_key = Some(HashMap::new());
        let mut items = vec![];
        while (last_eval_key.is_some()) {
            let mut query: QueryInput = Default::default();
            let cond: String = "#n = :nameValue".to_string();
            query.key_condition_expression = Some(cond);

            let mut attr_names = HashMap::new();
            attr_names.insert("#n".to_string(), "name".to_string());
            query.expression_attribute_names = Some(attr_names);

            query.projection_expression = Some("#n, version".to_string());

            let mut strAttr: AttributeValue = AttributeValue::default();
            strAttr.s = Some(credential.clone());

            let mut attr_values = HashMap::new();
            attr_values.insert(":nameValue".to_string(), strAttr);
            query.expression_attribute_values = Some(attr_values);
            query.table_name = table_name.clone();
            if (last_eval_key.clone().map_or(false, |hmap| !hmap.is_empty())) {
                query.exclusive_start_key = last_eval_key.clone();
            }
            let result = self.dynamo_client.query(query).sync();
            match result {
                Ok(val) => match val.items {
                    Some(mut result_items) => {
                        items.append(&mut result_items);
                        last_eval_key = val.last_evaluated_key;
                    }
                    None => {
                        last_eval_key = None;
                    }
                },
                Err(_) => {
                    last_eval_key = None;
                }
            }
        }
        let mut del_query: DeleteItemInput = Default::default();
        del_query.table_name = table_name;
        let result: Vec<_> = items
            .iter()
            .map(|item| {
                let mut delq = del_query.clone();
                delq.key = item.clone();
                let dom = self
                    .dynamo_client
                    .delete_item(delq)
                    .map_err(|err| From::from(err))
                    .and_then(|delete_output| Ok(delete_output))
                    .into_future();
                dom
            })
            .collect();
        join_all(result)
    }

    pub fn put_secret<'a>(
        &'a self,
        table_name: String,
        credential: String, // Key part. (Or the name column in dynamodb)
        value: String,      // This should be encrypted
        version: Option<u64>,
        context: Option<String>,
        comment: Option<String>,
        digest_algorithm: Algorithm,
    ) -> impl Future<Item = PutItemOutput, Error = CredStashClientError> + 'a {
        self.generate_key_via_kms(64)
            .map_err(|err| From::from(err))
            .and_then(move |result| {
                future::result(put_helper(
                    result,
                    digest_algorithm,
                    table_name,
                    value,
                    credential,
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
        tags: String,
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

        // todo: add tags also to create_query
        // todo: wait till tablestatus becomes active. see if you can do something with tokio
        table_result
            .map_err(|err| From::from(err))
            .and_then(move |tup| {
                self.dynamo_client
                    .create_table(create_query)
                    .map_err(|err| From::from(err))
                    .and_then(|result| Ok(result))
            })
    }

    pub fn get_all_secrets<'a>(
        &'a self,
        table_name: String,
    ) -> impl Future<Item = Vec<DynamoResult>, Error = CredStashClientError> + 'a {
        let table = table_name.clone();
        let keys: Vec<CredstashKey> = match self.list_secrets(table) {
            Ok(items) => items,
            Err(_) => vec![],
        };
        let items: Vec<_> = keys
            .into_iter()
            .map(|item| {
                self.get_secret(table_name.clone(), item.name, ring::hmac::HMAC_SHA256)
                    .map_err(|err| From::from(err))
                    .and_then(|result| Ok(result))
                    .into_future()
            })
            .collect();
        join_all(items)
    }

    fn to_dynamo_result<'a>(
        &'a self,
        query_output: Result<QueryOutput, RusotoError<QueryError>>,
        digest_algorithm: Algorithm,
    ) -> impl Future<Item = DynamoResult, Error = CredStashClientError> + 'a {
        fn aux(
            result: Result<QueryOutput, RusotoError<QueryError>>,
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
            let dynamo_result = result?.items.ok_or(CredStashClientError::AWSDynamoError(
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
                self.decrypt_via_kms(digest_algorithm.clone(), decoded_key)
                    .map_err(|err| From::from(err))
                    .and_then(move |(hmac_key, aes_key)| {
                        let crypto_context = crypto::Crypto::new();
                        let verified = crypto_context.verify_ciphertext_integrity(
                            &hmac_key,
                            &item_contents,
                            &item_hmac,
                        );
                        if (verified == false) {
                            return Err(CredStashClientError::HMacMismatch);
                        }
                        let contents =
                            CredStashClient::decrypt_secret(item_contents, aes_key.clone());
                        Ok(DynamoResult {
                            dynamo_aes_key: aes_key,
                            dynamo_hmac_key: hmac_key,
                            dynamo_contents: contents,
                            dynamo_hmac: item_hmac,
                            dynamo_digest: dynamo_digest
                                .s
                                .as_ref()
                                .ok_or(CredStashClientError::AWSDynamoError(
                                    "digest column value not present".to_string(),
                                ))?
                                .to_owned(),
                            dynamo_version: dynamo_version
                                .s
                                .as_ref()
                                .ok_or(CredStashClientError::AWSDynamoError(
                                    "version column value not present".to_string(),
                                ))?
                                .to_owned(),
                            dynamo_comment: None,
                            dynamo_name: dynamo_name
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
        key: String,
        digest_algorithm: Algorithm,
    ) -> impl Future<Item = DynamoResult, Error = CredStashClientError> + 'a {
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
        str_attr.s = Some(key);

        let mut attr_values = HashMap::new();
        attr_values.insert(":nameValue".to_string(), str_attr);
        query.expression_attribute_values = Some(attr_values);
        query.table_name = table_name;
        self.dynamo_client
            .query(query)
            .map_err(|err| From::from(err))
            .and_then(move |result| self.to_dynamo_result(Ok(result.clone()), digest_algorithm))
    }

    fn generate_key_via_kms(
        &self,
        number_of_bytes: i64,
    ) -> impl Future<Item = GenerateDataKeyResponse, Error = RusotoError<GenerateDataKeyError>>
    {
        let mut query: GenerateDataKeyRequest = Default::default();
        query.key_id = "alias/credstash".to_string();
        query.number_of_bytes = Some(number_of_bytes);
        self.kms_client.generate_data_key(query)
    }

    fn decrypt_via_kms(
        &self,
        digest_algorithm: Algorithm,
        cipher: Vec<u8>,
    ) -> impl Future<Item = (Key, Bytes), Error = CredStashClientError> {
        let mut query: DecryptRequest = Default::default();
        query.ciphertext_blob = Bytes::from(cipher);
        self.kms_client
            .decrypt(query)
            .map_err(|err| From::from(err))
            .and_then(move |result| get_key(result, digest_algorithm))
    }

    // todo: probably move to crypto context
    pub fn decrypt_secret(contents: Vec<u8>, key: Bytes) -> Vec<u8> {
        let crypto_context = crypto::Crypto::new();
        crypto_context.aes_decrypt_ctr3(contents, key.into_iter().collect())
    }
}
