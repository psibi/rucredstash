extern crate base64;
extern crate hex;
extern crate rusoto_core;
extern crate rusoto_dynamodb;

use rusoto_core::region::Region;
use rusoto_core::{RusotoError, RusotoResult};
use rusoto_dynamodb::{
    AttributeValue, DynamoDb, DynamoDbClient, ListTablesError, ListTablesInput, ListTablesOutput,
    QueryError, QueryInput,
};
use rusoto_kms::DecryptRequest;
use rusoto_kms::{
    DecryptError, GenerateDataKeyError, GenerateDataKeyRequest, GenerateDataKeyResponse, Kms,
    KmsClient,
};
use std::collections::HashMap;
use std::result::Result;
use std::vec::Vec;
mod crypto;
use base64::{decode, encode, DecodeError};
use bytes::Bytes;
use hex::FromHexError;
use ring::hmac::{sign, Algorithm, Key};

const PAD_LEN: usize = 19;

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

#[test]
fn pad_integer_check() {
    assert_eq!(pad_integer(1), "0000000000000000001".to_string());
}

#[test]
fn pad_integer_check_big_num() {
    assert_eq!(pad_integer(123), "0000000000000000123".to_string());
}

pub struct CredStashClient {
    dynamo_client: DynamoDbClient,
    kms_client: KmsClient,
}

#[derive(Debug)]
pub struct DynamoResult {
    dynamo_aes_key: Bytes,    // Key name
    dynamo_hmac_key: Key,     // Key name
    dynamo_contents: Vec<u8>, // Key value which we are interested to decrypt
    dynamo_hmac: Vec<u8>,     // HMAC Digest
    dynamo_digest: String,    // Digest type
    dynamo_version: String,   // Version
}

#[derive(Debug, PartialEq)]
pub enum CredStashClientError {
    NoKeyFound,
    KMSError(RusotoError<DecryptError>),
    KMSDataKeyError(RusotoError<GenerateDataKeyError>),
    DynamoError(RusotoError<QueryError>),
    AWSDynamoError(String),
    AWSKMSError(String),
    CredstashDecodeFalure(DecodeError),
    CredstashHexFailure(FromHexError),
    HMacMismatch,
}

impl From<RusotoError<GenerateDataKeyError>> for CredStashClientError {
    fn from(error: RusotoError<GenerateDataKeyError>) -> Self {
        CredStashClientError::KMSDataKeyError(error)
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

    pub fn get_highest_version(
        &self,
        table: String,
        key: String,
    ) -> Result<String, CredStashClientError> {
        let mut query: QueryInput = Default::default();
        query.scan_index_forward = Some(false);
        query.limit = Some(1);
        query.consistent_read = Some(true);
        let cond: String = "#n = :nameValue".to_string();
        query.key_condition_expression = Some(cond);

        let mut attr_names = HashMap::new();
        attr_names.insert("#n".to_string(), "name".to_string());
        query.expression_attribute_names = Some(attr_names);

        let mut strAttr: AttributeValue = AttributeValue::default();
        strAttr.s = Some(key);

        let mut attr_values = HashMap::new();
        attr_values.insert(":nameValue".to_string(), strAttr);
        query.expression_attribute_values = Some(attr_values);
        query.table_name = table;

        query.projection_expression = Some("version".to_string());
        let query_output = self.dynamo_client.query(query).sync();

        let dynamo_result: Vec<HashMap<String, AttributeValue>> = match query_output {
            Ok(val) => val.items.ok_or(CredStashClientError::AWSDynamoError(
                "items column is missing".to_string(),
            ))?,
            Err(err) => return Err(CredStashClientError::DynamoError(err)),
        };
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

    pub fn put_secret(
        &self,
        credential: String,
        value: String,
        context: Option<String>,
        digest_algorithm: Algorithm,
    ) -> Result<(), CredStashClientError> {
        let query_output = self.generate_key_via_kms(64)?;
        // todo: Refactor this code
        let mut hmac_key: Bytes = match query_output.plaintext {
            None => return Err(CredStashClientError::NoKeyFound),
            Some(val) => val,
        };
        let aes_key = hmac_key.split_to(32);
        let hmac_ring_key = Key::new(digest_algorithm, hmac_key.as_ref());
        let crypto_context = crypto::Crypto::new();
        let aes_enc = crypto_context.aes_encrypt_ctr(value.as_bytes().to_owned(), aes_key);
        let hmac_en = sign(&hmac_ring_key, &aes_enc);
        let ciphertext_blob = query_output
            .ciphertext_blob
            .ok_or(CredStashClientError::AWSKMSError(
                "ciphertext_blob is empty".to_string(),
            ))?
            .to_vec();
        let version = 1;
        let base64_aes_enc = encode(&aes_enc);
        let base64_cipher_blob = encode(&ciphertext_blob);
        let hex_hmac = hex::encode(hmac_en);
        // todo: Add new row according to the pseudocode
        Ok(())
    }

    pub fn get_secret(
        &self,
        table: String,
        key: String,
        digest_algorithm: Algorithm,
    ) -> Result<DynamoResult, CredStashClientError> {
        let mut query: QueryInput = Default::default();
        query.scan_index_forward = Some(false);
        query.limit = Some(1);
        query.consistent_read = Some(true);
        let cond: String = "#n = :nameValue".to_string();
        query.key_condition_expression = Some(cond);

        let mut attr_names = HashMap::new();
        attr_names.insert("#n".to_string(), "name".to_string());
        query.expression_attribute_names = Some(attr_names);

        let mut strAttr: AttributeValue = AttributeValue::default();
        strAttr.s = Some(key);

        let mut attr_values = HashMap::new();
        attr_values.insert(":nameValue".to_string(), strAttr);
        query.expression_attribute_values = Some(attr_values);
        query.table_name = table;
        let query_output = self.dynamo_client.query(query).sync();
        let dynamo_result: Vec<HashMap<String, AttributeValue>> = match query_output {
            Ok(val) => val.items.ok_or(CredStashClientError::AWSDynamoError(
                "items column is missing".to_string(),
            ))?,
            Err(err) => return Err(CredStashClientError::DynamoError(err)),
        };
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
        let key: &String = dynamo_key
            .s
            .as_ref()
            .ok_or(CredStashClientError::AWSDynamoError(
                "key column value not present".to_string(),
            ))?;
        let item_contents = decode(dynamo_contents.s.as_ref().ok_or(
            CredStashClientError::AWSDynamoError("contents column value not present".to_string()),
        )?)?;
        let item_hmac = hex::decode(dynamo_hmac.b.as_ref().ok_or(
            CredStashClientError::AWSDynamoError("hmac column value not present".to_string()),
        )?)?;

        let decoded_key: Vec<u8> = decode(key)?;
        let (hmac_key, aes_key) = self.decrypt_via_kms(digest_algorithm, decoded_key)?;
        let crypto_context = crypto::Crypto::new();
        let verified =
            crypto_context.verify_ciphertext_integrity(&hmac_key, &item_contents, &item_hmac);
        if (verified == false) {
            return Err(CredStashClientError::HMacMismatch);
        }
        Ok(DynamoResult {
            dynamo_aes_key: aes_key,
            dynamo_hmac_key: hmac_key,
            dynamo_contents: item_contents,
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
        })
    }

    fn generate_key_via_kms(
        &self,
        number_of_bytes: i64,
    ) -> Result<GenerateDataKeyResponse, RusotoError<GenerateDataKeyError>> {
        let mut query: GenerateDataKeyRequest = Default::default();
        query.key_id = "alias/credstash".to_string();
        query.number_of_bytes = Some(number_of_bytes);
        self.kms_client.generate_data_key(query).sync()
    }

    fn decrypt_via_kms(
        &self,
        digest_algorithm: Algorithm,
        cipher: Vec<u8>,
    ) -> Result<(Key, Bytes), CredStashClientError> {
        let mut query: DecryptRequest = Default::default();
        query.ciphertext_blob = Bytes::from(cipher);
        let query_output = match self.kms_client.decrypt(query).sync() {
            Ok(output) => output,
            Err(err) => return Err(CredStashClientError::KMSError(err)),
        };
        let mut hmac_key: Bytes = match query_output.plaintext {
            None => return Err(CredStashClientError::NoKeyFound),
            Some(val) => val,
        };
        let aes_key = hmac_key.split_to(32);
        let hmac_ring_key = Key::new(digest_algorithm, hmac_key.as_ref());
        Ok((hmac_ring_key, aes_key))
    }

    pub fn decrypt_secret(row: DynamoResult) -> Vec<u8> {
        let crypto_context = crypto::Crypto::new();
        crypto_context.aes_decrypt_ctr3(
            row.dynamo_contents,
            row.dynamo_aes_key.into_iter().collect(),
        )
    }
}
