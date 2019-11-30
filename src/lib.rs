extern crate base64;
extern crate hex;
extern crate rusoto_core;
extern crate rusoto_dynamodb;

use rusoto_core::region::Region;
use rusoto_core::{RusotoError, RusotoResult};
use rusoto_dynamodb::{
    AttributeValue, DeleteItemError, DeleteItemInput, DynamoDb, DynamoDbClient, ListTablesError,
    ListTablesInput, ListTablesOutput, PutItemError, PutItemInput, QueryError, QueryInput,
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
use ring;
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
    DynamoError2(RusotoError<PutItemError>),
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

    pub fn delete_secret(
        &self,
        table_name: String,
        credential: String,
    ) -> Result<(), CredStashClientError> {
        let mut query: QueryInput = Default::default();
        let cond: String = "#n = :nameValue".to_string();
        query.key_condition_expression = Some(cond);

        let mut attr_names = HashMap::new();
        attr_names.insert("#n".to_string(), "name".to_string());
        query.expression_attribute_names = Some(attr_names);

        query.projection_expression = Some("#n, version".to_string());

        let mut strAttr: AttributeValue = AttributeValue::default();
        strAttr.s = Some(credential);

        let mut attr_values = HashMap::new();
        attr_values.insert(":nameValue".to_string(), strAttr);
        query.expression_attribute_values = Some(attr_values);
        query.table_name = table_name.clone();
        let query_output = self.dynamo_client.query(query).sync();
        println!("another: {:?}", query_output);
        let dynamo_result: Vec<HashMap<String, AttributeValue>> = match query_output {
            Ok(val) => val.items.ok_or(CredStashClientError::AWSDynamoError(
                "items column is missing".to_string(),
            ))?,
            Err(err) => return Err(CredStashClientError::DynamoError(err)),
        };
        let mut del_query: DeleteItemInput = Default::default();
        del_query.table_name = table_name;
        for item in dynamo_result {
            let mut delq = del_query.clone();
            delq.key = item;
            self.dynamo_client.delete_item(delq).sync()?;
        }
        // println!("result {:?}", dynamo_result);
        Ok(())
    }

    pub fn put_secret(
        &self,
        table_name: String,
        credential: String, // Key part. (Or the name column in dynamodb)
        version: String,
        value: String, // This should be encrypted
        context: Option<String>,
        comment: Option<String>,
        digest_algorithm: Algorithm,
    ) -> Result<(), CredStashClientError> {
        let query_output = self.generate_key_via_kms(64)?;
        // todo: Refactor this code
        let mut hmac_key: Bytes = match query_output.plaintext {
            None => return Err(CredStashClientError::NoKeyFound),
            Some(val) => val,
        };
        let full_key = hmac_key.clone();
        let full_key_en = encode(&full_key); // Encoding of full data key
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
        item_version.s = Some(version);
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
        self.dynamo_client.put_item(put_item).sync()?;
        // todo: next step: test put_secret now
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
