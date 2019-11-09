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
use rusoto_kms::{DecryptError, Kms, KmsClient};
use std::collections::HashMap;
use std::result::Result;
use std::vec::Vec;
mod crypto;
use base64::decode;
use bytes::Bytes;

pub struct CredStashClient {
    dynamo_client: DynamoDbClient,
    kms_client: KmsClient,
}

#[derive(Debug, PartialEq)]
pub struct DynamoResult {
    dynamo_aes_key: Bytes,    // Key name
    dynamo_hmac_key: Bytes,   // Key name
    dynamo_contents: Vec<u8>, // Key value which we are interested to decrypt
    dynamo_hmac: Vec<u8>,     // HMAC Digest
    dynamo_digest: String,    // Digest type
    dynamo_version: String,   // Version
}

#[derive(Debug, PartialEq)]
pub enum CredStashClientError {
    NoKeyFound,
    KMSError(RusotoError<DecryptError>),
    DynamoError(RusotoError<QueryError>),
    AWSDynamoError(String),
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

    pub fn get_secret(
        &self,
        table: String,
        key: String,
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
            Ok(val) => val.items.unwrap(),
            Err(err) => return Err(CredStashClientError::DynamoError(err)),
        };
        let dr: HashMap<String, AttributeValue> =
            dynamo_result
                .into_iter()
                .nth(0)
                .ok_or(CredStashClientError::AWSDynamoError(
                    "items is Empty".to_string(),
                ))?;
        let dynamo_key: &AttributeValue = dr.get("key").unwrap();
        let dynamo_contents: &AttributeValue = dr.get("contents").unwrap();
        let dynamo_hmac: &AttributeValue = dr.get("hmac").unwrap();
        let dynamo_version: &AttributeValue = dr.get("version").unwrap();
        let dynamo_digest: &AttributeValue = dr.get("digest").unwrap();
        // let dkey: String = dynamo_key.s.as_ref().unwrap().to_string();
        let dkey1: &String = dynamo_key.s.as_ref().unwrap();
        let dkey1decode: Vec<u8> = decode(dkey1).unwrap();
        // pass dkey1decode to decrypt_via_kms
        let (hmac_key, aes_key) = self.decrypt_via_kms(dkey1decode).unwrap();
        Ok(DynamoResult {
            dynamo_aes_key: aes_key,
            dynamo_hmac_key: hmac_key,
            dynamo_contents: decode(dynamo_contents.s.as_ref().unwrap()).unwrap(),
            dynamo_hmac: hex::decode(dynamo_hmac.b.as_ref().unwrap()).unwrap(),
            dynamo_digest: dynamo_digest.s.as_ref().unwrap().to_string(),
            dynamo_version: dynamo_version.s.as_ref().unwrap().to_owned(),
        })
    }

    fn decrypt_via_kms(&self, cipher: Vec<u8>) -> Result<(Bytes, Bytes), CredStashClientError> {
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
        Ok((hmac_key, aes_key))
    }

    pub fn fetch_customer_managed_keys(self, alias: String) -> () {
        ()
    }

    pub fn decrypt_secret(row: DynamoResult) -> Vec<u8> {
        let crypto_context = crypto::Crypto::new();
        crypto_context.aes_decrypt_ctr3(
            row.dynamo_contents,
            row.dynamo_aes_key.into_iter().collect(),
        )
    }
}

// fn test() -> Result<ListTablesOutput, RusotoError<ListTablesError>> {
// let lto = self.dynamo_client.list_tables(list_tables_input).sync()?;
// let table_names = lto.table_names.expect("Not able to find the table");

//     let list_tables_input: ListTablesInput = Default::default();
//     dynamo_client.list_tables(list_tables_input).sync()
// }
