extern crate rusoto_core;
extern crate rusoto_dynamodb;

use rusoto_core::region::Region;
use rusoto_core::RusotoError;
use rusoto_dynamodb::{
    AttributeValue, DynamoDb, DynamoDbClient, ListTablesError, ListTablesInput, ListTablesOutput,
    QueryInput,
};
use rusoto_kms::KmsClient;
use std::collections::HashMap;
use std::result::Result;
use std::vec::Vec;
mod crypto;
use bytes::Bytes;

pub struct CredStashClient {
    dynamo_client: DynamoDbClient,
    kms_client: KmsClient,
}

#[derive(Debug, PartialEq)]
pub struct DynamoResult {
    dynamo_key: String,      // Key name
    dynamo_contents: String, // Key value which we are interested to decrypt
    dynamo_hmac: Bytes,      // HMAC Digest
    dynamo_digest: String,   // Digest type
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

    pub fn get_secret(self, table: String, key: String) -> DynamoResult {
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
        strAttr.s = Some("hello".to_string());

        let mut attr_values = HashMap::new();
        attr_values.insert(":nameValue".to_string(), strAttr);
        query.expression_attribute_values = Some(attr_values);
        query.table_name = table;
        let query_output = self.dynamo_client.query(query).sync();
        let dynamo_result: Vec<HashMap<String, AttributeValue>> =
            query_output.unwrap().items.unwrap();
        let dr: HashMap<String, AttributeValue> = dynamo_result.into_iter().nth(0).unwrap();
        println!("1");
        let dynamo_key: &AttributeValue = dr.get("key").unwrap();
        println!("2");
        let dynamo_contents: &AttributeValue = dr.get("contents").unwrap();
        println!("3");
        let dynamo_hmac: &AttributeValue = dr.get("hmac").unwrap();
        println!("4");
        let dynamo_version: &AttributeValue = dr.get("version").unwrap();
        println!("5");
        let dynamo_digest: &AttributeValue = dr.get("digest").unwrap();
        println!("6");
        let dkey: String = dynamo_key.s.as_ref().unwrap().to_string();
        println!("7");
        DynamoResult {
            dynamo_key: dkey,
            dynamo_contents: dynamo_contents.s.as_ref().unwrap().to_string(),
            dynamo_hmac: dynamo_hmac.b.as_ref().unwrap().to_owned(),
            dynamo_digest: dynamo_digest.s.as_ref().unwrap().to_string(),
        }
    }

    pub fn fetch_customer_managed_keys(self, alias: String) -> () {
        ()
    }

    pub fn decrypt_secret(self, value: String) -> () {
        ()
    }
}

// fn test() -> Result<ListTablesOutput, RusotoError<ListTablesError>> {
// let lto = self.dynamo_client.list_tables(list_tables_input).sync()?;
// let table_names = lto.table_names.expect("Not able to find the table");

//     let list_tables_input: ListTablesInput = Default::default();
//     dynamo_client.list_tables(list_tables_input).sync()
// }
