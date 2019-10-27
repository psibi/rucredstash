pub mod credstash {
    extern crate rusoto_core;
    extern crate rusoto_dynamodb;

    use rusoto_core::region::Region;
    use rusoto_core::RusotoError;
    use rusoto_dynamodb::{
        DynamoDb, DynamoDbClient, ListTablesError, ListTablesInput, ListTablesOutput, QueryInput,
    };
    use rusoto_kms::KmsClient;
    use std::result::Result;
    use std::vec::Vec;

    pub struct CredStashClient {
        dynamo_client: DynamoDbClient,
        kms_client: KmsClient,
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

        pub fn get_secret(self, table: String, key: String) -> () {
            let mut query: QueryInput = Default::default();
            query.scan_index_forward = Some(false);
            query.limit = Some(1);
            query.consistent_read = Some(true);
            let mut cond: String = "name = ".to_string();
            cond.push_str(key.as_str());
            query.key_condition_expression = Some(cond);
            let query_output = self.dynamo_client.query(query).sync();
            println!("{:?}", query_output);
            // now find the table key
            ()
        }
    }

    // fn test() -> Result<ListTablesOutput, RusotoError<ListTablesError>> {
    // let lto = self.dynamo_client.list_tables(list_tables_input).sync()?;
    // let table_names = lto.table_names.expect("Not able to find the table");

    //     let list_tables_input: ListTablesInput = Default::default();
    //     dynamo_client.list_tables(list_tables_input).sync()
    // }
}
