extern crate credstash;

use credstash::{CredStashClient, CredStashCredential, CredstashItem};
use std::str;

// This test assumes you have already have an AWS infrastructure running.
// Both table and the KMS key should be present for the test to pass.
#[tokio::test]
async fn credstash_basic_workflow() {
    // put credential
    let table_name = "credential-store".to_string();
    let app = CredStashClient::new(CredStashCredential::DefaultCredentialsProvider, None).unwrap();
    let put_result = app
        .put_secret(
            table_name.clone(),
            "hello12".to_string(),
            "world12".to_string(),
            None,
            vec![],
            None,
            None,
            ring::hmac::HMAC_SHA256,
        )
        .await;

    put_result.unwrap();

    // get credential
    let result: CredstashItem = app
        .get_secret(table_name.clone(), "hello12".to_string(), vec![], None)
        .await
        .unwrap();
    let secret_utf8 = str::from_utf8(&result.credential_value).unwrap();
    assert_eq!("world12".to_string(), secret_utf8);

    // put auto increment
    let put_auto_secret_future = app
        .put_secret_auto_version(
            table_name.clone(),
            "hello12".to_string(),
            "world12".to_string(),
            None,
            vec![],
            None,
            ring::hmac::HMAC_SHA256,
        )
        .await;
    assert!(put_auto_secret_future.is_ok());

    // get version
    let get_version_future = app
        .get_highest_version(table_name.clone(), "hello12".to_string())
        .await;
    assert_eq!(get_version_future.unwrap(), 2);

    // get all secrets
    let get_all_future = app.get_all_secrets(table_name.clone(), vec![], None).await;

    assert!(!get_all_future.unwrap().is_empty());

    // delete credential
    let delete_future = app.delete_secret(table_name, "hello12".to_string()).await;
    assert!(delete_future.is_ok());
}
