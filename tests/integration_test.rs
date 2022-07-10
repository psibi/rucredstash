extern crate credstash;

use credstash::{CredStashClient, CredStashCredential, CredstashItem};
use std::str;
use tokio::runtime::Runtime;

// This test assumes you have already have an AWS infrastructure running.
// Both table and the KMS key should be present for the test to pass.
#[test]
fn credstash_basic_workflow() {
    let rt = Runtime::new().unwrap();

    // put credential
    let table_name = "credential-store".to_string();
    let app = CredStashClient::new(CredStashCredential::DefaultCredentialsProvider, None).unwrap();
    let put_future = rt.block_on(async {
        app.put_secret(
            table_name.clone(),
            "hello12".to_string(),
            "world12".to_string(),
            None,
            vec![],
            None,
            None,
            ring::hmac::HMAC_SHA256,
        )
        .await
    });

    assert!(put_future.is_ok());

    // get credential
    let result: CredstashItem = rt
        .block_on(async {
            app.get_secret(table_name.clone(), "hello12".to_string(), vec![], None)
                .await
        })
        .unwrap();
    let secret_utf8 = str::from_utf8(&result.credential_value).unwrap();
    assert_eq!("world12".to_string(), secret_utf8);

    // put auto increment
    let put_auto_secret_future = app.put_secret_auto_version(
        table_name.clone(),
        "hello12".to_string(),
        "world12".to_string(),
        None,
        vec![],
        None,
        ring::hmac::HMAC_SHA256,
    );
    let result = rt.block_on(async { put_auto_secret_future.await });
    assert!(result.is_ok());

    // get version
    let get_version_future = app.get_highest_version(table_name.clone(), "hello12".to_string());
    let result = rt.block_on(async { get_version_future.await });
    assert_eq!(result.unwrap(), 2);

    // get all secrets
    let get_all_future = app.get_all_secrets(table_name.clone(), vec![], None);
    let result = rt.block_on(async { get_all_future.await });
    assert_eq!(result.unwrap().len() >= 1, true);

    // delete credential
    let delete_future = app.delete_secret(table_name, "hello12".to_string());
    let res = rt.block_on(async { delete_future.await });
    assert!(res.is_ok());
}
