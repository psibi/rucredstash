extern crate credstash;

use credstash::{CredStashClient, CredStashCredential};
use ring;
use std::str;
use tokio_core::reactor::Core;

// This test assumes you have already have an AWS infrastructure running.
// Both table and the KMS key should be present for the test to pass.
#[test]
fn credstash_basic_workflow() {
    // put credential
    let table_name = "credential-store".to_string();
    let app = CredStashClient::new(CredStashCredential::DefaultCredentialsProvider, None).unwrap();
    let mut core = Core::new().unwrap();
    let put_future = app.put_secret(
        table_name.clone(),
        "hello12".to_string(),
        "world12".to_string(),
        None,
        vec![],
        None,
        None,
        ring::hmac::HMAC_SHA256,
    );

    let result = core.run(put_future);
    assert!(result.is_ok());

    // get credential
    let get_future = app.get_secret(table_name.clone(), "hello12".to_string(), vec![], None);
    let result = core.run(get_future).unwrap();
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
    let result = core.run(put_auto_secret_future);
    assert!(result.is_ok());

    // get version
    let get_version_future = app.get_highest_version(table_name.clone(), "hello12".to_string());
    let result = core.run(get_version_future);
    assert_eq!(result.unwrap(), 2);

    // get all secrets
    let get_all_future = app.get_all_secrets(table_name.clone(), vec![], None);
    let result = core.run(get_all_future);
    assert_eq!(result.unwrap().len() >= 1, true);

    // delete credential
    let delete_future = app.delete_secret(table_name, "hello12".to_string());
    let res = core.run(delete_future);
    assert!(res.is_ok());
}
