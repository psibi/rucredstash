extern crate credstash;

use credstash::CredStashClient;
use ring;
use std::str;
use tokio_core::reactor::Core;

#[test]
fn credstash_basic_workflow() {
    // put credential
    let table_name = "credential-store".to_string();
    let app = CredStashClient::new();
    let mut core = Core::new().unwrap();
    let put_future = app.put_secret(
        table_name.clone(),
        "hello12".to_string(),
        "world12".to_string(),
        None,
        None,
        None,
        ring::hmac::HMAC_SHA256,
    );

    let result = core.run(put_future);
    assert!(result.is_ok());

    // get credential
    let get_future = app.get_secret(
        table_name.clone(),
        "hello12".to_string(),
        ring::hmac::HMAC_SHA256,
    );
    let result = core.run(get_future).unwrap();
    let secret_utf8 = str::from_utf8(&result.dynamo_contents).unwrap();
    assert_eq!("world12".to_string(), secret_utf8);

    // delete credential
    let delete_future = app.delete_secret(table_name, "hello12".to_string());
    let res = core.run(delete_future);
    assert!(res.is_ok());
}
