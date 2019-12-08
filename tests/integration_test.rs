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
    let res = app.put_secret(
        table_name.clone(),
        "hello".to_string(),
        "world".to_string(),
        None,
        None,
        None,
        ring::hmac::HMAC_SHA256,
    );

    assert_eq!(Ok(()), res);

    // get credential
    let res = app
        .get_secret(
            table_name.clone(),
            "hello".to_string(),
            ring::hmac::HMAC_SHA256,
        )
        .unwrap();
    let secret_utf8 = str::from_utf8(&res.dynamo_contents).unwrap();
    assert_eq!("world".to_string(), secret_utf8);

    // delete credential
    let delete_future = app.delete_secret(table_name, "hello".to_string());
    let res = core.run(delete_future);
    assert!(res.is_ok());
}
