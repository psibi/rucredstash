## Table Structure

## Default values

table: `credential-store`
key: `alias/credstash`
Default digest algorithm: `SHA256`

## Implementation notes

* The value "key" is base64 encoded.
* The value "contents" is base64 encoded.
* The value "hmac" is hex encoded.
* https://stackoverflow.com/a/52016942/1651941

## Put algorithm

* Generate 64 bytes key. Return both PlainText key and CipherTextBlob part of the key.
  - Use this function: https://docs.rs/rusoto_kms/0.41.0/rusoto_kms/trait.Kms.html#tymethod.generate_data_key
* Split the key: First half is used for AES, the second half is used for HMAC
* Encrypt the value using AES algorithm (with the first half of the key).
* Calculate HMAC of the encrypted text using the hmac key and proper digest method.
* Base64 encode the CipherTextBlob.
* Base64 encode the encrypted text.
* Hex encode the HMAC text.
* Create a new vesion.
* Optionally, see if we need to include comment.
* Add new row.
  - Use this function: https://docs.rs/rusoto_dynamodb/0.41.0/rusoto_dynamodb/trait.DynamoDb.html#tymethod.put_item
  - Have this condition: https://github.com/fugue/credstash/blob/014d96bbde5dc474e155383760bb4b7f6078f761/credstash.py#L316

## Done

* Miniature version of get algorithm
* Miniature version of put algorithm
* Full version of delete algorithm (At least that's what I believe)
* Full version of keys subcommand
* Full version of list subcommand
* Minimal version of getall subcommand
* Minimal version of setup subcommand

## Missing

* putall

## Decrypt algorithm

Algorithm: AES CTR mode
Key size: 32 bytes

The "key" column you have in DynamoDB is 64 bytes. The first half of
the it is used for AES operation. The second half of it is used as
HMAC key. But the "key" column is encrypted using the master key. You
need to decrypt that first.

## Questions

* What happens if you put the same key multiple times ?

## Todo:

* encryption context for put/get
* Next step: Implement put_secret and main.rs change with full arguments passed
* Further: Slowly convert everything into a future based interface

Name change:

credential_name
credential_value

## AWS Queries

AWS Quering for getting latest version:

``` shellsession
$ aws-env aws dynamodb query --table-name credential-store --projection-expression "version" --key-condition-expression "#n = :nameValue" --expression-attribute-names '{"#n": "name"}' --expression-attribute-values '{":nameValue":{"S":"hello"}}'
```

## Credstash behavior

We try to stay close to the behavior of credstash as much as possible.

``` shellsession
~/g/rucredstash (master) $ aws-env credstash getall
{
    "hello": "world"
}
```

Todo: Test the above with encryption context, different versions.

## Things to do in Future version

* Wildcard handling

## Reference

* https://docs.rs/ring/0.16.9/ring/hmac/struct.Key.html
* https://docs.rs/rusoto_kms/0.41.0/rusoto_kms/trait.Kms.html
* https://docs.rs/rusoto_dynamodb/0.41.0/rusoto_dynamodb/trait.DynamoDb.html
* https://docs.rs/bytes/0.4.12/bytes/struct.Bytes.html
* https://github.com/fugue/credstash/blob/master/credstash.py
