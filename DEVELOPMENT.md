# Development notes

## Default values

* table: `credential-store`
* key: `alias/credstash`
* Default digest algorithm: `SHA256`

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

## Decrypt algorithm

Algorithm: AES CTR mode
Key size: 32 bytes

The "key" column you have in DynamoDB is 64 bytes. The first half of
the it is used for AES operation. The second half of it is used as
HMAC key. But the "key" column is encrypted using the master key. You
need to decrypt that first.

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
~/g/rucredstash (v2-release) $ aws-env credstash get hellehllobyegood
dam
~/g/rucredstash (v2-release) $ aws-env credstash keys
hellehllobyegood
~/g/rucredstash (v2-release) $ aws-env credstash list
hellehllobyegood -- version 0000000000000000001 -- comment
~/g/rucredstash (v2-release) $ aws-env credstash put hello world
hello has been stored
~/g/rucredstash (master) $ aws-env credstash getall -f yaml
[aws-env] Assuming role arn:aws:iam::786946123934:role/admin
hellehllobyegood: dam
hello: world
hello1: world1
~/g/rucredstash (master) $ aws-env credstash getall -f csv
hellehllobyegood,dam
hello1,world1
hello,world
~/g/rucredstash (master) $ aws-env credstash getall -f dotenv
HELLEHLLOBYEGOOD='dam'
HELLO='world'
HELLO1='world1'
$ credstash getall > file.json
$ credstash putall @file.json
$ aws-env credstash putall '{"hello":"world", "hi":"bye"}'
```

## CI Tests

Note that CI doesn't run the integration tests as it needs AWS
integration and it isn't free.

For setting up the necessary infrastructure, you would need to do two
things. Make sure you have setup the credentials for your IAM user. I
typically export my access keys:

``` shellsession
export AWS_ACCESS_KEY_ID=REDACTED
export AWS_SECRET_ACCESS_KEY=REDACTED
```

And I use that IAM user to assume another role:

``` shellsession
aws assume-role --role-arn arn:aws:iam::REDACTED:role/admin --role-session-name test-credstash --serial-number arn:aws:iam::REDACTED:mfa/sibi  --token-code MFA_CODE
```

And you will get an output like this:

``` shellsession
{
    "Credentials": {
        "AccessKeyId": "REDACTED",
        "SecretAccessKey": "REDACTED",
        "SessionToken": "REDACTED",
        "Expiration": "2022-01-15T13:48:37+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "REDACTED",
        "Arn": "REDACTED"
    }
}
```

Now you export these environment variables:

``` shellsession
export AWS_ACCESS_KEY_ID=REDACTED
export AWS_SECRET_ACCESS_KEY=REDACTED
export AWS_SESSION_TOKEN=REDACTED
```

Now for creating the table, do:

``` shellsession
rucredstash setup
```

And for creating the KMS key run the terraform code present inside the
tests directory.

Once the above infrastructure is ready, for running the test suite do
this:

```
$ cargo test
$ cd tests
$ ./test.sh
```

## Future TODOs

* Provide cli subcommand to create CMK
  - This feature isn't present in the original credstash
* Remove all the usage of the `expect()` method in the main.rs file.

## Checklist before a new release

- [ ] Update help message in README
- [ ] Run *cargo clippy* (Todo: Integrate with CI)
- [ ] Ran integration tests with AWS infrastructure

## Reference

* https://docs.rs/ring/0.16.9/ring/hmac/struct.Key.html
* https://docs.rs/rusoto_kms/0.41.0/rusoto_kms/trait.Kms.html
* https://docs.rs/rusoto_dynamodb/0.41.0/rusoto_dynamodb/trait.DynamoDb.html
* https://docs.rs/bytes/0.4.12/bytes/struct.Bytes.html
