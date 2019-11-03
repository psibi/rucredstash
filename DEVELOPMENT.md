## Table Structure

## getSecret

* Retrieve data from DynamoDB

Sample response:

Some([{"version": AttributeValue { b: None, bool: None, bs: None, l: None, m: None, n: None, ns: None, null: None, s: Some("0000000000000000001"), ss: None }, "name": AttributeValue { b: None, bool: None, bs: None, l: None, m: None, n: None, ns: None, null: None, s: Some("hello"), ss: None }, "contents": AttributeValue { b: None, bool: None, bs: None, l: None, m: None, n: None, ns: None, null: None, s: Some("/RQIo98="), ss: None }, "digest": AttributeValue { b: None, bool: None, bs: None, l: None, m: None, n: None, ns: None, null: None, s: Some("SHA256"), ss: None }, "hmac": AttributeValue { b: Some(b"e409e4bbf5e7bd7b95d0d3642a4e1e20f4ebb0a40e7ba46da0d116ed32792367"), bool: None, bs: None, l: None, m: None, n: None, ns: None, null: None, s: None, ss: None }, "key": AttributeValue { b: None, bool: None, bs: None, l: None, m: None, n: None, ns: None, null: None, s: Some("AQIBAHh2LgYkISZhCX5HzfHk6rC/VgyqMMsZiABVXow4+2d6igEDotHJ1s4ABPG5NXkZSQtHAAAAojCBnwYJKoZIhvcNAQcGoIGRMIGOAgEAMIGIBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDD563GAbyfxh4Oq6PwIBEIBbmyvxBNaGXmXvYmwEax4mFkgQnfxsuI0pxmf0qVyB5mTvUkxwc1u1LOSRzCzUdjmZ4O9FxPLtqNxrb3mMroUHhLjNGjdGPySukO8ICb1egkwDRirys9/H39o4yw=="), ss: None }}])

content: Some("/RQIo98=")
key: Some("AQIBAHh2LgYkISZhCX5HzfHk6rC/VgyqMMsZiABVXow4+2d6igEDotHJ1s4ABPG5NXkZSQtHAAAAojCBnwYJKoZIhvcNAQcGoIGRMIGOAgEAMIGIBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDD563GAbyfxh4Oq6PwIBEIBbmyvxBNaGXmXvYmwEax4mFkgQnfxsuI0pxmf0qVyB5mTvUkxwc1u1LOSRzCzUdjmZ4O9FxPLtqNxrb3mMroUHhLjNGjdGPySukO8ICb1egkwDRirys9/H39o4yw==")

content:

Note:

* The value "key" is base64 encoded.
* The value "contents" is base64 encoded.
* The value "hmac" is hex encoded.

* Decrypt

## Decrypt algorithm

Algorithm: AES CTR mode
Key size: 32 bytes

* Validate HMAC
* Decrypt it

The "key" column you have in DynamoDB is 64 bytes. The first half of
the it is used for AES operation. The second half of it is used as
HMAC key. But the "key" column is encrypted using the master key. You
need to decrypt that first.



