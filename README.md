https://docs.rs/rusoto_kms/0.41.0/rusoto_kms/trait.Kms.html

Workflow:

* credstash setup
* create kms key via AWS Console

db:

get_item: https://docs.rs/rusoto_dynamodb/0.41.0/rusoto_dynamodb/trait.DynamoDb.html#tymethod.get_item

kms:

list_keys: https://docs.rs/rusoto_kms/0.41.0/rusoto_kms/trait.Kms.html#tymethod.list_keys

decrypt: https://docs.rs/rusoto_kms/0.41.0/rusoto_kms/trait.Kms.html#tymethod.decrypt

1. fetch master key

get_item
decret data column
d

~/g/rucredstash (master) $ aws-env credstash setup
Creating table...
Waiting for table to be created...
Adding tags...
Table has been created. Go read the README about how to create your KMS key
~/g/rucredstash (master) $ aws-env credstash put hello world
hello has been stored
