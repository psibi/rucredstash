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
~/g/rucredstash (master) $ aws-env credstash getall
{
    "dog": "cat",
    "hello": "world\n",
    "testkey": "testvalue\n",
    "testkey1": "testvalue1\n"
}
~/g/rucredstash (master) $ aws-env credstash list
dog      -- version 0000000000000000001 -- comment
hello    -- version 0000000000000000001 -- comment
testkey  -- version 0000000000000000001 -- comment
testkey1 -- version 0000000000000000001 -- comment
$ aws-env credstash put dog cat2
dog version 0000000000000000001 is already in the credential store. Use the -v flag to specify a new version
~/g/rucredstash (master) $ aws-env credstash keys
dog
hello
testkey
testkey1
~/g/rucredstash (master) $ aws-env credstash put hello1 world1 --comment "dummy comment"
hello1 has been stored
~
