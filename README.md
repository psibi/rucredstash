# Rucredstash

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/credstash.svg
[crates-url]: https://crates.io/crates/credstash
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: LICENSE

Rucredstash is a Rust port of [CredStash](https://github.com/fugue/credstash)

It uses a combination of AWS Key Management Service (KMS) and DynamoDB
to store secrets. This is needed when you want to store and retrieve
your credentials (like database password, API Keys etc) securely. A
more [detailed
tutorial](https://www.fpcomplete.com/blog/2017/08/credstash) is here.

This package offers the interface via both CLI and an library way of
accessing it.

## Usage

``` shellsession
$ rucredstash --help
rucredstash 0.1
Sibi Prabakaran
A credential/secret storage system

USAGE:
    rucredstash [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -a, --arn <ARN>                  AWS IAM ARN for AssumeRole
    -m, --mfa_serial <MFA_SERIAL>    Optional MFA hardware device serial number or virtual device ARN
    -p, --profile <PROFILE>          Boto config profile to use when connecting to AWS
    -r, --region <REGION>            the AWS region in which to operate. If a region is not specified, credstash will
                                     use the value of the AWS_DEFAULT_REGION env variable, or if that is not set, the
                                     value in `~/.aws/config`. As a last resort, it will use us-east-1
    -t, --table <TABLE>              DynamoDB table to use for credential storage. If not specified, credstash will use
                                     the value of the CREDSTASH_DEFAULT_TABLE env variable, or if that is not set, the
                                     value `credential-store` will be used

SUBCOMMANDS:
    delete    Delete a credential from the store
    get       Get a credential from the store
    getall    Get all credentials from the store
    help      Prints this message or the help of the given subcommand(s)
    keys      List all keys in the store
    list      List credentials and their versions
    put       Put a credential from the store
    setup     setup the credential store
```

## Usage Examples

The most simple case is to export the proper environment variable and use it:

``` shellsession
$ export AWS_ACCESS_KEY_ID=xxxx
$ export AWS_SECRET_ACCESS_KEY=xxxx
$ rucredstash list
Enter MFA Code: xxxxx
hello            -- version 0000000000000000001 --comment
hellehllobyegood -- version 0000000000000000001 --comment
hello1           -- version 0000000000000000001 --comment
```

Note that `rucredstash` by default uses
[DefaultCredentialsProvider](https://docs.rs/rusoto_credential/0.42.0/rusoto_credential/struct.DefaultCredentialsProvider.html),
so your credentials will be based on that. But it even allows complex
usecase (something which is not possible in the original credstash
program);

``` shellsession
$ export AWS_ACCESS_KEY_ID=xxxx
$ export AWS_SECRET_ACCESS_KEY=xxxx
$ rucredstash --arn arn:aws:iam::786946123934:role/admin --mfa_serial arn:aws:iam::786946123934:mfa/sibi --region us-west-2 list
Enter MFA Code: xxxxx
hello            -- version 0000000000000000001 --comment
hellehllobyegood -- version 0000000000000000001 --comment
hello1           -- version 0000000000000000001 --comment
```

Note that the MFA functionality isn't present in the original
rucredstash. You can also use programs like
[aws-env](https://github.com/fpco/devops-helpers/blob/master/doc/aws/aws-env.md)
and use this tool. Example:

``` shellsession
$ aws-env rucredstash list
hello            -- version 0000000000000000001 --comment
hellehllobyegood -- version 0000000000000000001 --comment
hello1           -- version 0000000000000000001 --comment
```
