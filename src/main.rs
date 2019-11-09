extern crate base64;
extern crate clap;

use base64::decode;
use clap::{App, Arg, SubCommand};
use rucredstash::CredStashClient;
use std::ffi::OsString;
mod crypto;

#[derive(Debug, PartialEq)]
struct RuCredStashApp {
    name: String,
    region_option: Option<String>,
    aws_profile: Option<String>,
    table_name: Option<String>,
    aws_arn: Option<String>,
    action: Action,
}

#[derive(Debug, PartialEq)]
enum Action {
    Delete(String),
    Get(String, Option<String>),
    GetAll,
    Keys,
    List,
    Put(String, String, Option<String>),
    Setup,
}

impl RuCredStashApp {
    fn new() -> Self {
        Self::new_from(std::env::args_os().into_iter()).unwrap_or_else(|e| e.exit())
    }

    fn new_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let app: App = App::new("rucredstash")
            .version("0.1")
            .about("A credential/secret storage system")
            .author("Sibi Prabakaran");

        let region_arg = Arg::with_name("region")
            .long("region")
            .short("r")
            .value_name("REGION")
            .help(
                "the AWS region in which to operate. If a region is \
                 not specified, credstash will use the value of the \
                 AWS_DEFAULT_REGION env variable, or if that is not \
                 set, the value in `~/.aws/config`. As a last resort, \
                 it will use us-east-1",
            );

        let table_arg = Arg::with_name("table")
            .long("table")
            .short("t")
            .value_name("TABLE")
            .help(
                "DynamoDB table to use for credential storage. If \
                 not specified, credstash will use the value of the \
                 CREDSTASH_DEFAULT_TABLE env variable, or if that is \
                 not set, the value `credential-store` will be used",
            );

        let profile_arg = Arg::with_name("profile")
            .long("profile")
            .short("p")
            .value_name("PROFILE")
            .help("Boto config profile to use when connecting to AWS");

        let arn_arg = Arg::with_name("arn")
            .long("arn")
            .short("n")
            .value_name("ARN")
            .help("AWS IAM ARN for AssumeRole");

        let del_command = SubCommand::with_name("delete")
            .about("Delete a credential from the store")
            .arg(Arg::with_name("credential").help("Delete a credential from the store"));

        let get_command = SubCommand::with_name("get")
            .about("Get a credential from the store")
            .arg(
                Arg::with_name("credential")
                    .help("the name of the credential to get")
                    .required(true)
            ).arg(
                Arg::with_name("context")
                    .help("encryption context key/value pairs associated with the credential in the form of key=value")

            )
            ;

        let get_all_command = SubCommand::with_name("getall")
            .about("Get all credentials from the store")
            .arg(Arg::with_name("secret").help("The secret to retrieve"));

        let keys_command = SubCommand::with_name("keys").about("List all keys in the store");

        let list_command =
            SubCommand::with_name("list").about("List credentials and their versions");

        let put_command = SubCommand::with_name("put")
            .about("Put a credential from the store")
            .arg(Arg::with_name("credential").help("the name of the credential to store"))
            .arg(Arg::with_name("value").help("the value of the credential to store"))
            .arg(Arg::with_name("context").help("encryption context key/value pairs associated with the credential in the form of key=value"));

        let put_all_command = SubCommand::with_name("putall")
            .about("Put credentials from json into the store")
            .arg(Arg::with_name("secret").help("The secret to retrieve"));

        let setup_command = SubCommand::with_name("setup").about("setup the credential store");

        let app = app
            .arg(region_arg)
            .arg(table_arg)
            .arg(profile_arg)
            .arg(arn_arg)
            .subcommand(del_command)
            .subcommand(get_command)
            .subcommand(get_all_command)
            .subcommand(keys_command)
            .subcommand(list_command)
            .subcommand(put_command)
            .subcommand(put_all_command)
            .subcommand(setup_command);
        // extract the matches
        let matches: clap::ArgMatches = app.get_matches_from_safe(args)?;

        let region: Option<&str> = matches.value_of("region");
        let action_value: Action = match matches.subcommand() {
            ("get", Some(get_matches)) => {
                let credential: String = get_matches.value_of("credential").unwrap().to_string();
                let context = get_matches.value_of("context").map(|e| e.to_string());
                Action::Get(credential, context)
            }
            ("getall", _) => Action::GetAll,
            ("keys", _) => Action::Keys,
            ("list", _) => Action::List,
            ("setup", _) => Action::Setup,
            ("put", Some(put_matches)) => {
                let credential: String = put_matches.value_of("credential").unwrap().to_string();
                let value: String = put_matches.value_of("value").unwrap().to_string();
                let context = put_matches.value_of("context").map(|e| e.to_string());
                Action::Put(credential, value, context)
            }
            ("delete", Some(del_matches)) => {
                let credential: String = del_matches.value_of("credential").unwrap().to_string();
                Action::Delete(credential)
            }
            _ => unreachable!(),
        };

        Ok(RuCredStashApp {
            name: "Hello".to_string(),
            region_option: region.map(|r| r.to_string()),
            aws_profile: matches.value_of("profile").map(|r| r.to_string()),
            aws_arn: matches.value_of("arn").map(|r| r.to_string()),
            table_name: matches.value_of("table").map(|r| r.to_string()),
            action: action_value,
        })
        // panic!("undefined");
    }
}

fn main() {
    let test = RuCredStashApp::new();
    println!("Hello, world {:?}", test);
    let a = CredStashClient::new();
    println!("debug");

    let b = a.get_secret("credential-store".to_string(), "hello".to_string());
    let c = CredStashClient::decrypt_secret(b);
    println!("{:?}", c);

    // let key_data = "AQIBAHh2LgYkISZhCX5HzfHk6rC/VgyqMMsZiABVXow4+2d6igEDotHJ1s4ABPG5NXkZSQtHAAAAojCBnwYJKoZIhvcNAQcGoIGRMIGOAgEAMIGIBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDD563GAbyfxh4Oq6PwIBEIBbmyvxBNaGXmXvYmwEax4mFkgQnfxsuI0pxmf0qVyB5mTvUkxwc1u1LOSRzCzUdjmZ4O9FxPLtqNxrb3mMroUHhLjNGjdGPySukO8ICb1egkwDRirys9/H39o4yw==".to_string();
    // let content = "/RQIo98=".to_string();
    // let key_data_b64 = decode(&key_data).unwrap();
    // let aes_key: Vec<u8> = key_data_b64[0..111].to_owned();
    // // let aes_key = key_data_b64[0..111];
    // let conent_b64: Vec<u8> = decode(&content).unwrap().to_owned();
    // let crypto_context = crypto::Crypto::new();
    // println!("{:?}", key_data.len());
    // let v = crypto_context.aes_decrypt_ctr3(conent_b64, aes_key);
    // println!("{:?}", v);
    // todo: use the master key to decrypt it
}
