extern crate base64;
extern crate clap;
extern crate either;
extern crate futures;
extern crate tokio_core;

use clap::{App, Arg, ArgGroup, SubCommand};
use credstash::{CredStashClient, CredstashKey};
use futures::future;
use futures::future::Future;
use futures::future::IntoFuture;
use futures::future::*;
use ring::hmac::Algorithm;
use std::ffi::OsString;
use std::io::{StdoutLock, Write};
mod crypto;
use either::Either;
use ring;
use std::clone::Clone;
use std::io;
use std::str;
use std::string::ToString;
use std::vec::Vec;
use tokio_core::reactor::Core;

// todo: move default type as publicly exported constants
// todo: change to CredstashApp
#[derive(Debug, PartialEq)]
struct RuCredStashApp {
    name: String,
    region_option: Option<String>,
    aws_profile: Option<String>,
    table_name: Option<String>,
    aws_arn: Option<String>,
    action: Action,
}

// todo: handle it properly
fn render_secret(secret: Vec<u8>) -> String {
    match str::from_utf8(&secret) {
        Ok(v) => v.to_string(),
        Err(_) => "".to_string(),
    }
}

fn render_comment(comment: Option<String>) -> String {
    match comment {
        None => "".to_string(),
        Some(val) => val,
    }
}

fn to_algorithm(digest: String) -> Algorithm {
    match digest.as_ref() {
        "SHA1" => ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        "SHA256" => ring::hmac::HMAC_SHA256,
        "SHA384" => ring::hmac::HMAC_SHA384,
        "SHA512" => ring::hmac::HMAC_SHA512,
        _ => panic!("Unsupported digest algorithm: {}", digest),
    }
}

#[derive(Debug, PartialEq)]
enum AutoIncrement {
    AutoIncrement,
}

#[derive(Debug, PartialEq, Clone)]
struct GetAllOpts {
    version: Option<u64>,
    encryption_context: Option<(String, String)>,
}

// todo: implement prompt for secret
// you likely need this to implement: https://github.com/clap-rs/clap/issues/824#issue-203710308
#[derive(Debug, PartialEq)]
struct PutOpts {
    key_id: Option<String>,
    comment: Option<String>,
    version: Either<u64, AutoIncrement>,
    digest_algorithm: Algorithm,
}

#[derive(Debug, PartialEq)]
struct GetOpts {
    noline: bool,
    version: Option<u64>,
}

#[derive(Debug, PartialEq)]
enum Action {
    Delete(String),
    Get(String, Option<(String, String)>, GetOpts),
    GetAll(Option<GetAllOpts>),
    Keys,
    List,
    Put(String, String, Option<(String, String)>, PutOpts),
    Setup,
}

fn get_table_name(table_name: Option<String>) -> String {
    table_name.map_or("credential-store".to_string(), |name| name)
}

// todo: remove hardcoding here
fn handle_action(app: RuCredStashApp, client: CredStashClient) -> () {
    let table_name = get_table_name(app.table_name);
    match app.action {
        Action::Put(credential_name, credential_value, encryption_context, put_opts) => {
            let box_future: Box<dyn Future<Item = _, Error = _>> = match put_opts.version {
                Either::Left(version) => Box::new(client.put_secret(
                    table_name.clone(),
                    credential_name.clone(),
                    credential_value.clone(),
                    put_opts.key_id,
                    encryption_context.clone(),
                    Some(version),
                    put_opts.comment,
                    put_opts.digest_algorithm,
                )),
                Either::Right(_) => Box::new(client.put_secret_auto_version(
                    table_name,
                    credential_name,
                    credential_value,
                    put_opts.key_id,
                    encryption_context,
                    put_opts.comment,
                    put_opts.digest_algorithm,
                )),
            };
            let mut core = Core::new().unwrap();
            match core.run(box_future) {
                Ok(_) => println!("Item putten successfully"),
                Err(err) => eprintln!("Failure: {:?}", err),
            }
        }
        Action::List => {
            let result = client.list_secrets("credential-store".to_string());
            match result {
                Err(err) => println!("Failure: {:?}", err),
                Ok(val) => {
                    let newval = val.clone();
                    let max_name_len: Vec<usize> =
                        newval.into_iter().map(|item| item.name.len()).collect();
                    let max_len = max_name_len
                        .iter()
                        .fold(1, |acc, x| if acc < *x { *x } else { acc });
                    val.into_iter()
                        .map(|item| {
                            println!(
                                "{:width$} -- version {: <10} --comment {}",
                                item.name,
                                item.version,
                                render_comment(item.comment),
                                width = max_len
                            )
                        })
                        .collect::<Vec<()>>();
                }
            }
        }
        Action::Delete(credential) => {
            let result = client.delete_secret("credential-store".to_string(), credential);
            let mut core = Core::new().unwrap();
            match core.run(result) {
                Ok(_) => println!("Item deleted"),
                Err(err) => eprintln!("Failure: {:?}", err),
            }
        }
        Action::Setup => {
            let result = client.create_db_table("test-db".to_string(), "fixme".to_string());
            let mut core = Core::new().unwrap();
            match core.run(result) {
                Err(err) => eprintln!("Failure: {:?}", err),
                Ok(val) => {
                    println!("Creation initiated");
                }
            }
        }
        Action::Keys => {
            let result = client.list_secrets("credential-store".to_string());
            match result {
                Err(err) => eprintln!("Failure: {:?}", err),
                Ok(val) => {
                    let d: Vec<()> = val
                        .into_iter()
                        .map(|item| println!("{}", item.name))
                        .collect();
                }
            }
        }
        Action::Get(credential_name, encryption_context, get_opts) => {
            let mut core = Core::new().unwrap();
            let get_future = client.get_secret(
                table_name,
                credential_name,
                encryption_context,
                get_opts.version,
            );
            match core.run(get_future) {
                Err(err) => eprintln!("Failure: {:?}", err),
                Ok(result) => println!("{:?}", result),
            }
        }
        Action::GetAll(get_opts) => {
            let version = get_opts
                .clone()
                .map(|opts| opts.version)
                .map_or(None, |item| item);
            let encryption_context = get_opts
                .map(|opts| opts.encryption_context)
                .map_or(None, |item| item);
            let get_future = client.get_all_secrets(table_name, encryption_context, version);
            let mut core = Core::new().unwrap();
            match core.run(get_future) {
                Err(err) => eprintln!("Failure: {:?}", err),
                Ok(val) => val
                    .into_iter()
                    .map(|item| {
                        println!(
                            "fetched: {} val: {}",
                            item.dynamo_name,
                            render_secret(item.dynamo_contents)
                        )
                    })
                    .collect(),
            }
        }
    }
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
            .arg(Arg::with_name("noline").short("n").long("noline").help("Don't append newline to returned value (useful in scripts or with binary files)"))
            .arg(Arg::with_name("version").short("v").long("version").value_name("VERSION").help("Get a specific version of the credential (defaults to the latest version"));

        let get_all_command = SubCommand::with_name("getall")
            .about("Get all credentials from the store")
            .arg(Arg::with_name("context")
                 .help("encryption context key/value pairs associated with the credential in the form of key=value")
            ).arg(Arg::with_name("version").short("v").long("version").value_name("VERSION").help("Get a specific version of the credential (defaults to the latest version"));

        let keys_command = SubCommand::with_name("keys").about("List all keys in the store");

        let list_command =
            SubCommand::with_name("list").about("List credentials and their versions");

        let put_command = SubCommand::with_name("put")
            .about("Put a credential from the store")
            .arg(Arg::with_name("credential").help("the name of the credential to store").required(true))
            .arg(Arg::with_name("value").help("the value of the credential to store").required(true).conflicts_with("prompt"))
            .arg(Arg::with_name("context").help("encryption context key/value pairs associated with the credential in the form of key=value"))
            .arg(Arg::with_name("key").short("k").long("key").value_name("KEY").help("the KMS key-id of the master key to use. Defaults to alias/credstash"))
            .arg(Arg::with_name("comment").short("c").long("comment").value_name("COMMENT").help("Include reference information or a comment about value to be stored."))
            .arg(Arg::with_name("version").short("v").long("version").value_name("VERSION").help("Put a specific version of the credential (update the credential; defaults to version `1`)"))            
            .arg(Arg::with_name("autoversion").short("a").long("autoversion").help("Automatically increment the version of the credential to be stored.").conflicts_with("version"))
            .arg(Arg::with_name("digest").short("d").long("digest").value_name("DIGEST").help("the hashing algorithm used to to encrypt the data. Defaults to SHA256.").possible_values(&["SHA1", "SHA256", "SHA384", "SHA512"]).case_insensitive(true))
            .arg(Arg::with_name("prompt").short("p").long("prompt").help("Prompt for secret").takes_value(false));

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
                let encryption_context: Option<(String, String)> =
                    context.map_or(None, |e| split_context_to_tuple(e));
                let version = get_matches.value_of("version").map(|ver| {
                    ver.to_string()
                        .parse::<u64>()
                        .expect("Version should be positive integer")
                });
                let get_opts = GetOpts {
                    noline: get_matches.is_present("noline"),
                    version,
                };
                Action::Get(credential, encryption_context, get_opts)
            }
            ("getall", None) => Action::GetAll(None),
            ("getall", Some(get_matches)) => {
                let context: Option<String> =
                    get_matches.value_of("context").map(|e| e.to_string());
                let encryption_context: Option<(String, String)> =
                    context.map_or(None, |e| split_context_to_tuple(e));
                let version = get_matches.value_of("version").map(|ver| {
                    ver.to_string()
                        .parse::<u64>()
                        .expect("Version should be positive integer")
                });
                let getall_opts = GetAllOpts {
                    version,
                    encryption_context,
                };
                Action::GetAll(Some(getall_opts))
            }
            ("keys", _) => Action::Keys,
            ("list", _) => Action::List,
            ("setup", _) => Action::Setup,
            ("put", Some(put_matches)) => {
                // todo: fix all unwrap
                let credential_name: String =
                    put_matches.value_of("credential").unwrap().to_string();
                let credential_value: String = {
                    let mut value = String::new();
                    let get_input = put_matches.is_present("prompt");
                    if get_input {
                        print!("{}: ", credential_name);
                        let stdout = io::stdout();
                        let mut std_handle = stdout.lock();
                        std_handle.flush().ok();
                        // todo: trim newline
                        // https://blog.v-gar.de/2019/04/rust-remove-trailing-newline-after-input/
                        io::stdin()
                            .read_line(&mut value)
                            .expect("Failed to read from stdin");
                    } else {
                        value = put_matches.value_of("value").unwrap().to_string();
                    }
                    value
                };
                let key_id = put_matches.value_of("key").map(|e| e.to_string());
                let comment = put_matches.value_of("comment").map(|e| e.to_string());
                let version: Either<u64, AutoIncrement> = {
                    let version_option = put_matches.value_of("option").map_or(1, |e| {
                        e.to_string()
                            .parse::<u64>()
                            .expect("Version should be positive integer")
                    });
                    let autoversion = put_matches.is_present("autoversion");
                    if autoversion {
                        Either::Right(AutoIncrement::AutoIncrement)
                    } else {
                        Either::Left(version_option)
                    }
                };
                let digest_algorithm = {
                    let algorithm = put_matches
                        .value_of("digest")
                        .map(|e| to_algorithm(e.to_string()));
                    match algorithm {
                        Some(algo) => algo,
                        None => ring::hmac::HMAC_SHA256,
                    }
                };
                let put_opts = PutOpts {
                    key_id,
                    comment,
                    version,
                    digest_algorithm,
                };
                let context: Option<String> =
                    put_matches.value_of("context").map(|e| e.to_string());
                let encryption_context: Option<(String, String)> =
                    context.map_or(None, |e| split_context_to_tuple(e));
                Action::Put(
                    credential_name,
                    credential_value,
                    encryption_context,
                    put_opts,
                )
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

fn split_context_to_tuple(encryption_context: String) -> Option<(String, String)> {
    let context: Vec<&str> = encryption_context.split('=').collect();
    match context.len() {
        0 => None,
        1 => panic!(
            "error: argument context: {} is not the form of key=value",
            encryption_context
        ),
        2 => Some((context[0].to_string(), context[1].to_string())),
        _ => panic!(
            "error: argument context: {} is not the form of key=value",
            encryption_context
        ),
    }
}

fn main() {
    let test = RuCredStashApp::new();
    println!("Hello, world {:?}", test);
    let client = CredStashClient::new();
    handle_action(test, client);

    // Get version
    // let version = client
    //     .get_highest_version("credential-store".to_string(), "hello".to_string())
    //     .unwrap();
    // println!("{}", version);

    // Put secret
    // let test = client.put_secret(
    //     "credential-store".to_string(),
    //     "testkey".to_string(),
    //     "0000000000000000001".to_string(),
    //     "testvalue".to_string(),
    //     None,
    //     None,
    //     ring::hmac::HMAC_SHA256,
    // );

    // println!("{:?}", test.unwrap());

    // Get Secret
    // let dynamo_row = client
    //     .get_secret(
    //         "credential-store".to_string(),
    //         "testkey".to_string(),
    //         ring::hmac::HMAC_SHA256,
    //     )
    //     .unwrap();

    // let secret = CredStashClient::decrypt_secret(dynamo_row);
    // let secret_utf8 = match str::from_utf8(&secret) {
    //     Ok(v) => v,
    //     Err(e) => panic!("invalid utf8 sequence: {}", e),
    // };

    // println!("{}", secret_utf8);

    // Delete secret
    // let dynamo_row = client
    //     .delete_secret("credential-store".to_string(), "hello".to_string())
    //     .unwrap();

    // list secrets
    // let dynamo_row = client
    //     .list_secrets("credential-store".to_string(), ring::hmac::HMAC_SHA256)
    //     .unwrap();
    // println!("{:?}", dynamo_row);
}
