use clap::error::ErrorKind::{DisplayHelp, DisplayVersion};
use clap::{Arg, Command};
use credstash::{CredStashClient, CredStashCredential};
use either::Either;
use futures::future::join_all;
use ring::hmac::Algorithm;
use rusoto_core::region::Region;
use rusoto_dynamodb::AttributeValue;
use serde_json::{map::Map, to_string_pretty, Value};
use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::Write;
use std::str::{self, FromStr};

#[derive(Debug, PartialEq, Clone)]
struct CredstashApp {
    region: Option<String>,
    table_name: Option<String>,
    credential: CredStashCredential,
    action: Action,
}

#[derive(Debug)]
pub enum CredStashAppError {
    VersionError(String),
    ClapError(clap::Error),
    MissingEnv(String),
    InsufficientContext(String),
    InvalidArguments(String),
    MissingCredential,
    MissingCredentialValue,
    DigestAlgorithmNotSupported(String),
    ClientError(credstash::CredStashClientError),
    InvalidAction(String),
    ParseError(String),
    IOError(String),
    InsertionError(String),
}

#[derive(Debug, PartialEq, Clone)]
enum AutoIncrement {
    AutoIncrement,
}

#[derive(Debug, PartialEq, Clone)]
enum ExportOption {
    Json,
    Yaml,
    Csv,
    DotEnv,
}

#[derive(Debug, PartialEq, Clone)]
struct GetAllOpts {
    version: Option<u64>,
    encryption_context: Vec<(String, String)>,
    export: ExportOption,
}

#[derive(Debug, PartialEq, Clone)]
struct PutOpts {
    key_id: Option<String>,
    comment: Option<String>,
    version: Either<u64, AutoIncrement>,
    digest_algorithm: Algorithm,
}

#[derive(Debug, PartialEq, Clone)]
struct Credential {
    name: String,
    value: String,
}

#[derive(Debug, PartialEq, Clone)]
struct PutAllOpts {
    key_id: Option<String>,
    comment: Option<String>,
    version: Either<u64, AutoIncrement>,
    digest_algorithm: Algorithm,
    content: Vec<Credential>,
    encryption_context: Vec<(String, String)>,
}

#[derive(Debug, PartialEq, Clone)]
struct SetupOpts {
    tags: Vec<(String, String)>,
}

#[derive(Debug, PartialEq, Clone)]
struct GetOpts {
    noline: bool,
    version: Option<u64>,
}

#[derive(Debug, PartialEq, Clone)]
enum Action {
    Delete(String),
    Get(String, Vec<(String, String)>, GetOpts),
    GetAll(Option<GetAllOpts>),
    Keys,
    List,
    Put(String, String, Vec<(String, String)>, PutOpts),
    PutAll(PutAllOpts),
    Setup(SetupOpts),
    Invalid(String),
}

fn parse_credential(content: String) -> Result<Vec<Credential>, CredStashAppError> {
    let credential: serde_json::Value = serde_json::from_str(&content)?;
    let mut credential_value = vec![];
    let mut result = true;
    match credential {
        serde_json::Value::Object(val) => {
            let msg = format!(
                "JSON parsing issue. Expecting an object of key value pairs, but instead got {}",
                content
            );
            for (key, value) in val {
                if value.is_string() {
                    let secret_value = value
                        .as_str()
                        .map_or(Err(CredStashAppError::ParseError(msg.clone())), |val| {
                            Ok(val.to_string())
                        })?;
                    credential_value.push(Credential {
                        name: key,
                        value: secret_value,
                    });
                } else {
                    result = false;
                }
            }
        }
        _ => {
            result = false;
        }
    }
    if result {
        Ok(credential_value)
    } else {
        let msg = format!(
            "JSON parsing issue. Expecting an object of key value pairs, but instead got {}",
            content
        );
        Err(CredStashAppError::ParseError(msg))
    }
}

#[test]
fn parse_credential_check() {
    let result = vec![
        Credential {
            name: "hello".to_string(),
            value: "world".to_string(),
        },
        Credential {
            name: "hi".to_string(),
            value: "bye".to_string(),
        },
    ];
    assert_eq!(
        parse_credential(r#"{"hello":"world", "hi":"bye"}"#.to_string()).unwrap(),
        result
    );
}

fn render_secret(secret: Vec<u8>) -> Result<String, CredStashAppError> {
    match str::from_utf8(&secret) {
        Ok(v) => Ok(v.to_string()),
        Err(err) => Err(CredStashAppError::ParseError(format!(
            "Decode failure: {}",
            err
        ))),
    }
}

fn render_comment(comment: Option<String>) -> String {
    comment.unwrap_or_else(|| "".to_string())
}

fn to_algorithm(digest: String) -> Result<Algorithm, CredStashAppError> {
    match digest.as_ref() {
        "SHA1" => Ok(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
        "SHA256" => Ok(ring::hmac::HMAC_SHA256),
        "SHA384" => Ok(ring::hmac::HMAC_SHA384),
        "SHA512" => Ok(ring::hmac::HMAC_SHA512),
        _ => Err(CredStashAppError::DigestAlgorithmNotSupported(format!(
            "Unsupported digest algorithm: {}",
            digest
        ))),
    }
}

fn get_table_name(table_name: Option<String>) -> String {
    table_name.map_or("credential-store".to_string(), |name| name)
}

async fn handle_action(
    app: CredstashApp,
    client: CredStashClient,
) -> Result<(), CredStashAppError> {
    let table_name = get_table_name(app.table_name);
    match app.action {
        Action::PutAll(putall_opts) => match putall_opts.version {
            Either::Left(version) => {
                let result = join_all(putall_opts.content.clone().into_iter().map(|item| {
                    client.put_secret(
                        table_name.clone(),
                        item.name,
                        item.value,
                        putall_opts.key_id.clone(),
                        putall_opts.encryption_context.clone(),
                        Some(version),
                        putall_opts.comment.clone(),
                        putall_opts.digest_algorithm,
                    )
                }))
                .await;
                let mut exit_status = true;
                for (status, credential) in result.iter().zip(putall_opts.content.iter()) {
                    if status.is_ok() {
                        println!("{} has been stored", credential.name);
                    } else {
                        exit_status = false;
                        eprintln!("Error in storing the credential {}", credential.name)
                    }
                }
                if exit_status {
                    Ok(())
                } else {
                    Err(CredStashAppError::InsertionError(
                        "Error in put operation for the credentails".to_string(),
                    ))
                }
            }
            Either::Right(_) => {
                let result = join_all(putall_opts.content.clone().into_iter().map(|item| {
                    client.put_secret_auto_version(
                        table_name.clone(),
                        item.name,
                        item.value,
                        putall_opts.key_id.clone(),
                        putall_opts.encryption_context.clone(),
                        putall_opts.comment.clone(),
                        putall_opts.digest_algorithm,
                    )
                }))
                .await;
                let mut exit_status = true;
                for (status, credential) in result.iter().zip(putall_opts.content.iter()) {
                    if status.is_ok() {
                        println!("{} has been stored", credential.name);
                    } else {
                        exit_status = false;
                        eprintln!("Error in storing the credential {}", credential.name)
                    }
                }
                if exit_status {
                    Ok(())
                } else {
                    Err(CredStashAppError::InsertionError(
                        "Error in put operation for the credentails".to_string(),
                    ))
                }
            }
        },
        Action::Put(credential_name, credential_value, encryption_context, put_opts) => {
            match put_opts.version {
                Either::Left(version) => {
                    client
                        .put_secret(
                            table_name.clone(),
                            credential_name.clone(),
                            credential_value.clone(),
                            put_opts.key_id,
                            encryption_context.clone(),
                            Some(version),
                            put_opts.comment,
                            put_opts.digest_algorithm,
                        )
                        .await?
                }
                Either::Right(_) => {
                    client
                        .put_secret_auto_version(
                            table_name,
                            credential_name.clone(),
                            credential_value,
                            put_opts.key_id,
                            encryption_context,
                            put_opts.comment,
                            put_opts.digest_algorithm,
                        )
                        .await?
                }
            };
            println!("{} has been stored", credential_name);
            Ok(())
        }
        Action::List => {
            let items = client.list_secrets(table_name).await?;
            let max_name_len: Vec<usize> = items.iter().map(|item| item.name.len()).collect();
            let max_len = max_name_len
                .iter()
                .fold(1, |acc, x| if acc < *x { *x } else { acc });
            for item in items {
                println!(
                    "{:width$} -- version {: <10} --comment {}",
                    item.name,
                    item.version,
                    render_comment(item.comment),
                    width = max_len
                );
            }
            Ok(())
        }
        Action::Delete(credential) => {
            let items = client.delete_secret(table_name, credential.clone()).await?;
            for item in items {
                println!(
                    "Deleting {} {}",
                    credential,
                    render_version(item.attributes)
                );
            }
            Ok(())
        }
        Action::Setup(setup_opts) => {
            client.create_db_table(table_name, setup_opts.tags).await?;
            println!("Creation initiated");
            Ok(())
        }

        Action::Keys => {
            let items = client.list_secrets(table_name).await?;
            for item in items {
                println!("{}", item.name)
            }
            Ok(())
        }

        Action::Get(credential_name, encryption_context, get_opts) => {
            let item = client
                .get_secret(
                    table_name,
                    credential_name,
                    encryption_context,
                    get_opts.version,
                )
                .await?;
            if get_opts.noline {
                print!("{}", render_secret(item.credential_value)?)
            } else {
                println!("{}", render_secret(item.credential_value)?)
            }
            Ok(())
        }
        Action::GetAll(get_opts) => {
            let version = get_opts.clone().map(|opts| opts.version).unwrap_or(None);
            let encryption_context = get_opts
                .clone()
                .map(|opts| opts.encryption_context)
                .unwrap_or_default();
            let val = client
                .get_all_secrets(table_name, encryption_context, version)
                .await?;
            match get_opts {
                None => (),
                Some(opts) => match opts.export {
                    ExportOption::Json => render_json_credstash_item(val)?,
                    ExportOption::Yaml => render_yaml_credstash_item(val)?,
                    ExportOption::Csv => render_csv_credstash_item(val)?,
                    ExportOption::DotEnv => render_dotenv_credstash_item(val)?,
                },
            }
            Ok(())
        }
        Action::Invalid(msg) => Err(CredStashAppError::InvalidAction(msg)),
    }
}

fn render_csv_credstash_item(val: Vec<credstash::CredstashItem>) -> Result<(), CredStashAppError> {
    for item in val {
        println!(
            "{},{}",
            item.credential_name,
            render_secret(item.credential_value)?
        )
    }
    Ok(())
}

fn render_dotenv_credstash_item(
    val: Vec<credstash::CredstashItem>,
) -> Result<(), CredStashAppError> {
    for item in val {
        println!(
            "{}='{}'",
            item.credential_name,
            render_secret(item.credential_value)?
        )
    }
    Ok(())
}

fn render_yaml_credstash_item(val: Vec<credstash::CredstashItem>) -> Result<(), CredStashAppError> {
    for item in val {
        println!(
            "{}: {}",
            item.credential_name,
            render_secret(item.credential_value)?
        )
    }
    Ok(())
}

fn render_json_credstash_item(val: Vec<credstash::CredstashItem>) -> Result<(), CredStashAppError> {
    let mut items: Map<_, _> = Map::new();
    for item in val {
        let credential_value = render_secret(item.credential_value)?;
        items.insert(item.credential_name, Value::String(credential_value));
    }
    let result: Result<String, _> = to_string_pretty(&Value::Object(items));
    match result {
        Ok(val) => {
            println!("{}", val);
            Ok(())
        }
        Err(err) => {
            let err_msg = format!("Serde JSON error: {}", err);
            Err(CredStashAppError::ParseError(err_msg))
        }
    }
}

impl From<clap::Error> for CredStashAppError {
    fn from(error: clap::Error) -> Self {
        CredStashAppError::ClapError(error)
    }
}

impl From<std::io::Error> for CredStashAppError {
    fn from(error: std::io::Error) -> Self {
        CredStashAppError::IOError(error.to_string())
    }
}

impl From<credstash::CredStashClientError> for CredStashAppError {
    fn from(error: credstash::CredStashClientError) -> Self {
        CredStashAppError::ClientError(error)
    }
}

impl From<serde_json::error::Error> for CredStashAppError {
    fn from(error: serde_json::error::Error) -> Self {
        CredStashAppError::ParseError(error.to_string())
    }
}

impl CredstashApp {
    fn new() -> Result<Self, CredStashAppError> {
        Self::new_from(std::env::args_os())
    }

    fn new_from<I, T>(args: I) -> Result<Self, CredStashAppError>
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let version: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
        let app: Command = Command::new("rucredstash")
            .version(version.map_or(
                Err(CredStashAppError::MissingEnv(
                    "CARGO_PKG_VERSION environment variable not present".to_string(),
                )),
                Ok,
            )?)
            .about("A credential/secret storage system")
            .author("Sibi Prabakaran");

        let region_arg = Arg::new("region")
            .long("region")
            .short('r')
            .value_name("REGION")
            .help(
                "the AWS region in which to operate. If a region is \
                 not specified, credstash will use the value of the \
                 AWS_DEFAULT_REGION env variable, or if that is not \
                 set, the value in `~/.aws/config`. As a last resort, \
                 it will use us-east-1",
            );

        let table_arg = Arg::new("table")
            .long("table")
            .short('t')
            .value_name("TABLE")
            .help(
                "DynamoDB table to use for credential storage. If \
                 not specified, credstash will use the value of the \
                 CREDSTASH_DEFAULT_TABLE env variable, or if that is \
                 not set, the value `credential-store` will be used",
            );

        let profile_arg = Arg::new("profile")
            .long("profile")
            .short('p')
            .value_name("PROFILE")
            .help("Boto config profile to use when connecting to AWS");

        let arn_arg = Arg::new("arn")
            .long("arn")
            .short('a')
            .value_name("ARN")
            .help("AWS IAM ARN for AssumeRole")
            .conflicts_with("profile");

        let mfa_arg = Arg::new("mfa")
            .long("mfa_serial")
            .short('m')
            .value_name("MFA_SERIAL")
            .help("Optional MFA hardware device serial number or virtual device ARN")
            .conflicts_with("profile");

        let del_command = Command::new("delete")
            .about("Delete a credential from the store")
            .arg(
                Arg::new("credential")
                    .help("Delete a credential from the store")
                    .required(true),
            );

        let get_command = Command::new("get")
            .about("Get a credential from the store")
            .arg(
                Arg::new("credential")
                    .help("the name of the credential to get")
                    .required(true)
            ).arg(
                Arg::new("context")
                    .help("encryption context key/value pairs associated with the credential in the form of key=value")
                    .action(clap::ArgAction::Append)
	    )
            .arg(Arg::new("noline").short('n').long("noline").help("Don't append newline to returned value (useful in scripts or with binary files)"))
            .arg(Arg::new("version").short('v').long("version").value_name("VERSION").help("Get a specific version of the credential (defaults to the latest version"));

        let get_all_command = Command::new("getall")
            .about("Get all credentials from the store")
            .arg(Arg::new("context")
                 .help("encryption context key/value pairs associated with the credential in the form of key=value")
		 .action(clap::ArgAction::Append)
            ).arg(Arg::new("version").short('v').long("version").value_name("VERSION").help("Get a specific version of the credential (defaults to the latest version")).arg(Arg::new("format").short('f').long("format").value_name("FORMAT").help("Output format. json(default) yaml, csv or dotenv.").ignore_case(true).value_parser(["json", "yaml", "csv", "dotenv"]));

        let keys_command = Command::new("keys").about("List all keys in the store");

        let list_command = Command::new("list").about("List credentials and their versions");

        let put_command = Command::new("put")
            .about("Put a credential into the store")
            .arg(Arg::new("credential").help("the name of the credential to store").required(true))
            .arg(Arg::new("value").help("the value of the credential to store").required(true).conflicts_with("prompt"))
            .arg(Arg::new("context").help("encryption context key/value pairs associated with the credential in the form of key=value").action(clap::ArgAction::Append))
            .arg(Arg::new("key").short('k').long("key").value_name("KEY").help("the KMS key-id of the master key to use. Defaults to alias/credstash"))
            .arg(Arg::new("comment").short('c').long("comment").value_name("COMMENT").help("Include reference information or a comment about value to be stored."))
            .arg(Arg::new("version").short('v').long("version").value_name("VERSION").help("Put a specific version of the credential (update the credential; defaults to version `1`)"))
            .arg(Arg::new("autoversion").short('a').long("autoversion").help("Automatically increment the version of the credential to be stored.").conflicts_with("version"))
            .arg(Arg::new("digest").short('d').long("digest").value_name("DIGEST").help("the hashing algorithm used to to encrypt the data. Defaults to SHA256.").ignore_case(true).value_parser(["SHA1", "SHA256", "SHA384", "SHA512"]))
            .arg(Arg::new("prompt").short('p').long("prompt").help("Prompt for secret").takes_value(false));

        let put_all_command = Command::new("putall")
            .about("Put credentials from json or file into the store")
            .arg(Arg::new("credentials").help("the value of the credential to store or, if beginning with the \"@\" \
                                                     character, the filename of the file containing the values, or \
                                                     pass \"-\" to read the values from stdin. Should be in json format.").required(true))
            .arg(Arg::new("context").help("encryption context key/value pairs associated with the credential in the form of key=value"))
            .arg(Arg::new("key").short('k').long("key").value_name("KEY").help("the KMS key-id of the master key to use. Defaults to alias/credstash"))
            .arg(Arg::new("version").short('v').long("version").value_name("VERSION").help("Put a specific version of the credential (update the credential; defaults to version `1`)"))
            .arg(Arg::new("comment").short('c').long("comment").value_name("COMMENT").help("Include reference information or a comment about value to be stored."))
            .arg(Arg::new("autoversion").short('a').long("autoversion").help("Automatically increment the version of the credential to be stored.").conflicts_with("version"))
            .arg(Arg::new("digest").short('d').long("digest").value_name("DIGEST").help("the hashing algorithm used to to encrypt the data. Defaults to SHA256.").ignore_case(true).value_parser(["SHA1", "SHA256", "SHA384", "SHA512"]));

        let setup_command = Command::new("setup").about("setup the credential store").arg(Arg::new("tags").value_name("TAGS").help("Tags to apply to the Dynamodb Table passed in as a space sparated list of Key=Value").long("tags").short('t'));
        let app = app
            .arg(region_arg)
            .arg(table_arg)
            .arg(profile_arg)
            .arg(arn_arg)
            .arg(mfa_arg)
            .subcommand(del_command)
            .subcommand(get_command)
            .subcommand(get_all_command)
            .subcommand(keys_command)
            .subcommand(list_command)
            .subcommand(put_command)
            .subcommand(put_all_command)
            .subcommand(setup_command);
        // extract the matches

        log::debug!("Application initialized");

        let matches: clap::ArgMatches = app.try_get_matches_from(args)?;

        log::debug!("ArgMatches parsed");

        let region: Option<&str> = matches.value_of("region");

        log::debug!("AWS Region: {:?}", region);

        let action_value: Action = match matches.subcommand() {
            Some(("get", get_matches)) => {
                let credential: String = get_matches
                    .value_of("credential")
                    .expect("Credential not supplied")
                    .to_string();
                let context: Option<Vec<_>> = get_matches.values_of("context").and_then(|e| {
                    e.map(|item| split_context_to_tuple(item.to_string()).ok())
                        .collect()
                });

                let encryption_context: Vec<_> = match context {
                    None => vec![],
                    Some(x) => x,
                };
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
            Some(("getall", get_matches)) => {
                let context: Option<Vec<_>> = get_matches.values_of("context").and_then(|e| {
                    e.map(|item| split_context_to_tuple(item.to_string()).ok())
                        .collect()
                });

                let encryption_context: Vec<_> = match context {
                    None => vec![],
                    Some(x) => x,
                };
                let version = get_matches.value_of("version").map(|ver| {
                    ver.to_string()
                        .parse::<u64>()
                        .expect("Version should be positive integer")
                });
                let export_type = get_matches.value_of("format").map_or(
                    ExportOption::Json,
                    |export| match export.to_lowercase().as_ref() {
                        "csv" => ExportOption::Csv,
                        "yaml" => ExportOption::Yaml,
                        "dotenv" => ExportOption::DotEnv,
                        _ => ExportOption::Json,
                    },
                );
                let getall_opts = GetAllOpts {
                    version,
                    encryption_context,
                    export: export_type,
                };
                Action::GetAll(Some(getall_opts))
            }
            Some(("keys", _)) => Action::Keys,
            Some(("list", _)) => Action::List,
            Some(("setup", setup_matches)) => {
                let tags = setup_matches.values_of("tags");
                let tags_options: Option<Vec<String>> =
                    tags.map(|values| values.map(|item| item.to_string()).collect());
                let table_tags: Option<Vec<(String, String)>> = tags_options.map(|item| {
                    item.into_iter()
                        .filter_map(|item| split_tags_to_tuple(item).ok())
                        .collect()
                });
                let setup_opts = SetupOpts {
                    tags: table_tags.map_or(vec![], |tag| tag),
                };
                Action::Setup(setup_opts)
            }
            Some(("putall", putall_matches)) => {
                let credential_name: String = putall_matches
                    .value_of("credentials")
                    .map_or(Err(CredStashAppError::MissingCredential), |val| {
                        Ok(val.to_string())
                    })?;
                let mut credential_content = String::new();
                let credential_value: Vec<Credential> = match credential_name.chars().next() {
                    Some('@') => {
                        let mut filename = credential_name.clone();
                        filename.remove(0);
                        let mut file = File::open(filename)?;
                        file.read_to_string(&mut credential_content)?;
                        parse_credential(credential_content)?
                    }
                    Some('-') => {
                        let stdout = io::stdout();
                        let mut std_handle = stdout.lock();
                        std_handle.flush().ok();
                        io::stdin()
                            .read_line(&mut credential_content)
                            .expect("Failed to read from stdin");
                        parse_credential(credential_content)?
                    }
                    _ => parse_credential(credential_name)?,
                };

                let key_id = putall_matches.value_of("key").map(|e| e.to_string());
                let comment = putall_matches.value_of("comment").map(|e| e.to_string());
                let version: Either<u64, AutoIncrement> = {
                    let version_option = putall_matches.value_of("version").map_or(1, |e| {
                        e.to_string()
                            .parse::<u64>()
                            .expect("Version should be positive integer")
                    });
                    let autoversion = putall_matches.is_present("autoversion");
                    if autoversion {
                        Either::Right(AutoIncrement::AutoIncrement)
                    } else {
                        Either::Left(version_option)
                    }
                };
                let digest_algorithm = putall_matches
                    .value_of("digest")
                    .map_or(Ok(ring::hmac::HMAC_SHA256), |e| to_algorithm(e.to_string()))?;

                let context: Option<Vec<_>> = putall_matches.values_of("context").and_then(|e| {
                    e.map(|item| split_context_to_tuple(item.to_string()).ok())
                        .collect()
                });
                let encryption_context: Vec<_> = match context {
                    None => vec![],
                    Some(x) => x,
                };
                let putall_opts = PutAllOpts {
                    key_id,
                    comment,
                    version,
                    digest_algorithm,
                    content: credential_value,
                    encryption_context,
                };
                Action::PutAll(putall_opts)
            }
            Some(("put", put_matches)) => {
                log::debug!("Put Action");
                let credential_name: String = put_matches
                    .value_of("credential")
                    .map_or(Err(CredStashAppError::MissingCredential), |val| {
                        Ok(val.to_string())
                    })?;
                log::debug!("Credential name: {}", credential_name);
                let credential_value: String = {
                    let mut value = String::new();
                    let get_input = put_matches.is_present("prompt");
                    if get_input {
                        print!("{}: ", credential_name);
                        let stdout = io::stdout();
                        let mut std_handle = stdout.lock();
                        std_handle.flush().ok();
                        io::stdin()
                            .read_line(&mut value)
                            .expect("Failed to read from stdin");
                    } else {
                        value = put_matches
                            .value_of("value")
                            .map_or(Err(CredStashAppError::MissingCredentialValue), |val| {
                                Ok(val.to_string())
                            })?;
                    }
                    value.trim().to_string()
                };
                log::debug!("Credential value: {}", credential_value);
                let key_id = put_matches.value_of("key").map(|e| e.to_string());
                log::debug!("Key ID: {:?}", key_id);
                let comment = put_matches.value_of("comment").map(|e| e.to_string());
                log::debug!("Comment: {:?}", comment);
                let version: Either<u64, AutoIncrement> = {
                    let version_option = put_matches.value_of("version").map_or(1, |e| {
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
                log::debug!("Version: {:?}", version);
                let digest_algorithm = put_matches
                    .value_of("digest")
                    .map_or(Ok(ring::hmac::HMAC_SHA256), |e| to_algorithm(e.to_string()))?;

                let put_opts = PutOpts {
                    key_id,
                    comment,
                    version,
                    digest_algorithm,
                };
                let context: Option<Vec<_>> = put_matches.values_of("context").and_then(|e| {
                    e.map(|item| split_context_to_tuple(item.to_string()).ok())
                        .collect()
                });
                log::debug!("Context: {:?}", context);
                let encryption_context: Vec<_> = match context {
                    None => vec![],
                    Some(x) => x,
                };
                Action::Put(
                    credential_name,
                    credential_value,
                    encryption_context,
                    put_opts,
                )
            }
            Some(("delete", del_matches)) => {
                let credential: String = del_matches
                    .value_of("credential")
                    .map_or(Err(CredStashAppError::MissingCredential), |val| {
                        Ok(val.to_string())
                    })?;
                Action::Delete(credential)
            }
            Some((subcommand, _)) => {
                let err_msg = format!("Invalid Subcommand {} found. Use --help to see accepted subcommands and option", subcommand);
                Action::Invalid(err_msg)
            }
            None => {
                let err_msg =
                    "Invalid Subcommand found. Use --help to see accepted subcommands and option";
                Action::Invalid(err_msg.into())
            }
        };

        log::debug!("Action type: {:?}", action_value);

        let table_name = {
            match env::var("CREDSTASH_DEFAULT_TABLE ") {
                Ok(val) => Some(val),
                Err(_) => matches.value_of("table").map(|r| r.to_string()),
            }
        };
        let mfa = matches.value_of("mfa").map(|r| {
            print!("Enter MFA Code: ");
            let mut value = String::new();
            let stdout = io::stdout();
            let mut std_handle = stdout.lock();
            std_handle.flush().ok();
            io::stdin()
                .read_line(&mut value)
                .expect("Failed to read from stdin");
            (r.to_string(), value.trim().to_string())
        });
        let credential_type = {
            let assume_role = matches
                .value_of("arn")
                .map(|r| CredStashCredential::DefaultAssumeRole((r.to_string(), mfa)));
            let profile_cred = matches
                .value_of("profile")
                .map(|r| CredStashCredential::DefaultProfile(Some(r.to_string())));
            match (assume_role, profile_cred) {
                (Some(cred), _) => cred,
                (_, Some(cred)) => cred,
                _ => CredStashCredential::DefaultCredentialsProvider,
            }
        };
        Ok(CredstashApp {
            region: region.map(|r| r.to_string()),
            credential: credential_type,
            table_name,
            action: action_value,
        })
    }
}

fn split_context_to_tuple(
    encryption_context: String,
) -> Result<(String, String), CredStashAppError> {
    let context: Vec<&str> = encryption_context.split('=').collect();
    match context.len() {
        0 => Err(CredStashAppError::InsufficientContext(
            "No context supplied".to_string(),
        )),
        1 => {
            let msg = format!(
                "error: argument context: {} is not the form of key=value",
                encryption_context
            );
            Err(CredStashAppError::InsufficientContext(msg))
        }
        2 => Ok((context[0].to_string(), context[1].to_string())),
        _ => {
            let msg = format!(
                "error: argument context: {} is not the form of key=value",
                encryption_context
            );
            Err(CredStashAppError::InsufficientContext(msg))
        }
    }
}

fn split_tags_to_tuple(encryption_context: String) -> Result<(String, String), CredStashAppError> {
    let context: Vec<&str> = encryption_context.split('=').collect();
    match context.len() {
        0 => Err(CredStashAppError::InvalidArguments(
            "No arguments passed".to_string(),
        )),
        1 => {
            let msg = format!(
                "argument --tags: {} is not the form of key=value",
                encryption_context
            );
            Err(CredStashAppError::InvalidArguments(msg))
        }
        2 => Ok((context[0].to_string(), context[1].to_string())),
        _ => {
            let msg = format!(
                "argument --tags: {} is not the form of key=value",
                encryption_context
            );
            Err(CredStashAppError::InvalidArguments(msg))
        }
    }
}

fn render_version(item: Option<HashMap<String, AttributeValue>>) -> String {
    item.map_or("".to_string(), |hmap| {
        hmap.get("version").map_or("".to_string(), |version| {
            version
                .s
                .as_ref()
                .map_or("".to_string(), |ver| format!("--version {}", ver))
        })
    })
}

fn handle_error(error: CredStashAppError) {
    match error {
        CredStashAppError::VersionError(error_message) => program_exit(&error_message),
        CredStashAppError::ClapError(clap_error) => {
            if clap_error.kind == DisplayHelp || clap_error.kind == DisplayVersion {
                eprintln!("{}", &clap_error.to_string())
            } else {
                program_exit(&clap_error.to_string())
            }
        }
        CredStashAppError::MissingEnv(error_message) => program_exit(&error_message),
        CredStashAppError::InsufficientContext(error_message) => program_exit(&error_message),
        CredStashAppError::InvalidArguments(error_message) => program_exit(&error_message),
        CredStashAppError::MissingCredential => program_exit("Missing credentials"),
        CredStashAppError::MissingCredentialValue => program_exit("Missing credential value"),
        CredStashAppError::DigestAlgorithmNotSupported(error_message) => {
            program_exit(&error_message)
        }
        CredStashAppError::ClientError(credstash_error) => handle_credstash_error(credstash_error),
        CredStashAppError::InvalidAction(error_message) => program_exit(&error_message),
        CredStashAppError::ParseError(error_message) => program_exit(&error_message),
        CredStashAppError::IOError(error_message) => program_exit(&error_message),
        CredStashAppError::InsertionError(error_message) => program_exit(&error_message),
    }
}

fn handle_credstash_error(error: credstash::CredStashClientError) {
    match error {
        credstash::CredStashClientError::NoKeyFound => {
            program_exit("No key found in the remote DynamoDB")
        }
        credstash::CredStashClientError::AWSDynamoError(error_message) => {
            program_exit(&error_message)
        }
        credstash::CredStashClientError::AWSKMSError(error_message) => program_exit(&error_message),
        credstash::CredStashClientError::CredstashDecodeFalure(error_message) => {
            program_exit(&error_message.to_string())
        }
        credstash::CredStashClientError::CredstashHexFailure(error_message) => {
            program_exit(&error_message.to_string())
        }
        credstash::CredStashClientError::HMacMismatch => {
            program_exit("No key found in the remote DynamoDB")
        }
        credstash::CredStashClientError::ParseError(error_message) => program_exit(&error_message),
        credstash::CredStashClientError::CredentialsError(error_message) => {
            program_exit(&error_message)
        }

        credstash::CredStashClientError::TlsError(error_message) => program_exit(&error_message),
        credstash::CredStashClientError::DigestAlgorithmNotSupported(error_message) => {
            program_exit(&error_message)
        }
    }
}

fn program_exit(msg: &str) {
    eprintln!("{}", msg);
    std::process::exit(1);
}

fn init_logger() {
    use env_logger::{Builder, Target};
    let mut builder = Builder::from_default_env();
    builder.target(Target::Stderr).init();
}

#[tokio::main]
async fn main() {
    init_logger();
    log::debug!("Logger initialization done");
    let credstash_app = CredstashApp::new();
    match credstash_app {
        Ok(app) => {
            let region: Option<Region> = {
                app.clone().region.map_or(Some(Region::default()), |item| {
                    Some(Region::from_str(&item).expect("Invalid region supplied"))
                })
            };
            match CredStashClient::new(app.credential.clone(), region) {
                Ok(client) => match handle_action(app, client).await {
                    Ok(()) => (),
                    Err(error) => handle_error(error),
                },
                Err(error) => handle_error(CredStashAppError::ClientError(error)),
            }
        }
        Err(error) => handle_error(error),
    }
}
