extern crate clap;

use clap::{App, Arg, SubCommand};
use std::ffi::OsString;

#[derive(Debug, PartialEq)]
struct RuCredStashApp {
    name: String,
    region_option: Option<String>,
    aws_profile: Option<String>,
    table_name: Option<String>,
    aws_arn: Option<String>,
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
            .help("the AWS region in which to operate. If a region is not specified, credstash will use the value of the AWS_DEFAULT_REGION env variable, or if that is not set, the value in `~/.aws/config`. As a last resort, it will use us-east-1");

        let table_arg = Arg::with_name("table")
            .long("table")
            .short("t")
            .value_name("TABLE")
            .help("DynamoDB table to use for credential storage. If not specified, credstash will use the value of the CREDSTASH_DEFAULT_TABLE env variable, or if that is not set, the value `credential-store` will be used");

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
            .arg(Arg::with_name("del_secret").help("The secret to delete"));

        let get_command = SubCommand::with_name("get")
            .about("Get a credential from the store")
            .arg(Arg::with_name("secret").help("The secret to retrieve"));

        let get_all_command = SubCommand::with_name("getall")
            .about("Get all credentials from the store")
            .arg(Arg::with_name("secret").help("The secret to retrieve"));

        let keys_command = SubCommand::with_name("keys").about("List all keys in the store");

        let list_command =
            SubCommand::with_name("list").about("List credentials and their versions");

        let put_command = SubCommand::with_name("put")
            .about("Put a credential from the store")
            .arg(Arg::with_name("secret").help("The secret to retrieve"));

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

        Ok(RuCredStashApp {
            name: "Hello".to_string(),
            region_option: region.map(|r| r.to_string()),
            aws_profile: matches.value_of("profile").map(|r| r.to_string()),
            aws_arn: matches.value_of("arn").map(|r| r.to_string()),
            table_name: matches.value_of("table").map(|r| r.to_string()),
        })
        // panic!("undefined");
    }
}

fn main() {
    let test = RuCredStashApp::new();
    println!("Hello, world {:?}", test);
}
