# v0.9.2

- Use rustls feature of rusoto crates to make musl builds easier.
- Some rust code changes to conform rustfmt and clippy

# v0.9.1

- Minor fixes based on clippy suggestions
- Upgrade crates to latest version and make relevant changes for ctr.
- Default to SHA256 when digest column is not present
- Bump dependencies and rust-toolchain.

# v0.9.0

- Switch away from deprecated crate: aes-ctr to aes
- Upgrade all the dependencies
- Share client between CredStashClient instead of creating individual ones for both dynamodb and  kms.

# v0.8.0

* Implement putall subcommand
* Minor refactors and perf improvement.
* Add tests for the crypto module.
* Imports cleanup, improve documentation

# v0.7.0

* Remove unwrap usage from the library and hence make it more safe.
* Remove panic usage, new value introduced in the error enum type to
  cover more conditions.

# v0.6.1

* Fix compatibility with [credstash](https://github.com/fugue/credstash), when reading secrets written by it
* Bump rust-toolchain to 1.45.2
* Fix typo in help message

# v0.6.0

* Migration to async/await
* Update dependencies for rusoto libraries etc.

# v0.5.0

* Fix encryption context arguments and improve documentation.
* Make tags option to setup more ergonomic
* Improve errror messages on decryption failure based on encryption contexts
* Improve tests

# v0.4.0

* Set proper failure exit code on error
* Fix version display of the program
* Fix all the warnings
* Handle invalid subcommand and options.
* Improved documentation of the CLI tool.

# v0.3.0

* Add different format support for export options.

# v0.2.3

* Fix missing OS assets

# v0.2.2

* Add CI trigger for tags also.

# v0.2.1

* Fix release script

# v0.2.0

* Add various credential support. Previously this was driven purely by aws-env.
* Various UX improvements to match the original credstash program.
* Rename field in the CredstashItem
* Improve README with usage examples.

# v0.1.0

* Initial version released.
