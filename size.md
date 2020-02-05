# Investigating binary size with rucredstash

```
cargo build --release
```

```
12M /home/callen/.cargo/cache/release/rucredstash
```

After strip:

```
6.8M /home/callen/.cargo/cache/release/rucredstash
```

## Bloat report

```
File  .text     Size             Crate Name
 0.6%   5.3% 740.7KiB              http http::header::name::parse_hdr
 0.2%   1.4% 190.1KiB             regex <regex::exec::ExecNoSync as regex::re_trait::Reg...
 0.0%   0.3%  38.5KiB             regex regex::re_unicode::Regex::shortest_match_at
 0.0%   0.2%  25.5KiB             regex aho_corasick::ahocorasick::AhoCorasick<S>::find
 0.0%   0.2%  24.5KiB            base64 base64::decode::decode_helper
 0.0%   0.2%  24.5KiB            base64 base64::decode::decode_helper
 0.0%   0.2%  24.5KiB         credstash base64::decode::decode_helper
 0.0%   0.2%  24.2KiB   rusoto_dynamodb <rusoto_dynamodb::generated::_IMPL_DESERIALIZE_F...
 0.0%   0.2%  23.6KiB rusoto_credential h2::codec::framed_read::FramedRead<T>::decode_frame
 0.0%   0.2%  23.6KiB       rusoto_core h2::codec::framed_read::FramedRead<T>::decode_frame
 0.0%   0.2%  23.3KiB              clap clap::app::parser::Parser::get_matches_with
 0.0%   0.1%  19.4KiB       rucredstash rucredstash::CredstashApp::new_from
 0.0%   0.1%  17.6KiB       rucredstash rucredstash::handle_action
 0.0%   0.1%  17.1KiB              sha2 sha2::sha256_utils::sha256_digest_block_u32
 0.0%   0.1%  16.9KiB          aes_soft aes_soft::bitslice::bit_slice_1x128_with_u32x4
 0.0%   0.1%  16.8KiB          aes_soft aes_soft::bitslice::un_bit_slice_1x128_with_u32x4
 0.0%   0.1%  14.6KiB   rusoto_dynamodb <rusoto_dynamodb::generated::_IMPL_DESERIALIZE_F...
 0.0%   0.1%  13.0KiB   rusoto_dynamodb <rusoto_dynamodb::generated::_IMPL_DESERIALIZE_F...
 0.0%   0.1%  12.5KiB                h2 h2::frame::headers::HeaderBlock::load::{{closure}}
 0.0%   0.1%  12.4KiB            chrono chrono::format::parse::parse
10.6%  87.1%  11.9MiB                   And 65319 smaller methods. Use -n N to show more.
12.2% 100.0%  13.7MiB                   .text section size, the file size is 112.3MiB
```

## Making further improvements

```
[profile.release]
opt-level = 'z'  # Optimize for size.
lto = true
codegen-units = 1
panic = 'abort'
```

Before strip:

```
5.2M /home/callen/.cargo/cache/release/rucredstash

```

After strip:

```
3.3M /home/callen/.cargo/cache/release/rucredstash
```

## Going hard with Xargo and a source-compiled lib-std

Same result really, 3.3mb after stripping.
