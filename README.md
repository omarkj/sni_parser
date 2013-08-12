# SNI Parser

## Guaranteed to work all the time!*

TLS 1.0 supports Server Name Identification (SNI) and this is an attempt to
write a SNI parser in Erlang.

## But how does it work?

This library is designed to parse the CLIENT HELLO packet. If the SNI extension
is installed it will extract the host name.

## Does it work?

Yes and no. I haven't tested it much but it seems to work well with OpenSSL 
s_client and Firefox. Chrome (28) doesn't work - there is a problem parsing
the extensions. I might look into it.

## Types

``` erlang
-type parse_error() :: no_tls_handshake|
                       invalid_ssl_version|
                       not_whole_handshake|
                       invalid_handshake_1|
                       invalid_handshake_2|
                       invalid_handshake_3|
                       invalid_session_id|
                       no_sni_extenson|
                       invalid_extension_block|
                       invalid_sni.

-type hello_info() :: [info()].

-type info() :: {major_ssl_version|minor_ssl_version|
                 gmt_unix_time, pos_integer()}|
                {random, <<_:28>>}|
                {session_id, binary()}|
                {sni, binary()}.
```

## API

``` erlang
-spec parse(binary()) -> {error, parse_error()}|
                         {ok, hello_info()}.
```

\* Not guaranteed at all
