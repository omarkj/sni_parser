# SNI Parser

## Guaranteed to work all the time!*

TLS 1.0 supports Server Name Identification (SNI) and this is an attempt to
write a SNI parser in Erlang.

## But how does it work?

This library is designed to parse the CLIENT HELLO packet. If the SNI extension
is installed it will extract the host name.

This library parses the whole CLIENT_HELLO and I have a untested but
probably functional
[ALNP](http://tools.ietf.org/html/draft-friedl-tls-applayerprotoneg-00)
parser as well.

## Types

``` erlang
-type bytes_missing() :: integer().
-type parse_error() :: no_tls_handshake|
                       unknown_tls_version|
                       {not_whole_handshake, bytes_missing()}|
                       not_client_hello|
                       invalid_client_hello|
                       invalid_session_id|
                       invalid_cipher_suites|
                       invalid_compression_methods|
                       invalid_extensions.

-type client_hello() :: #client_hello{}.
-spec parse(binary()) -> {error, parse_error()}|
                         {ok, client_hello()}.
-type extensions() :: {extension_name(), [extension_info()]}.
-type extension_name() :: sni.
-type extension_info() :: {uri, binary()}.
-record(client_hello, {tls_version :: {1,0}|{1,1}|{1,2},
                       gmt_unix_time :: pos_integer(),
                       random :: <<_:28>>,
                       session_id :: binary(),
                       cipher_suites = [] :: [any()],
                       compression_methods = [] :: [any()],
                       extensions = [] :: [extensions()]}).
```

## API

``` erlang
-spec parse(binary()) -> {error, parse_error()}|
                         {ok, client_hello()}.
```

\* Not guaranteed at all
