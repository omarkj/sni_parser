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
