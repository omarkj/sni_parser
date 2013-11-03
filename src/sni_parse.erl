-module(sni_parse).
-export([parse/1]).
-include("sni_parser.hrl").

-define(CONTENT_TYPE, 22).
-define(MSG_TYPE, 1).
-define(CLIENT_HELLO, 1).
-define(SNI, 0).
-define(SNI_HOST_NAME, 0).
-define(SESSION_TICKET, 35).
-define(ALPN, 16).

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
parse(<<?CONTENT_TYPE:8/integer-big-unsigned, Rest/binary>>) ->
    parse_ssl_version(Rest);
parse(Packet) ->
    {error, {no_tls_handshake, Packet}}.

parse_ssl_version(<<MajorVersion:8/integer-big-unsigned,
                    MinorVersion:8/integer-big-unsigned, 
                    Rest/binary>>) ->
    case {MajorVersion, MinorVersion} of
        {3, 1} ->
            parse_length(Rest, #client_hello{tls_version={1,0}});
        {3, 2} ->
            parse_length(Rest, #client_hello{tls_version={1,1}});
        {3, 3} ->
            parse_length(Rest, #client_hello{tls_version={1,2}});
        _ ->
            {error, unknown_tls_version}
    end.

parse_length(<<Length:16/integer-big-unsigned,
               Rest/binary>>, Retval) ->
    if Length =:= size(Rest) ->
            parse_handshake_type(Rest, Retval);
       true ->
            {error, {not_whole_handshake, Length - size(Rest)}}
    end.

parse_handshake_type(<<?CLIENT_HELLO:8/integer-big-unsigned,
                       Length:24/integer-big-unsigned,
                       Rest/binary>>, Retval) when Length =:= size(Rest)  ->
    parse_version(Rest, Retval);
parse_handshake_type(_, _) ->
    {error, not_client_hello}.

parse_version(<<_MajorVersion:8/integer-big-unsigned,
                _MinorVersion:8/integer-big-unsigned,
                GMTUnixTime:32/integer-big-unsigned,
                Random:28/binary,
                Rest/binary>>, Retval) ->
    parse_session(Rest, Retval#client_hello{gmt_unix_time = GMTUnixTime,
                                            random = Random});
parse_version(_, _) ->
    {error, invalid_client_hello}.

parse_session(<<SessionIdLength:8/integer-big-unsigned,
                SessionId:SessionIdLength/binary,
                Rest/binary>>, Retval) when SessionIdLength =< 32 ->
    parse_cipher_suites(Rest, Retval#client_hello{session_id = SessionId});
parse_session(_, _) ->
    {error, invalid_session_id}.

parse_cipher_suites(<<CipherSuitesLength:16/integer-big-unsigned,
                      CipherSuites:CipherSuitesLength/binary,
                      Rest/binary>>, Retval) ->
    parse_compression_methods(Rest, Retval#client_hello{cipher_suites = parse_cipher_suite(CipherSuites, [])});
parse_cipher_suites(_, _) ->
    {error, invalid_cipher_suites}.

parse_compression_methods(<<CompressionMethodsLength:8/integer-big-unsigned,
                            CompressionMethods:CompressionMethodsLength/binary,
                            Rest/binary>>, Retval) ->
    parse_extensions(Rest, Retval#client_hello{compression_methods = parse_compression_method(CompressionMethods, [])});
parse_compression_methods(_, _) ->
    {error, invalid_compression_methods}.

parse_extensions(<<ExtensionsLength:16/unsigned-big-integer,
                   ExtensionsBlob:ExtensionsLength/binary>>, Retval) ->
    parse_extension(ExtensionsBlob, Retval);
parse_extensions(_, _) ->
    {error, invalid_extensions}.

parse_cipher_suite(<<>>, CipherSuites) ->
    CipherSuites;
parse_cipher_suite(<<A:8/integer-big-unsigned,
                     B:8/integer-big-unsigned,
                     Rest/binary>>, CipherSuites) ->
    parse_cipher_suite(Rest, CipherSuites ++ [{A, B}]).

parse_compression_method(<<>>, CompressionMethods) ->
    CompressionMethods;
parse_compression_method(<<CompressionMethod:8/integer-big-unsigned,
                           Rest/binary>>, CompressionMethods) ->
    parse_compression_method(Rest, CompressionMethods ++ [CompressionMethod]).

parse_extension(<<>>, Retval) ->
    {ok, Retval};
parse_extension(<<?SNI:16/integer-big-unsigned,
                  ServerNameListLength:16/integer-big-unsigned,
                  ServerNameListBlob:ServerNameListLength/binary,
                  Rest/binary>>, #client_hello{extensions = Extensions} = Retval) ->
    ServerNameList = {sni, [{server_name_list, parse_server_name_list(ServerNameListBlob, [])}]},
    parse_extension(Rest, Retval#client_hello{extensions = Extensions ++ [ServerNameList]});
parse_extension(<<?ALPN:16/integer-big-unsigned,
                  ProtocolNameListLength:16/integer-big-unsigned,
                  ProtocolNameListBlob:ProtocolNameListLength/binary,
                  Rest/binary>>, #client_hello{extensions = Extensions} = Retval) ->
    ProtocolNameList = {alpn, [{protocols, parse_protocol_name_list(ProtocolNameListBlob, [])}]},
    parse_extension(Rest, Retval#client_hello{extensions = Extensions ++ [ProtocolNameList]});
parse_extension(<<_:16/integer-big-unsigned,
                  Len:16/integer-big-unsigned,
                  _:Len/binary,
                  Rest/binary>>, Retval) ->
    % @todo log?
    parse_extension(Rest, Retval).

parse_server_name_list(<<>>, ServerNameList) ->
    ServerNameList;
parse_server_name_list(<<_ServerNameLength:16/integer-big-unsigned,
                         ?SNI_HOST_NAME:8/integer-big-unsigned,
                         ServerNameStringLength:16/integer-big-unsigned,
                         ServerName:ServerNameStringLength/binary,
                         Rest/binary>>, ServerNameList) ->
    parse_server_name_list(Rest, ServerNameList ++ [ServerName]).

parse_protocol_name_list(<<>>, ProtocolNameList) ->
    ProtocolNameList;
parse_protocol_name_list(<<ProtocolNameLength:16/integer-big-unsigned,
                           ProtocolName:ProtocolNameLength/binary,
                           Rest/binary>>, ProtocolNameList) ->
    parse_protocol_name_list(Rest, ProtocolNameList ++ [ProtocolName]).
