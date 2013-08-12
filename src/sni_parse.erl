-module(sni_parse).

-export([parse/1]).

-define(CONTENT_TYPE, 22).
-define(MSG_TYPE, 1).
-define(SNI_EXTENSION, 0).

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

-spec parse(binary()) -> {error, parse_error()}|
                         {ok, hello_info()}.
parse(<<?CONTENT_TYPE, Rest/binary>>) ->
    parse_ssl_version(Rest);
parse(Packet) ->
    {error, {no_tls_handshake, Packet}}.

parse_ssl_version(<<MajorVersion:8/integer-big-unsigned,
                    MinorVersion:8/integer-big-unsigned, 
                    Rest/binary>>) when
      MajorVersion =< 3 andalso
      MinorVersion =< 1 ->
    parse_length(Rest, [{major_ssl_version, MajorVersion},
                        {minor_ssl_version, MinorVersion}]);
parse_ssl_version(_) ->
    {error, invalid_ssl_version}.

% Finishing up this Fragment, data left is the handshake
parse_length(<<Length:16/integer-big-unsigned,
               Rest/binary>>, Retval) when 
      Length =:= size(Rest) ->
    parse_handshake_type(Rest, Retval);
parse_length(_, _) ->
    {error, not_whole_handshake}.

parse_handshake_type(<<1:8/integer,
                       _Length:24/unsigned-big-integer,
                       Rest/binary>>, Retval) ->
    % @todo check length
    parse_version(Rest, Retval).

parse_version(<<_MajorVersion:8/unsigned-big-integer,
                _MinorVersion:8/unsigned-big-integer,
                GMTUnixTime:32/unsigned-big-integer,
                Random:28/binary,
                Rest/binary>>, Retval) ->
    parse_session(Rest, [{gmt_unix_time, GMTUnixTime},
                         {random, Random}|Retval]);
parse_version(_, _) ->
    {error, invalid_handshake_1}.

parse_session(<<SessionIdLength:8/unsigned-big-integer,
                SessionId:SessionIdLength/binary,
                Rest/binary>>, Retval) when SessionIdLength =< 32 ->
    parse_until_extensions(Rest, [{session_id, SessionId}|Retval]);
parse_session(_, _) ->
    {error, invalid_session_id}.

parse_until_extensions(<<CipherSuitesLength:16/unsigned-big-integer,
                         _CipherSuites:CipherSuitesLength/binary,
                         CompressionMethodsLength:8/unsigned-big-integer,
                         _CompressionMethods:CompressionMethodsLength/binary,
                         Rest/binary>>, Retval) ->
    parse_extensions(Rest, Retval);
parse_until_extensions(_, _) ->
    {error, invalid_handshake_2}.

parse_extensions(<<ExtLength:16/unsigned-big-integer,
                   Extensions:ExtLength/binary,
                   _/binary>>, Retval) ->
    parse_extension(Extensions, Retval);
parse_extensions(_, _) ->
    {error, invalid_handshake_3}.

parse_extension(<<>>, _) ->
    {error, no_sni_extenson};
parse_extension(<<12:8/integer,
                  SNILength:16/unsigned-big-integer,
                  SNIPart:SNILength/binary,
                  _Rest/binary>>, Retval) ->
    parse_sni(SNIPart, Retval);
parse_extension(<<_:8/integer,
                  Length:16/unsigned-big-integer,
                  _Data:Length/binary,
                  Rest/binary>>, Retval) ->
    parse_extension(Rest, Retval);
parse_extension(_, _) ->
    {error, invalid_extension_block}.


parse_sni(<<?SNI_EXTENSION:8/unsigned-big-integer,
            SNIHostLength:16/unsigned-big-integer,
            SNI:SNIHostLength/binary>>, Retval) ->
    {ok, [{sni, SNI}|Retval]};
parse_sni(_,_) ->
    {error, invalid_sni}.
