-module(sni_parse).

-export([parse/1]).

-define(TLS_HEADER_LENGTH, 5).
-define(CONTENT_TYPE, 22).
-define(TLS_MSG_TYPE, 8#01).

parse(<<?CONTENT_TYPE, Rest/binary>>) ->
    parse_ssl_version(Rest);
parse(Packet) ->
    {error, {no_tls_handshake, Packet}}.

parse_ssl_version(<<MajorSSLVersion:8/integer-big-unsigned,
                    MinorSSLVersion:8/integer-big-unsigned, Rest/binary>>) when
      MajorSSLVersion =< 3 andalso
      MinorSSLVersion =< 1 ->
    parse_length(Rest, [{major_ssl_version, MajorSSLVersion},
                        {minor_ssl_version, MinorSSLVersion}]);
parse_ssl_version(_) ->
    {error, invalid_ssl_version}.

parse_length(<<Length:16/integer-unsigned,
               Rest/binary>>, 
             Retval) when Length =:= size(Rest) ->
    parse_version(Rest, Retval);
parse_length(_, _) ->
    {error, not_whole_handshake}.

parse_version(<<MajorTLSVersion:8/unsigned-big-integer,
                MinorTLSVersion:8/unsigned-big-integer,
                _Random:32/binary,
                Rest/binary>>, Retval) ->
    parse_session(Rest, [{major_tls_version, MajorTLSVersion},
                         {minor_tls_version, MinorTLSVersion}|Retval]);
parse_version(_, _) ->
    {error, invalid_tls_version}.

parse_session(<<SessionIdLength:8/unsigned-big-integer,
                SessionId:SessionIdLength/binary,
                Rest/binary>>, Retval) ->
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
    {error, invalid_handshake_1}.

parse_extensions(<<_ExtLength:16/unsigned-big-integer,
                   Rest/binary>>, Retval) ->
    parse_extension(Rest, Retval);
parse_extensions(_, _) ->
    {error, invalid_handshake_2}.

parse_extension(<<>>, _) ->
    {error, no_extensons};
parse_extension(<<12:16/unsigned-big-integer,
                  SNILength:16/unsigned-big-integer,
                  SNIPart:SNILength/binary,
                  _Rest/binary>>, Retval) ->
    parse_sni(SNIPart, Retval);
parse_extension(<<_:16/unsigned-big-integer,
                   Length:16/unsigned-big-integer,
                   _:Length/binary,
                   Rest/binary>>, Retval) ->
    parse_extension(Rest, Retval).

parse_sni(<<0:8/unsigned-big-integer,
            SNIHostLength:16/unsigned-big-integer,
            SNI:SNIHostLength/binary>>, Retval) ->
    {ok, [{sni, SNI}|Retval]};
parse_sni(_,_) ->
    {error, invalid_sni}.
