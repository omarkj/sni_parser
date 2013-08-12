-module(sni_demo).

-export([create_server/1,
        server/1]).

create_server(Port) ->
    {ok, ListenSock} = gen_tcp:listen(Port, [{active, false}, binary]),
    {ok, RealPort} = inet:port(ListenSock),
    start_servers(1, ListenSock),
    RealPort.

start_servers(0,_) ->
    ok;
start_servers(Num,LSocket) ->
    spawn(?MODULE,server,[LSocket]),
    start_servers(Num-1, LSocket).

server(LSocket) ->
    {ok, AcceptSocket} = gen_tcp:accept(LSocket),
    loop(AcceptSocket, <<>>),
    server(LSocket).

loop(Socket, Buf) ->
    inet:setopts(Socket, [{active,once}]),
    receive
        {tcp, _, Data} ->
            loop(Socket, <<Buf/binary, Data/binary>>);
        {tcp_closed, _} ->
            error_logger:info_msg("Package is ~p", [sni_parse:parse(Buf)]),
            Buf
    end.
