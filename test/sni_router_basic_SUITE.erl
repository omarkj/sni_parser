-module(sni_router_basic_SUITE).
-include_lib("common_test/include/ct.hrl").
-include("sni_parser.hrl").

-export([all/0
         ,groups/0
         ,init_per_suite/1
         ,end_per_suite/1
         ,init_per_group/2
         ,end_per_group/2
         ,init_per_testcase/2
         ,end_per_testcase/2]).

-export([parse_sni/1]).

-compile(export_all).

all() -> [{group, basics}].

groups() -> [{basics,
              [],
              [parse_sni]}
            ].

init_per_suite(Config) ->
    Config.
end_per_suite(Config) ->
    Config.

init_per_group(_, Config) ->
    Config.

end_per_group(_, Config) ->
    Config.

init_per_testcase(_, Config) ->
    Config.
end_per_testcase(_, Config) ->
    Config.

parse_sni(Config) ->
    {ok, #client_hello{extensions = Extensions}} = sni_parse:parse(hello_package()),
    SNIExtension = proplists:get_value(sni, Extensions),
    true = lists:member(<<"lol.com">>, proplists:get_value(server_name_list, SNIExtension)),
    Config.


% Internal
hello_package() ->
    <<22,3,1,0,111,1,0,0,107,3,1,82,4,158,55,56,214,46,166,40,112,227,240,
      221,69,105,234,145,162,211,235,70,121,24,117,61,26,255,9,3,147,43,63,
      0,0,46,0,57,0,56,0,53,0,22,0,19,0,10,0,51,0,50,0,47,0,154,0,153,0,
      150,0,5,0,4,0,21,0,18,0,9,0,20,0,17,0,8,0,6,0,3,0,255,1,0,0,20,0,0,0,
      12,0,10,0,0,7,108,111,108,46,99,111,109,0,35,0,0>>.
