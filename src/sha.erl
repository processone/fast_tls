%%%----------------------------------------------------------------------
%%% File    : sha.erl
%%% Author  : Alexey Shchepin <alexey@process-one.net>
%%% Purpose :
%%% Created : 20 Dec 2002 by Alexey Shchepin <alexey@process-one.net>
%%%
%%%
%%% ejabberd, Copyright (C) 2002-2013   ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this program; if not, write to the Free Software
%%% Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
%%% 02111-1307 USA
%%%
%%%----------------------------------------------------------------------

-module(sha).

-author('alexey@process-one.net').

-behaviour(gen_server).

-export([sha/1, sha1/1, sha224/1, sha256/1,
	 sha384/1, sha512/1, to_hexlist/1]).

%% Internal exports, call-back functions.
-export([start_link/0, init/1, handle_call/3, handle_cast/2,
	 handle_info/2, code_change/3, terminate/2]).

-ifdef(HAVE_MD2).

-export([md2/1]).

-endif.

-define(DRIVER, sha_drv).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [],
			  []).

init([]) ->
    case load_driver() of
        ok ->
            Port = open_port({spawn, atom_to_list(?DRIVER)},
                             [binary]),
            register(?DRIVER, Port),
            {ok, Port};
        {error, Why} ->
            {stop, Why}
    end.

%%% --------------------------------------------------------
%%% The call-back functions.
%%% --------------------------------------------------------

handle_call(_, _, State) -> {noreply, State}.

handle_cast(_, State) -> {noreply, State}.

handle_info({'EXIT', Port, Reason}, Port) ->
    {stop, {port_died, Reason}, Port};
handle_info({'EXIT', _Pid, _Reason}, Port) ->
    {noreply, Port};
handle_info(_, State) -> {noreply, State}.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

terminate(_Reason, Port) ->
    catch port_close(Port),
    ok.

digit_to_xchar(D) when (D >= 0) and (D < 10) -> D + 48;
digit_to_xchar(D) -> D + 87.

-spec sha(binary()) -> binary().

sha(Text) ->
    Bin = crypto:sha(Text),
    to_hexlist(Bin).

-spec to_hexlist(binary()) -> binary().

to_hexlist(Bin) ->
    iolist_to_binary(lists:reverse(ints_to_rxstr(binary_to_list(Bin), []))).

ints_to_rxstr([], Res) -> Res;
ints_to_rxstr([N | Ns], Res) ->
    ints_to_rxstr(Ns,
		  [digit_to_xchar(N rem 16), digit_to_xchar(N div 16)
		   | Res]).

-spec sha1(binary()) -> binary().
-spec sha224(binary()) -> binary().
-spec sha256(binary()) -> binary().
-spec sha384(binary()) -> binary().
-spec sha512(binary()) -> binary().

sha1(Text) -> crypto:sha(Text).

sha224(Text) -> erlang:port_control(?DRIVER, 224, Text).

sha256(Text) -> erlang:port_control(?DRIVER, 256, Text).

sha384(Text) -> erlang:port_control(?DRIVER, 384, Text).

sha512(Text) -> erlang:port_control(?DRIVER, 512, Text).

-ifdef(HAVE_MD2).

-spec md2(binary()) -> binary().

md2(Text) -> erlang:port_control(?DRIVER, 2, Text).

-endif.

get_so_path() ->
    case os:getenv("EJABBERD_SO_PATH") of
        false ->
            case code:priv_dir(p1_tls) of
                {error, _} ->
                    filename:join(["priv", "lib"]);
                Path ->
                    filename:join([Path, "lib"])
            end;
        Path ->
            Path
    end.

load_driver() ->
    case erl_ddll:load_driver(get_so_path(), ?DRIVER) of
        ok ->
            ok;
        {error, already_loaded} ->
            ok;
        {error, ErrorDesc} = Err ->
            error_logger:error_msg("failed to load SHA driver: ~s~n",
                                   [erl_ddll:format_error(ErrorDesc)]),
            Err
    end.
