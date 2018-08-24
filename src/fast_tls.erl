%%%----------------------------------------------------------------------
%%% File    : fast_tls.erl
%%% Author  : Alexey Shchepin <alexey@process-one.net>
%%% Purpose : Interface to openssl
%%% Created : 24 Jul 2004 by Alexey Shchepin <alexey@process-one.net>
%%%
%%%
%%% Copyright (C) 2002-2017 ProcessOne, SARL. All Rights Reserved.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%%----------------------------------------------------------------------

-module(fast_tls).

-author('alexey@process-one.net').

-compile({no_auto_import, [{integer_to_binary, 1}]}).

-behaviour(gen_server).

-export([open_nif/8, get_decrypted_input_nif/2,
	 set_encrypted_input_nif/2, get_encrypted_output_nif/1,
	 set_decrypted_output_nif/2, get_peer_certificate_nif/1,
	 get_verify_result_nif/1, invalidate_nif/1, get_negotiated_cipher_nif/1]).

-export([start_link/0, tcp_to_tls/2,
	 tls_to_tcp/1, send/2, recv/2, recv/3, recv_data/2,
	 setopts/2, sockname/1, peername/1,
	 controlling_process/2, close/1,
	 get_peer_certificate/1, get_peer_certificate/2,
	 get_verify_result/1, get_cert_verify_string/2,
	 add_certfile/2, get_certfile/1, delete_certfile/1,
	 clear_cache/0, get_negotiated_cipher/1]).

%% Internal exports, call-back functions.
-export([init/1, handle_call/3, handle_cast/2,
	 handle_info/2, code_change/3, terminate/2]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.
-include_lib("public_key/include/public_key.hrl").

-define(SET_CERTIFICATE_FILE_ACCEPT, 1).

-define(SET_CERTIFICATE_FILE_CONNECT, 2).

-define(SET_ENCRYPTED_INPUT, 3).

-define(SET_DECRYPTED_OUTPUT, 4).

-define(GET_ENCRYPTED_OUTPUT, 5).

-define(GET_DECRYPTED_INPUT, 6).

-define(GET_PEER_CERTIFICATE, 7).

-define(GET_VERIFY_RESULT, 8).

-define(VERIFY_NONE, 16#10000).

-define(COMPRESSION_NONE, 16#100000).

-define(PRINT(Format, Args), io:format(Format, Args)).

-record(tlssock, {tcpsock :: inet:socket(),
                  tlsport :: port()}).

-type tls_socket() :: #tlssock{}.

-type cert() :: any(). %% TODO

-export_type([tls_socket/0]).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [],
			  []).

init([]) ->
    case load_nif() of
        ok ->
            {ok, []};
        {error, Why} ->
            {stop, Why}
    end.

open_nif(_Flags, _CertFile, _Ciphers, _ProtocolOpts, _DHFile, _CAFile, _SNI, _ALPN) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

get_decrypted_input_nif(_Port, _Length) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

set_encrypted_input_nif(_Port, _Packet) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

get_encrypted_output_nif(_Port) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

set_decrypted_output_nif(_Port, _Packet) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

get_peer_certificate_nif(_Port) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

get_verify_result_nif(_Port) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

add_certfile_nif(_Domain, _File) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

get_certfile_nif(_Domain) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

delete_certfile_nif(_Domain) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

invalidate_nif(_Port) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

clear_cache_nif() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

get_negotiated_cipher_nif(_Port) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

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

terminate(_Reason, _State) ->
    ok.

-spec tcp_to_tls(inet:socket(),
                 [{atom(), any()}]) -> {'error','no_certfile' | binary()} |
                                       {ok, tls_socket()}.

tcp_to_tls(TCPSocket, Options) ->
    Command = case lists:member(connect, Options) of
		  true -> ?SET_CERTIFICATE_FILE_CONNECT;
		  false -> ?SET_CERTIFICATE_FILE_ACCEPT
	      end,
    CertFile = proplists:get_value(certfile, Options, ""),
    if CertFile /= [] orelse Command == ?SET_CERTIFICATE_FILE_ACCEPT ->
	    Flags1 = case lists:member(verify_none, Options) of
			 true -> ?VERIFY_NONE;
			 false -> 0
		     end,
	    Flags2 = case lists:member(compression_none, Options) of
			 true -> ?COMPRESSION_NONE;
			 false -> 0
		     end,
	    Flags = Flags1 bor Flags2,
	    Ciphers =
	    case lists:keysearch(ciphers, 1, Options) of
		{value, {ciphers, C}} ->
		    iolist_to_binary(C);
		false ->
		    <<>>
	    end,
	    ProtocolOpts = case lists:keysearch(protocol_options, 1, Options) of
			       {value, {protocol_options, P}} ->
				   iolist_to_binary(P);
			       false ->
				   <<>>
			   end,
	    DHFile = case lists:keysearch(dhfile, 1, Options) of
			 {value, {dhfile, D}} ->
			     iolist_to_binary(D);
			 false ->
			     <<>>
		     end,
	    CAFile = case lists:keysearch(cafile, 1, Options) of
			 {value, {cafile, CA}} ->
			     iolist_to_binary(CA);
			 false ->
			     <<>>
		     end,
	    ServerName = case lists:keysearch(sni, 1, Options) of
			     {value, {sni, SNI}} ->
				 iolist_to_binary(SNI);
			     false ->
				 <<>>
			 end,
	    ALPN = case lists:keysearch(alpn, 1, Options) of
		       {value, {alpn, ProtoList}} ->
			   encode_alpn(ProtoList);
		       false ->
			   <<>>
		   end,
	    case open_nif(Command bor Flags, CertFile, Ciphers, ProtocolOpts,
			  DHFile, CAFile, ServerName, ALPN) of
		{ok, Port} ->
		    {ok, #tlssock{tcpsock = TCPSocket, tlsport = Port}};
		Err = {error, _} ->
		    Err
	    end;
	true -> {error, no_certfile}
    end.

-spec tls_to_tcp(tls_socket()) -> inet:socket().

tls_to_tcp(#tlssock{tcpsock = TCPSocket,
		    tlsport = Port}) ->
    invalidate_nif(Port),
    TCPSocket.

recv(Socket, Length) -> recv(Socket, Length, infinity).

-spec recv(tls_socket(), non_neg_integer(),
           timeout()) -> {error, inet:posix()} |
                         {error, binary()} |
                         {ok, binary()}.

recv(#tlssock{tcpsock = TCPSocket} =
	 TLSSock,
     Length, Timeout) ->
    case recv_data(TLSSock, <<>>, Length) of
        {ok, <<>>} ->
            case gen_tcp:recv(TCPSocket, 0, Timeout) of
                {ok, Packet} -> recv_data(TLSSock, Packet, Length);
                {error, _Reason} = Error -> Error
            end;
        Res -> Res
    end.

-spec recv_data(tls_socket(), binary()) -> {error, inet:posix() | binary()} |
                                           {ok, binary()}.

recv_data(TLSSock, Packet) ->
    recv_data(TLSSock, Packet, 0).

-spec recv_data(tls_socket(), binary(),
                non_neg_integer()) -> {error, inet:posix() | binary()} |
                                      {ok, binary()}.

recv_data(TLSSock, Packet, Length) ->
    case catch recv_data1(TLSSock, Packet, Length) of
      {'EXIT', Reason} -> {error, Reason};
      Res -> Res
    end.

recv_data1(#tlssock{tcpsock = TCPSocket,
		    tlsport = Port},
	   Packet, Length) ->
    case catch set_encrypted_input_nif(Port, Packet) of
	{'EXIT', {badarg, _}} ->
	    {error, einval};
	ok ->
	    case catch get_decrypted_input_nif(Port, Length) of
		{'EXIT', {badarg, _}} ->
		    {error, einval};
		{ok, In} -> {ok, In};
		{send, In} ->
		    case catch get_encrypted_output_nif(Port) of
			{'EXIT', {badarg, _}} ->
			    {error, einval};
			{ok, Out} ->
			    case gen_tcp:send(TCPSocket, Out) of
				ok -> {ok, In};
				Error -> Error
			    end;
			{error, _} = Err ->
			    Err
		    end;
		{error, _} = Err ->
		    Err
	    end;
	{error, _} = Err ->
	    Err
    end.

-spec send(tls_socket(), binary()) -> ok | {error, inet:posix() |
                                            binary() | timeout}.

send(#tlssock{tcpsock = TCPSocket, tlsport = Port},
     Packet) ->
    case catch set_decrypted_output_nif(Port, Packet) of
	{'EXIT', {badarg, _}} ->
	    {error, einval};
	ok ->
	    case catch get_encrypted_output_nif(Port) of
		{'EXIT', {badarg, _}} ->
		    {error, einval};
		{ok, Out} ->
		    gen_tcp:send(TCPSocket, Out);
		{error, _} = Err ->
		    Err
	    end;
	{error, _} = Err ->
	    Err
    end.

-spec setopts(tls_socket(), list()) -> ok | {error, inet:posix()}.

setopts(#tlssock{tcpsock = TCPSocket}, Opts) ->
    inet:setopts(TCPSocket, Opts).

-spec sockname(tls_socket()) -> {ok, {inet:ip_address(), inet:port_number()}} |
                                {error, inet:posix()}.

sockname(#tlssock{tcpsock = TCPSocket}) ->
    inet:sockname(TCPSocket).

peername(#tlssock{tcpsock = TCPSocket}) ->
    inet:peername(TCPSocket).

controlling_process(#tlssock{tcpsock = TCPSocket},
		    Pid) ->
    gen_tcp:controlling_process(TCPSocket, Pid).

close(#tlssock{tcpsock = TCPSocket, tlsport = Port}) ->
    invalidate_nif(Port),
    gen_tcp:close(TCPSocket).

-spec get_peer_certificate(tls_socket()) -> error | {ok, cert()}.
get_peer_certificate(TLSSock) ->
    get_peer_certificate(TLSSock, plain).

-spec get_peer_certificate(tls_socket(), otp|plain) -> error | {ok, cert()}.
get_peer_certificate(#tlssock{tlsport = Port}, Type) ->
    case catch get_peer_certificate_nif(Port) of
	{'EXIT', {badarg, _}} ->
	    error;
	{ok, BCert} ->
	    try public_key:pkix_decode_cert(BCert, Type) of
		Cert -> {ok, Cert}
	    catch _:_ ->
		    error
	    end;
	{error, _} -> error
    end.

-spec get_negotiated_cipher(tls_socket()) -> error | {ok, binary()}.
get_negotiated_cipher(#tlssock{tlsport = Port}) ->
		case catch get_negotiated_cipher_nif(Port) of
			Val when is_binary(Val) ->
				{ok, Val};
			_ ->
				error
		end.

-spec get_verify_result(tls_socket()) -> byte().

get_verify_result(#tlssock{tlsport = Port}) ->
    {ok, Res} = get_verify_result_nif(Port),
    Res.

-spec get_cert_verify_string(number(), cert()) -> binary().

get_cert_verify_string(CertVerifyRes, Cert) ->
    case catch cert_is_self_signed(Cert) of
      {'EXIT', _} -> <<"unknown verification error">>;
      IsSelfsigned ->
	  case {CertVerifyRes, IsSelfsigned} of
	    {21, true} -> <<"self-signed certificate">>;
	    _ -> cert_verify_code(CertVerifyRes)
	  end
    end.

cert_is_self_signed(#'Certificate'{} = Cert) ->
    BCert = public_key:pkix_encode('Certificate', Cert, plain),
    cert_is_self_signed(BCert);
cert_is_self_signed(Cert) ->
    public_key:pkix_is_self_signed(Cert).

-spec add_certfile(iodata(), iodata()) -> ok.
add_certfile(Domain, File) ->
    add_certfile_nif(Domain, File).

%% @doc This function is intended for tests only
-spec get_certfile(iodata()) -> {ok, binary()} | error.
get_certfile(Domain) ->
    get_certfile_nif(Domain).

%% @doc Returns `true` if element is deleted, `false` otherwise
-spec delete_certfile(iodata()) -> boolean().
delete_certfile(Domain) ->
    delete_certfile_nif(Domain).

%% @doc Clears cached SSL_CTX structures
%% You MUST call this function if you change content
%% of your CA, DH or certificate files
-spec clear_cache() -> ok.
clear_cache() ->
    clear_cache_nif().

cert_verify_code(0) -> <<"ok">>;
cert_verify_code(2) ->
    <<"unable to get issuer certificate">>;
cert_verify_code(3) ->
    <<"unable to get certificate CRL">>;
cert_verify_code(4) ->
    <<"unable to decrypt certificate's signature">>;
cert_verify_code(5) ->
    <<"unable to decrypt CRL's signature">>;
cert_verify_code(6) ->
    <<"unable to decode issuer public key">>;
cert_verify_code(7) ->
    <<"certificate signature failure">>;
cert_verify_code(8) -> <<"CRL signature failure">>;
cert_verify_code(9) ->
    <<"certificate is not yet valid">>;
cert_verify_code(10) -> <<"certificate has expired">>;
cert_verify_code(11) -> <<"CRL is not yet valid">>;
cert_verify_code(12) -> <<"CRL has expired">>;
cert_verify_code(13) ->
    <<"format error in certificate's notBefore "
      "field">>;
cert_verify_code(14) ->
    <<"format error in certificate's notAfter "
      "field">>;
cert_verify_code(15) ->
    <<"format error in CRL's lastUpdate field">>;
cert_verify_code(16) ->
    <<"format error in CRL's nextUpdate field">>;
cert_verify_code(17) -> <<"out of memory">>;
cert_verify_code(18) -> <<"self signed certificate">>;
cert_verify_code(19) ->
    <<"self signed certificate in certificate "
      "chain">>;
cert_verify_code(20) ->
    <<"unable to get local issuer certificate">>;
cert_verify_code(21) ->
    <<"unable to verify the first certificate">>;
cert_verify_code(22) ->
    <<"certificate chain too long">>;
cert_verify_code(23) -> <<"certificate revoked">>;
cert_verify_code(24) -> <<"invalid CA certificate">>;
cert_verify_code(25) ->
    <<"path length constraint exceeded">>;
cert_verify_code(26) ->
    <<"unsupported certificate purpose">>;
cert_verify_code(27) -> <<"certificate not trusted">>;
cert_verify_code(28) -> <<"certificate rejected">>;
cert_verify_code(29) -> <<"subject issuer mismatch">>;
cert_verify_code(30) ->
    <<"authority and subject key identifier "
      "mismatch">>;
cert_verify_code(31) ->
    <<"authority and issuer serial number mismatch">>;
cert_verify_code(32) ->
    <<"key usage does not include certificate "
      "signing">>;
cert_verify_code(50) ->
    <<"application verification failure">>;
cert_verify_code(X) ->
    <<"Unknown OpenSSL error code: ", (integer_to_binary(X))/binary>>.

integer_to_binary(I) ->
    list_to_binary(integer_to_list(I)).

encode_alpn(ProtoList) ->
    [<<(size(Proto)), Proto/binary>> || Proto <- ProtoList, Proto /= <<>>].

load_nif() ->
    SOPath = p1_nif_utils:get_so_path(fast_tls, [fast_tls], "fast_tls"),
    load_nif(SOPath).

load_nif(SOPath) ->
    case erlang:load_nif(SOPath, 0) of
        ok ->
            ok;
        {error, already_loaded} ->
            ok;
        {error, ErrorDesc} = Err ->
            error_logger:error_msg("failed to load TLS NIF: ~s~n",
                                   [erl_ddll:format_error(ErrorDesc)]),
            Err
    end.

-ifdef(TEST).

load_nif_test() ->
    SOPath = p1_nif_utils:get_so_path(fast_tls, [], "fast_tls"),
    ?assertEqual(ok, load_nif(SOPath)).

transmission_test() ->
    {LPid, Port} = setup_listener([]),
    SPid = setup_sender(Port, []),
    SPid ! {stop, self()},
    receive
	{result, Res} ->
	    ?assertEqual(ok, Res)
    end,
    LPid ! {stop, self()},
    receive
	{received, Msg} ->
	    ?assertEqual(<<"abcdefghi">>, Msg)
    end.

not_compatible_protocol_options_test() ->
    {LPid, Port} = setup_listener([{protocol_options, <<"no_sslv2|no_sslv3|no_tlsv1_1|no_tlsv1_2|no_tlsv1_3">>}]),
    SPid = setup_sender(Port, [{protocol_options, <<"no_sslv2|no_sslv3|no_tlsv1|no_tlsv1_2|no_tlsv1_3">>}]),
    SPid ! {stop, self()},
    receive
	{result, Res} ->
	    ?assertMatch({badmatch, {error, _}}, Res)
    end,
    LPid ! {stop, self()},
    receive
	{received, {error, _, _} = Msg} ->
	    ?assertMatch({error, _, <<>>}, Msg);
	{received, Msg} ->
	    ?assertMatch(<<>>, Msg)
    end.

setup_listener(Opts) ->
    {ok, ListenSocket} = gen_tcp:listen(0,
					[binary, {packet, 0}, {active, false},
					 {reuseaddr, true}, {nodelay, true}]),
    Pid = spawn(fun() ->
	{ok, Socket} = gen_tcp:accept(ListenSocket),
	{ok, TLSSock} = tcp_to_tls(Socket, [{certfile, <<"../tests/cert.pem">>} | Opts]),
	listener_loop(TLSSock, <<>>)
		end),
    {ok, Port} = inet:port(ListenSocket),
    {Pid, Port}.

listener_loop(TLSSock, Msg) ->
    case recv(TLSSock, 1, 1000) of
	{error, timeout} ->
	    receive
		{stop, Pid} ->
		    Pid ! {received, Msg}
	    after 0 ->
		listener_loop(TLSSock, Msg)
	    end;
	{error, closed} ->
	    receive
		{stop, Pid} ->
		    Pid ! {received, Msg}
	    end;
	{error, Err} ->
	    receive
		{stop, Pid} ->
		    Pid ! {received, {error, Err, Msg}}
	    end;
	{ok, Data} ->
	    listener_loop(TLSSock, <<Msg/binary, Data/binary>>)
    end.

setup_sender(Port, Opts) ->
    {ok, Socket} = gen_tcp:connect({127, 0, 0, 1}, Port, [
	binary, {packet, 0}, {active, false},
	{reuseaddr, true}, {nodelay, true}]),
    spawn(fun() ->
	{ok, TLSSock} = tcp_to_tls(Socket, [connect, {certfile, <<"../tests/cert.pem">>} | Opts]),
	sender_loop(TLSSock)
	  end).

sender_loop(TLSSock) ->
    Res = try
	      recv(TLSSock, 0, 1000),
	      ok = send(TLSSock, <<"abc">>),
	      recv(TLSSock, 0, 1000),
	      ok = send(TLSSock, <<"def">>),
	      recv(TLSSock, 0, 1000),
	      ok = send(TLSSock, <<"ghi">>),
	      recv(TLSSock, 0, 1000),
	      close(TLSSock),
	      ok
	  catch
	      _:Err ->
	      close(TLSSock),
	      Err
	  end,
    receive
	{stop, Pid} ->
	    Pid ! {result, Res}
    end.

-endif.
