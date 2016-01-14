/*
 * Copyright (C) 2002-2016 ProcessOne, SARL. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <erl_nif.h>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>

#define SHA1_T 1
#define SHA224_T 224
#define SHA256_T 256
#define SHA384_T 384
#define SHA512_T 512

static int load(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info)
{
    return 0;
}

static int convert(ErlNifEnv* env, int argc,
		   const ERL_NIF_TERM argv[],
		   int type, ErlNifBinary *out)
{
    ErlNifBinary in;
    int res = 0;
    
    if (argc == 1) {
	if (enif_inspect_iolist_as_binary(env, argv[0], &in)) {
	    switch (type) {
	    case SHA1_T:
		res = enif_alloc_binary(SHA_DIGEST_LENGTH, out);
		if (res) SHA1(in.data, in.size, out->data);
		break;
	    case SHA224_T:
		res = enif_alloc_binary(SHA224_DIGEST_LENGTH, out);
		if (res) SHA224(in.data, in.size, out->data);
		break;
	    case SHA256_T:
		res = enif_alloc_binary(SHA256_DIGEST_LENGTH, out);
		if (res) SHA256(in.data, in.size, out->data);
		break;
	    case SHA384_T:
		res = enif_alloc_binary(SHA384_DIGEST_LENGTH, out);
		if (res) SHA384(in.data, in.size, out->data);
		break;
	    case SHA512_T:
		res = enif_alloc_binary(SHA512_DIGEST_LENGTH, out);
		if (res) SHA512(in.data, in.size, out->data);
		break;
	    }
	}
    }

    return res;
}

static ERL_NIF_TERM sha1(ErlNifEnv* env, int argc,
			 const ERL_NIF_TERM argv[])
{
    ErlNifBinary out;

    if (convert(env, argc, argv, SHA1_T, &out))
	return enif_make_binary(env, &out);
    else
	return enif_make_badarg(env);
}

static ERL_NIF_TERM sha224(ErlNifEnv* env, int argc,
			   const ERL_NIF_TERM argv[])
{
    ErlNifBinary out;

    if (convert(env, argc, argv, SHA224_T, &out))
	return enif_make_binary(env, &out);
    else
	return enif_make_badarg(env);
}

static ERL_NIF_TERM sha256(ErlNifEnv* env, int argc,
			   const ERL_NIF_TERM argv[])
{
    ErlNifBinary out;

    if (convert(env, argc, argv, SHA256_T, &out))
	return enif_make_binary(env, &out);
    else
	return enif_make_badarg(env);
}

static ERL_NIF_TERM sha384(ErlNifEnv* env, int argc,
			   const ERL_NIF_TERM argv[])
{
    ErlNifBinary out;

    if (convert(env, argc, argv, SHA384_T, &out))
	return enif_make_binary(env, &out);
    else
	return enif_make_badarg(env);
}

static ERL_NIF_TERM sha512(ErlNifEnv* env, int argc,
			   const ERL_NIF_TERM argv[])
{
    ErlNifBinary out;

    if (convert(env, argc, argv, SHA512_T, &out))
	return enif_make_binary(env, &out);
    else
	return enif_make_badarg(env);
}

static ERL_NIF_TERM to_hexlist(ErlNifEnv* env, int argc,
			       const ERL_NIF_TERM argv[])
{
    ErlNifBinary in;
    ErlNifBinary out;
    int res, i;

    if (argc == 1) {
	if (enif_inspect_iolist_as_binary(env, argv[0], &in)) {
	    res = enif_alloc_binary(2*in.size, &out);
	    if (res) {
		for (i = 0; i<in.size; i++) {
		    sprintf((char *) (out.data + 2*i), "%02x", in.data[i]);
		}
		return enif_make_binary(env, &out);
	    }
	}
    }

    return enif_make_badarg(env);
}

static ErlNifFunc nif_funcs[] =
    {
	{"sha1", 1, sha1},
	{"sha224", 1, sha224},
	{"sha256", 1, sha256},
	{"sha384", 1, sha384},
	{"sha512", 1, sha512},
	{"to_hexlist", 1, to_hexlist}
    };

ERL_NIF_INIT(p1_sha, nif_funcs, load, NULL, NULL, NULL)
