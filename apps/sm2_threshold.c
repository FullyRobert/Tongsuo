/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sm2_threshold.h>
#include <openssl/ec.h>
#include <internal/cryptlib.h>

#undef MAXSIZE
#define MAXSIZE 1024*1024*8

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_KEYGEN, OPT_PUBKEY, OPT_CKEYGEN,
    OPT_SIGN_INIT, OPT_SIGN_UPDATE, OPT_SIGN_FINAL, OPT_VERIFY,
    OPT_KEY_IN, OPT_PUBKEY_IN, OPT_SIGNATURE_IN,
    OPT_OUT, OPT_RAND_OUT,
} OPTION_CHOICE;

const OPTIONS sm2_threshold_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [action options] [input/output options] [file]\n"},

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},

    OPT_SECTION("Key-Action"),
    {"keygen", OPT_KEYGEN, '-', "Generate a SM2 threshold keypair, including a private key and a partial public key"},
    {"pubkey", OPT_PUBKEY, '-', "Extract a partial or complete public key from SM2 threshold key pairs"},
    {"ckeygen", OPT_CKEYGEN, '-', "Generate a SM2 complete public key, output a complete keypair"},

    OPT_SECTION("Sign-Action"),
    {"sign_init", OPT_SIGN_INIT, '-', "Compute the 1st part of SM2 threshold signature"},
    {"sign_update", OPT_SIGN_UPDATE, '-', "Compute the 2nd part of SM2 threshold signature"},
    {"sign_final", OPT_SIGN_FINAL, '-', "Compute the 3rd part of SM2 threshold signature"},
    {"verify", OPT_VERIFY, '-', "Verify a SM2 threshold signature using complete public key"},

    OPT_SECTION("Input"),
    {"key_in", OPT_KEY_IN, '<', "Input a SM2 threshold (partial or complete) keypair"},
    {"pubkey_in", OPT_PUBKEY_IN, '<', "Input a SM2 threshold (partial or complete) public key"},
    {"signature_in", OPT_SIGNATURE_IN, '<', "Input a SM2 threshold signature"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output the SM2 threshold result to specified file"},
    {"rand_out", OPT_RAND_OUT, '>', "Output the SM2 threshold random number to specified file"},

    OPT_PARAMETERS(),
    {"file", 0, 0, "Data file involved in SM2 threshold sign or verify"},
    {NULL}
};

static int readbuf(const char *filename, unsigned char **buf);
static int sm2_threshold_keygen(BIO *out);
static int sm2_threshold_pubkey(BIO *key_in, BIO *out);
static int sm2_threshold_ckeygen(BIO *key_in, BIO *pubkey_in, BIO *out);
static int sm2_threshold_sign_init(BIO *key_in, BIO *rand_out, BIO *out, 
                                   const unsigned char *msgbuf, int msglen);
static int sm2_threshold_sign_update(BIO *key_in, BIO *out, 
                                     const unsigned char *msgbuf, int msglen);
static int sm2_threshold_sign_final(BIO *key_in, BIO *out, 
                                    const unsigned char *msgbuf, int msglen,
                                    const unsigned char *psigbuf, int psiglen);
static int sm2_threshold_verify(BIO *pubkey_in, BIO * out, 
                                const unsigned char *msgbuf, int msglen, 
                                const unsigned char *sigbuf, int siglen);

int sm2_threshold_main(int argc, char **argv)
{
    BIO *out = NULL, *rand_out = NULL, *key_in = NULL, *pubkey_in = NULL;
    int ret = 1, msglen = 0, siglen = 0;
    int key_action_sum = 0, sign_action_sum = 0, action_sum = 0;
    int keygen = 0, pubkey = 0, ckeygen = 0;
    int sign_init = 0, sign_update = 0, sign_fianl = 0, verify = 0;
    char *key_file = NULL, *pubkey_file = NULL, *sig_file = NULL, *rand_file = NULL;
    char *outfile = NULL; 
    char *prog;
    unsigned char *msgbuf = NULL, *sigbuf = NULL;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, sm2_threshold_options);
    if ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp1:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(sm2_threshold_options);
            goto end;
        case OPT_KEYGEN:
            keygen = 1;
            break;
        case OPT_PUBKEY:
            pubkey = 1;
            break;
        case OPT_CKEYGEN:
            ckeygen = 1;
            break;
        case OPT_SIGN_INIT:
            sign_init = 1;
            break;
        case OPT_SIGN_UPDATE:
            sign_update = 1;
            break;
        case OPT_SIGN_FINAL:
            sign_fianl = 1;
            break;
        case OPT_VERIFY:
            verify = 1;
            break;
        default:
            goto opthelp1;
        }
    }

    key_action_sum = keygen + pubkey + ckeygen;
    sign_action_sum = sign_init + sign_update + sign_fianl + verify;
    action_sum = key_action_sum + sign_action_sum;
    if (action_sum == 0) {
        BIO_printf(bio_err, "No action parameter specified.\n");
        goto opthelp1;
    } else if (action_sum != 1) {
        BIO_printf(bio_err, "Only one action parameter must be specified.\n");
        goto opthelp1;
    }

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp2:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(sm2_threshold_options);
            goto end;
        case OPT_KEY_IN:
            key_file = opt_arg();
            break;
        case OPT_PUBKEY_IN:
            pubkey_file = opt_arg();
            break;
        case OPT_SIGNATURE_IN:
            sig_file = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_RAND_OUT:
            rand_file = opt_arg();
            break;
        default:
            goto opthelp2;
            break;
        }
    }

    argc = opt_num_rest();
    argv = opt_rest();

    if (sign_action_sum) { 
        if (argc > 1) {
            BIO_printf(bio_err, "%s: Can only read one file.\n", prog);
            goto opthelp2;
        }
    }
    else if (argc > 0) {
        BIO_printf(bio_err, "Extra arguments given.\n");
        goto opthelp2;
    }

    if (!app_RAND_load())
        goto end;
    
    if (ckeygen + pubkey + sign_action_sum - verify == 1) {
        if (key_file == NULL) {
            BIO_printf(bio_err, "No SM2 threshold key file path specified.\n");
            goto end;
        }

        key_in = bio_open_default(key_file, 'r', FORMAT_PEM);
        if (key_in == NULL)
            goto end;
    }

    if (ckeygen + verify == 1) {
        if (pubkey_file == NULL) {
            BIO_printf(bio_err, "No SM2 threshold pubkey file path specified.\n");
            goto end;
        }

        pubkey_in = bio_open_default(pubkey_file, 'r', FORMAT_PEM);
        if (pubkey_in == NULL)
            goto end;
    }

    if (key_action_sum)
        out = bio_open_owner(outfile, FORMAT_PEM, 1);
    else
        out = bio_open_default(outfile, 'w', 
                               verify ? FORMAT_TEXT : FORMAT_BINARY);
    if (out == NULL)
        goto end;

    if (keygen)
        ret = sm2_threshold_keygen(out);
    else if (pubkey)
        ret = sm2_threshold_pubkey(key_in, out);
    else if (ckeygen)
        ret = sm2_threshold_ckeygen(key_in, pubkey_in, out);
    else if (sign_action_sum) {
        msglen = readbuf(argv[0], &msgbuf);
        if (msglen == -1)
            goto end;

        if (sign_init) {
            rand_out = bio_open_default(rand_file, 'w', FORMAT_BINARY);
            if (rand_out == NULL)
                goto end;
            
            ret = sm2_threshold_sign_init(key_in, rand_out, out, msgbuf, msglen);
        }
        else if (sign_update)
            ret = sm2_threshold_sign_update(key_in, out, msgbuf, msglen);
        else {
            siglen = readbuf(sig_file, &sigbuf);
            /* siglen can not equal to 0 */
            if (siglen <= 0)
                goto end;

            if (sign_fianl)
                ret = sm2_threshold_sign_final(key_in, out, msgbuf,
                                               msglen, sigbuf, siglen);
            else if (verify)
                ret = sm2_threshold_verify(pubkey_in, out, msgbuf,
                                           msglen, sigbuf, siglen);
        }
    }

    ret = ret ? 0 : 1;
 end:
    OPENSSL_free(msgbuf);
    OPENSSL_free(sigbuf);
    BIO_free(key_in);
    BIO_free(pubkey_in);
    BIO_free(out);
    BIO_free(rand_out);
    
    if (ret != 0) {
        BIO_printf(bio_err, "Maybe some errors occured, please use -help for usage summary.\n");
        ERR_print_errors(bio_err);
    }
    return ret;
}

static int readbuf(const char *filename, unsigned char **buf)
{
    int len = 0;
    BIO *in = BIO_new_file(filename, "rb");
    
    if (in == NULL) {
        BIO_printf(bio_err, "Error opening file %s\n", filename);
        return -1;
    }

    len = bio_to_mem(buf, MAXSIZE, in);
    if (len == -1)
        BIO_printf(bio_err, "Error reading file %s\n", filename);

    BIO_free(in);

    return len;
}

static int sm2_threshold_keygen(BIO *out)
{
    int ret = 0;
    EC_KEY *key = NULL;

    if (!(key = SM2_THRESHOLD_keypair_generate()))
        goto err;

    if (!PEM_write_bio_ECPrivateKey(out, key, NULL, NULL, 0, NULL, NULL))
        goto err;

    ret = 1;
err:
    EC_KEY_free(key);
    return ret;
}

static int sm2_threshold_pubkey(BIO *key_in, BIO *out)
{
    int ret = 0;
    EC_KEY *key = NULL;

    if (!(key = PEM_read_bio_ECPrivateKey(key_in ,NULL, NULL, NULL)))
        goto err;

    if (!PEM_write_bio_EC_PUBKEY(out, key))
        goto err;

    ret = 1;
err:
    EC_KEY_free(key);
    return ret;
}

static int sm2_threshold_ckeygen(BIO *key_in, BIO *pubkey_in, BIO *out)
{
    int ret = 0;
    EC_KEY *key = NULL, *pubkey = NULL, *ckey = NULL;

    if (!(key = PEM_read_bio_ECPrivateKey(key_in, NULL, NULL, NULL))
            || !(pubkey = PEM_read_bio_EC_PUBKEY(pubkey_in, NULL, NULL, NULL)))
        goto err;

    if (!(ckey = SM2_THRESHOLD_complete_keypair_generate(key, pubkey)))
        goto err;

    if (!PEM_write_bio_ECPrivateKey(out, ckey, NULL, NULL, 0, NULL, NULL))
        goto err;

    ret = 1;
err:
    EC_KEY_free(key);
    EC_KEY_free(pubkey);
    EC_KEY_free(ckey);

    return ret;
}

static int sm2_threshold_sign_init(BIO *key_in, BIO *rand_out, BIO *out, 
                                   const unsigned char *msgbuf, int msglen)
{
    int ret = 0;
    size_t encode_msg_len = 0, rand_len = 0;
    EC_KEY *key = NULL;
    BIGNUM *w1 = BN_new();
    SM2_THRESHOLD_MSG *sign_msg = SM2_THRESHOLD_MSG_new();
    unsigned char *encode_msg = NULL, *encode_rand = NULL;

    if (!(key = PEM_read_bio_ECPrivateKey(key_in, NULL, NULL, NULL)))
        goto err;

    if (!SM2_THRESHOLD_sign_init(key, EVP_sm3(), NULL, 0,
                                (const uint8_t *)msgbuf, msglen, w1, sign_msg)) {
        BIO_printf(bio_err, "Error signing data\n");
        goto err;
    }
    
    /* Encoding SM2_THRESHOLD_MSG and w1, then writing to specified files */
    encode_msg_len = SM2_THRESHOLD_MSG_encode(key, sign_msg, NULL, 0);
    if (!(encode_msg = app_malloc(encode_msg_len, "SM2_THRESHOLD_MSG buffer")))
        goto err;
    if (!(SM2_THRESHOLD_MSG_encode(key, sign_msg, encode_msg, encode_msg_len)))
        goto err;

    BIO_write(out, encode_msg, encode_msg_len);

    rand_len = (EC_GROUP_order_bits(EC_KEY_get0_group(key)) + 7) / 8;
    if (!(encode_rand = app_malloc(rand_len, "Random number buffer"))
            || BN_bn2binpad(w1, encode_rand, rand_len) == -1)
        goto err;
    
    BIO_write(rand_out, encode_rand, rand_len);

    ret = 1;
 err:
    EC_KEY_free(key);
    BN_free(w1);
    SM2_THRESHOLD_MSG_free(sign_msg);
    OPENSSL_clear_free(encode_msg, encode_msg_len);
    OPENSSL_clear_free(encode_rand, rand_len);

    return ret;
}

static int sm2_threshold_sign_update(BIO *key_in, BIO *out, 
                                     const unsigned char *msgbuf, int msglen)
{
    int ret = 0, siglen = 0;
    EC_KEY *key = NULL;
    ECDSA_SIG *partial_sig = ECDSA_SIG_new();
    SM2_THRESHOLD_MSG *sign_msg = SM2_THRESHOLD_MSG_new();
    unsigned char *out_sig = NULL;

    if (!(key = PEM_read_bio_ECPrivateKey(key_in, NULL, NULL, NULL)))
        goto err;

    if (!SM2_THRESHOLD_MSG_decode(key, sign_msg, msgbuf, msglen)
            || !SM2_THRESHOLD_sign_update(key, sign_msg, partial_sig)) {
        BIO_printf(bio_err, "Error signing data\n");
        goto err;
    }
   
    siglen = i2d_ECDSA_SIG(partial_sig, &out_sig);
    if (siglen <= 0) {
        BIO_printf(bio_err, "Error occur when output signature\n");
        goto err;
    }
    BIO_write(out, out_sig, siglen);

    ret = 1;
 err:
    EC_KEY_free(key);
    ECDSA_SIG_free(partial_sig);
    SM2_THRESHOLD_MSG_free(sign_msg);
    OPENSSL_clear_free(out_sig, siglen);

    return ret;
}

static int sm2_threshold_sign_final(BIO *key_in, BIO *out, 
                                    const unsigned char *msgbuf, int msglen,
                                    const unsigned char *psigbuf, int psiglen)
{
    int ret = 0, siglen = 0;
    EC_KEY *key;
    ECDSA_SIG *sig = ECDSA_SIG_new(), *partial_sig = ECDSA_SIG_new();
    BIGNUM *w1 = BN_new();
    unsigned char *out_sig = NULL;

    if (!(key = PEM_read_bio_ECPrivateKey(key_in, NULL, NULL, NULL)))
        goto err;
    
    /* Read w1 and partial_sig from buffer */
    if (!BN_bin2bn(msgbuf, msglen, w1)
            || !d2i_ECDSA_SIG(&partial_sig, &psigbuf, psiglen))
        goto err;

    if (!SM2_THRESHOLD_sign_final(key, w1, partial_sig, sig)) {
        BIO_printf(bio_err, "Error signing data\n");
        goto err;
    }
   
    siglen = i2d_ECDSA_SIG(sig, &out_sig);
    if (siglen <= 0) {
        BIO_printf(bio_err, "Error occur when output signature\n");
        goto err;
    }
    BIO_write(out, out_sig, siglen);

    ret = 1;
 err:
    EC_KEY_free(key);
    ECDSA_SIG_free(sig);
    ECDSA_SIG_free(partial_sig);
    BN_free(w1);
    OPENSSL_clear_free(out_sig, siglen);

    return ret;
}

static int sm2_threshold_verify(BIO *pubkey_in, BIO * out, 
                                const unsigned char *msgbuf, int msglen, 
                                const unsigned char *sigbuf, int siglen)
{
    int ret = 0, status = 0;
    EC_KEY *pubkey = NULL;
    ECDSA_SIG *sig = ECDSA_SIG_new();

    if (!(pubkey = PEM_read_bio_EC_PUBKEY(pubkey_in, NULL, NULL, NULL)))
        goto end;

    if (d2i_ECDSA_SIG(&sig, &sigbuf, siglen) == NULL)
        goto end;

    status = SM2_THRESHOLD_verify(pubkey, EVP_sm3(), sig, NULL, 0,
                                  (const uint8_t *)msgbuf, msglen);

    ret = 1;
 end:
    if (status == 0)
        BIO_printf(out, "Verification failure\n");
    else
        BIO_printf(out, "Verified OK\n");
    
    EC_KEY_free(pubkey);
    ECDSA_SIG_free(sig);

    return ret;
}
