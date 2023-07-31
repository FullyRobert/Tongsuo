/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "internal/deprecated.h"

#include "crypto/sm2.h"
#include "crypto/sm2err.h"
#include "crypto/ec.h"
#include "internal/numbers.h"
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/sm2_threshold.h>

struct sm2_threshold_message_st {
    /* the message digest */
    BIGNUM *e;
    /* the EC_POINT represent [w1]*G */
    EC_POINT *Q1;
};

SM2_THRESHOLD_MSG *SM2_THRESHOLD_MSG_new(void)
{
    SM2_THRESHOLD_MSG *msg = OPENSSL_zalloc(sizeof(*msg));
    
    if (msg == NULL)
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);

    return msg;
}

void SM2_THRESHOLD_MSG_free(SM2_THRESHOLD_MSG *msg)
{
    if (msg == NULL)
        return;
    BN_clear_free(msg->e);
    EC_POINT_free(msg->Q1);
    OPENSSL_free(msg);
}

static const BIGNUM *SM2_THRESHOLD_MSG_get0_e(const SM2_THRESHOLD_MSG *msg)
{
    return msg->e;
}

static const EC_POINT *SM2_THRESHOLD_MSG_get0_Q1(const SM2_THRESHOLD_MSG *msg)
{
    return msg->Q1;
}

static int SM2_THRESHOLD_MSG_set0(SM2_THRESHOLD_MSG *msg,
                                  BIGNUM *e , EC_POINT *Q1)
{
    if (msg == NULL || e == NULL || Q1 == NULL)
        return 0;

    BN_clear_free(msg->e);
    EC_POINT_free(msg->Q1);
    msg->e = e;
    msg->Q1 = Q1;

    return 1;
}

int SM2_THRESHOLD_partial_pubkey_generate(EC_KEY *key)
{
    int ret = 0;
    const BIGNUM *dA = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pkey = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *dA_inv = NULL;
    OSSL_LIB_CTX *libctx = ossl_ec_key_get_libctx(key);

    pkey = EC_POINT_new(group);
    ctx = BN_CTX_new_ex(libctx);
    if (pkey == NULL || ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    dA_inv = BN_CTX_get(ctx);
    if (dA_inv == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /* 
     * Compute the partial public key: 
     *    P_1 = dA_1^(-1) * G 
     */
    if (!ossl_ec_group_do_inverse_ord(group, dA_inv, dA, ctx)
            || !EC_POINT_mul(group, pkey, dA_inv, NULL, NULL, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    /* Set key->pub_key with threshold partial public key */
    if (!EC_KEY_set_public_key(key, pkey)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    ret = 1;
 done:
    EC_POINT_free(pkey);
    BN_CTX_free(ctx);
    return ret;
}

EC_KEY *SM2_THRESHOLD_keypair_generate(void)
{
    EC_KEY *key = NULL;

    if (((key = EC_KEY_new_by_curve_name(NID_sm2)) == NULL)
            || !EC_KEY_generate_key(key)
            || !SM2_THRESHOLD_partial_pubkey_generate(key)) {
        EC_KEY_free(key);
        return NULL;
    }

    return key;
}

EC_KEY *SM2_THRESHOLD_complete_pubkey_generate(const EC_KEY *key, 
                                               const EC_KEY *pkey)
{
    int ret = 0;
    const BIGNUM *dA = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_KEY *complete_key = NULL;
    EC_POINT *complete_pubkey = NULL;
    EC_POINT *g = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *dA_inv = NULL;
    OSSL_LIB_CTX *libctx = ossl_ec_key_get_libctx(key);

    if (key == NULL || pkey == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        goto done;
    }

    complete_key = EC_KEY_dup(key);
    complete_pubkey = EC_POINT_new(group);
    g = EC_POINT_new(group);
    ctx = BN_CTX_new_ex(libctx);
    if (complete_key == NULL || complete_pubkey == NULL 
            || g == NULL || ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    dA_inv = BN_CTX_get(ctx);
    if (dA_inv == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    
    /* 
     * Compute the complete public key:
     *    P = dA_2^(-1) * pkey - G 
     */
    if (!ossl_ec_group_do_inverse_ord(group, dA_inv, dA, ctx)
            || !EC_POINT_mul(group, complete_pubkey, NULL, 
                             EC_KEY_get0_public_key(pkey), dA_inv, ctx)
            || !EC_POINT_copy(g, EC_GROUP_get0_generator(group))
            || !EC_POINT_invert(group, g, ctx)
            || !EC_POINT_add(group, complete_pubkey, complete_pubkey, g, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    /* Set key->pub_key with threshold public key */
    if (!EC_KEY_set_public_key(complete_key, complete_pubkey)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    ret = 1;

 done:
    if (ret == 0)
        EC_KEY_free(complete_key);

    BN_CTX_free(ctx);
    EC_POINT_free(g);
    EC_POINT_free(complete_pubkey);

    return complete_key;
}

static int SM2_THRESHOLD_sign_init_internal(const EC_KEY *key, 
                                            EC_POINT *Q1, BIGNUM *w1)
{
    int ret = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *ctx = NULL;
    OSSL_LIB_CTX *libctx = ossl_ec_key_get_libctx(key);

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    /*
     * SM2 threshold signature part 1:
     * 1. Generate a random number w1 in [1,n-1] using random number generators;
     * 2. Compute Q1 = [w1]G.
     */
    if (!BN_priv_rand_range_ex(w1, order, 0, ctx)
            || !EC_POINT_mul(group, Q1, w1, NULL, NULL, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    ret = 1;
 done:
    BN_CTX_free(ctx);

    return ret; 
}

int SM2_THRESHOLD_sign_init(const EC_KEY *key,
                            const EVP_MD *digest,
                            const uint8_t *id,
                            const size_t id_len,
                            const uint8_t *msg, size_t msg_len,
                            BIGNUM *w1, SM2_THRESHOLD_MSG *sign_msg)
{
    int ret = 0;
    BIGNUM *e = NULL;
    EC_POINT *Q1 = EC_POINT_new(EC_KEY_get0_group(key));

    if (w1 == NULL || sign_msg == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        goto done;
    }

    if (Q1 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    e = ossl_sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
    if (e == NULL) {
        /* SM2err already called */
        goto done;
    }

    if (!SM2_THRESHOLD_sign_init_internal(key, Q1, w1)){
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    if (!SM2_THRESHOLD_MSG_set0(sign_msg, e, Q1)){
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    ret = 1;

 done:
    if (ret == 0){
        BN_free(e);
        EC_POINT_free(Q1);
    }

    return ret;
}

int SM2_THRESHOLD_sign_update(const EC_KEY *key, const SM2_THRESHOLD_MSG *msg,
                              ECDSA_SIG *partial_sig)
{
    int ret = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *dA = EC_KEY_get0_private_key(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    EC_POINT *Q1 = NULL;
    EC_POINT *Q = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *dA_inv = NULL;
    BIGNUM *w2 = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s1 = NULL;
    OSSL_LIB_CTX *libctx = ossl_ec_key_get_libctx(key);

    if (msg == NULL || partial_sig == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        goto done;
    }

    Q1 = EC_POINT_dup(SM2_THRESHOLD_MSG_get0_Q1(msg), group);
    Q = EC_POINT_new(group);
    ctx = BN_CTX_new_ex(libctx);
    if (Q == NULL || ctx == NULL || Q1 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    dA_inv = BN_CTX_get(ctx);
    w2 = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    if (dA_inv == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /*
     * These values are returned and so should not be allocated out of the
     * context
     */
    r = BN_new();
    s1 = BN_new();

    if (r == NULL || s1 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /*
     * SM2 threshold signature part 2:
     * 1. Generate a random number w2 in [1,n-1] using random number generators;
     * 2. Compute Q = [w2]G + dA^(-1) * Q1
     * 3. Compute r = (e + x1) mod n
     * 4. Compute s1 = dA(r + w2) mod n
     */
    if (!BN_priv_rand_range_ex(w2, order, 0, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    if (!EC_POINT_mul(group, Q, w2, NULL, NULL, ctx)
            || !ossl_ec_group_do_inverse_ord(group, dA_inv, dA, ctx)
            || !EC_POINT_mul(group, Q1, NULL, Q1, dA_inv, ctx)
            || !EC_POINT_add(group, Q, Q, Q1, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }
    
    if (!EC_POINT_get_affine_coordinates(group, Q, x1, NULL,ctx)
            || !BN_mod_add(r, SM2_THRESHOLD_MSG_get0_e(msg), x1, order, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    if (!BN_add(s1, r, w2)
            || !BN_mod_mul(s1, s1, dA, order, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    /* a "partial" signature to stored r and s1 */
    if (!ECDSA_SIG_set0(partial_sig, r, s1)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    ret = 1;

 done:
    if (ret == 0) {
        BN_free(r);
        BN_free(s1);
    }

    EC_POINT_free(Q);
    EC_POINT_free(Q1);
    BN_CTX_free(ctx);

    return ret;
}

int SM2_THRESHOLD_sign_final(const EC_KEY *key, const BIGNUM *w1, 
                             const ECDSA_SIG *partial_sig,
                             ECDSA_SIG *final_sig)
{   
    int ret = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *dA = EC_KEY_get0_private_key(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *ctx = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    OSSL_LIB_CTX *libctx = ossl_ec_key_get_libctx(key);

    if (w1 == NULL || partial_sig == NULL || final_sig == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        goto done;
    }

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    BN_CTX_start(ctx);

    /*
     * These values are returned and so should not be allocated out of the
     * context
     */
    r = BN_dup(ECDSA_SIG_get0_r(partial_sig));
    s = BN_new();

    if (r == NULL || s == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    
    /*
     * SM2 threshold signature part 3:
     * 1. Compute s = (d1(s1 + w1) - r) mod n
     * 2. Return sig(r,s)
     */
    if (!BN_add(s, ECDSA_SIG_get0_s(partial_sig), w1)
            || !BN_mod_mul(s, s, dA, order, ctx)
            || !BN_mod_sub(s, s, r, order, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    /* takes ownership of r and s */
    if (!ECDSA_SIG_set0(final_sig, r, s)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    ret = 1;

 done:
    if (ret == 0) {
        BN_free(r);
        BN_free(s);
    }

    BN_CTX_free(ctx);

    return ret;
}

int SM2_THRESHOLD_verify(const EC_KEY *key,
                         const EVP_MD *digest,
                         const ECDSA_SIG *sig,
                         const uint8_t *id,
                         const size_t id_len,
                         const uint8_t *msg, size_t msg_len)
{
    return ossl_sm2_do_verify(key, digest, sig, id, id_len, msg, msg_len);
}
