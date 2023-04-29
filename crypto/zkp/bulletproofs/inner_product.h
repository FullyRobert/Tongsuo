/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_BP_INNER_PRODUCT_LOCAL_H
# define HEADER_BP_INNER_PRODUCT_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/bn.h>
# include <openssl/ec.h>
# include "internal/refcount.h"
# include "transcript.h"

typedef struct bp_inner_product_pub_param_st {
    int curve_id;
    int initial;
    int n;
    EC_POINT **vec_G;
    EC_POINT **vec_H;
} bp_inner_product_pub_param_t;

typedef struct bp_inner_product_ctx_st {
    BP_TRANSCRIPT *transcript;
    EC_GROUP *group;
    EC_POINT *P;
    EC_POINT *U;
    int factors_num;
    BIGNUM **vec_G_factors;
    BIGNUM **vec_H_factors;
    bp_inner_product_pub_param_t *pp;
} bp_inner_product_ctx_t;

typedef struct bp_inner_product_witness_st {
    int n;
    BIGNUM **vec_a;
    BIGNUM **vec_b;
} bp_inner_product_witness_t;

typedef struct bp_inner_product_proof_st {
    int n;
    EC_POINT **vec_L;
    EC_POINT **vec_R;
    BIGNUM *a;
    BIGNUM *b;
} bp_inner_product_proof_t;

bp_inner_product_pub_param_t *bp_inner_product_pub_param_new(int curve_id);
int bp_inner_product_pub_param_set(bp_inner_product_pub_param_t *pp,
                                   EC_POINT **vec_G, EC_POINT **vec_H,
                                   int n);
int bp_inner_product_pub_param_gen(bp_inner_product_pub_param_t *pp, int n);
void bp_inner_product_pub_param_free(bp_inner_product_pub_param_t *pp);
bp_inner_product_ctx_t *bp_inner_product_ctx_new(bp_inner_product_pub_param_t *pp,
                                                 BP_TRANSCRIPT *transcript,
                                                 EC_POINT *U, EC_POINT *P,
                                                 BIGNUM **vec_G_factors,
                                                 BIGNUM **vec_H_factors,
                                                 int factors_num);
void bp_inner_product_ctx_free(bp_inner_product_ctx_t *ctx);
bp_inner_product_witness_t *bp_inner_product_witness_new(BIGNUM **vec_a,
                                                         BIGNUM **vec_b,
                                                         int n);
void bp_inner_product_witness_free(bp_inner_product_witness_t *witness);
bp_inner_product_proof_t *bp_inner_product_proof_alloc(int n);
bp_inner_product_proof_t *bp_inner_product_proof_new(bp_inner_product_ctx_t *ctx);
void bp_inner_product_proof_free(bp_inner_product_proof_t *proof);
int bp_inner_product_proof_prove(bp_inner_product_ctx_t *ctx,
                                 bp_inner_product_witness_t *witness,
                                 bp_inner_product_proof_t *proof);
int bp_inner_product_proof_verify(bp_inner_product_ctx_t *ctx,
                                  bp_inner_product_proof_t *proof);

# ifdef  __cplusplus
}
# endif

#endif

