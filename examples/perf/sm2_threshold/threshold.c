/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/* Performance test for SM2-threshold sign(TPS), verify(TPS), keygen(TPS) */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include <openssl/sm2_threshold.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

static long long get_time();

/* Iteration number, could be adjusted as required */
#define ITR_NUM 1000

/* Time difference on each index */
struct perf_index {
    int sm2_threshold_sign;
    int sm2_threshold_verify;
    int sm2_threshold_keygen;
};

/* Final result TPS */
struct perf_result {
    int sm2_threshold_sign_avg;
    int sm2_threshold_verify_avg;
    int sm2_threshold_keygen_avg;
};

static long long get_time()
{
    /* Use gettimeofday() to adequate for our case */
    struct timeval tp;

    if (gettimeofday(&tp, NULL) != 0)
        return 0;
    else
        return (long long)(tp.tv_sec * 1000 * 1000 + tp.tv_usec);
}

/* These values are from GM/T 0003.2-2012 standard */
static const char *userid = "ALICE123@YAHOO.COM";
static const char *message = "message digest";

int main(void)
{
    struct perf_index *indices = NULL;
    struct perf_result result;
    int msg_len = strlen(message), i = 0;
    long long start = 0, end = 0;
    EC_KEY *key1 = NULL, *key2 = NULL;
    EC_KEY *complete_key1 = NULL, *complete_key2 = NULL;
    ECDSA_SIG *sig = ECDSA_SIG_new(), *partial_sig = ECDSA_SIG_new();
    BIGNUM *w1 = BN_new();
    SM2_THRESHOLD_MSG *sign_msg = SM2_THRESHOLD_MSG_new();

    memset(&result, 0, sizeof(result));
    indices = malloc(sizeof(struct perf_index) * ITR_NUM);
    if (indices == NULL) {
        fprintf(stderr, "malloc error - indices\n");
        return -1;
    }
    memset(indices, 0, sizeof(struct perf_index) * ITR_NUM);

    for (; i < ITR_NUM; i++) {
        fprintf(stdout, "Iteration %d: ", i);

        /* SM2 threshold keygen */
        start = get_time();
        key1 = SM2_THRESHOLD_keypair_generate();
        key2 = SM2_THRESHOLD_keypair_generate();
        if (key1 == NULL || key2 == NULL)
            goto err;        
        
        complete_key1 = SM2_THRESHOLD_complete_keypair_generate(key1, key2);
        complete_key2 = SM2_THRESHOLD_complete_keypair_generate(key2, key1);
        if (complete_key1 == NULL || complete_key2 == NULL)
            goto err;
        end = get_time();
        /* Generate 2 keypair per iteration, so the result need to multiple 2 */
        indices[i].sm2_threshold_keygen = 1000 * 1000 * 2/ (end - start);

        /* SM2 threshold sign */
        start = get_time();
        if (!SM2_THRESHOLD_sign_init(complete_key1, EVP_sm3(), (const uint8_t *)userid,
                                     strlen(userid), (const uint8_t *)message, msg_len,
                                     w1, sign_msg)
                || !SM2_THRESHOLD_sign_update(complete_key2, sign_msg, partial_sig)
                || !SM2_THRESHOLD_sign_final(complete_key1, w1, partial_sig, sig))
            goto err;
        end = get_time();
        indices[i].sm2_threshold_sign = 1000 * 1000 / (end - start);

        /* SM2 threshold verify */
        start = get_time();
        if (!SM2_THRESHOLD_verify(complete_key1, EVP_sm3(), sig, (const uint8_t *)userid,
                                  strlen(userid), (const uint8_t *)message, msg_len))
            goto err;
        end = get_time();
        indices[i].sm2_threshold_verify = 1000 * 1000 / (end - start);

#if 1
        fprintf(stdout, "sm2-threshold-sign: %d, "
                        "sm2-threshold-verify: %d, "
                        "sm2-threshold-keygen: %d\n",
                        indices[i].sm2_threshold_sign, indices[i].sm2_threshold_verify,
                        indices[i].sm2_threshold_keygen);
#endif
    }

    /* calculate the final average result */
    for (i = 0; i < ITR_NUM; i++) {
        result.sm2_threshold_sign_avg += indices[i].sm2_threshold_sign;
        result.sm2_threshold_verify_avg += indices[i].sm2_threshold_verify;
        result.sm2_threshold_keygen_avg += indices[i].sm2_threshold_keygen;
    }
 
    result.sm2_threshold_sign_avg /= ITR_NUM;
    result.sm2_threshold_verify_avg /= ITR_NUM;
    result.sm2_threshold_keygen_avg /= ITR_NUM;
 
    fprintf(stdout, "sm2-threshold-sign: %d/s\n"
            "sm2-threshold-verify: %d/s\n"
            "sm2-threshold-keygen: %d/s\n",
            result.sm2_threshold_sign_avg, result.sm2_threshold_verify_avg,
            result.sm2_threshold_keygen_avg);

    return 0;
err:
    fprintf(stderr, "Error: %s\n", ERR_error_string(ERR_get_error(), NULL));
    OPENSSL_free(indices);
    EC_KEY_free(key1);
    EC_KEY_free(key2);
    EC_KEY_free(complete_key1);
    EC_KEY_free(complete_key2);
    ECDSA_SIG_free(sig);
    ECDSA_SIG_free(partial_sig);
    BN_free(w1);
    SM2_THRESHOLD_MSG_free(sign_msg);
    return -1;
}
