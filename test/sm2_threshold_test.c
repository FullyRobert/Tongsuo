/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Low level APIs are deprecated for public use, but still ok for internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include "testutil.h"

#ifndef OPENSSL_NO_SM2_THRESHOLD

# include <openssl/sm2_threshold.h>

/* These values are from GM/T 0003.2-2012 standard */
static const char *userid = "ALICE123@YAHOO.COM";
static const char *message = "message digest";

static int sm2_threshold_keygen_test(void)
{
    int testresult = 0;
    const EC_GROUP *group = NULL;
    EC_KEY *key1 = NULL, *key2 = NULL;
    EC_KEY *complete_key1 = NULL, *complete_key2 = NULL;

    /* Generate SM2 EC_KEY */
    if (!TEST_ptr(key1 = EC_KEY_new_by_curve_name(NID_sm2))
            || !TEST_true(EC_KEY_generate_key(key1))
            || !TEST_ptr(key2 = EC_KEY_new_by_curve_name(NID_sm2))
            || !TEST_true(EC_KEY_generate_key(key2))
            || !TEST_ptr(group = EC_KEY_get0_group(key1)))
        goto err;   

    /* Generate SM2 threshold partial public key */
    if (!TEST_true(SM2_THRESHOLD_partial_pubkey_generate(key1))
            || !TEST_true(SM2_THRESHOLD_partial_pubkey_generate(key2)))
        goto err;        
    
    /*
     * Generate a complete threshold public key using partial 
     * public key from another participant
     */
    if (!TEST_ptr(complete_key1 = SM2_THRESHOLD_complete_keypair_generate(key1, key2))
            || !TEST_ptr(complete_key2 = SM2_THRESHOLD_complete_keypair_generate(key2, key1)))
        goto err;

    /* Compare if two complete public keys are equal */
    if (!TEST_false(EC_POINT_cmp(group, EC_KEY_get0_public_key(complete_key1), EC_KEY_get0_public_key(complete_key2), NULL)))
        goto err;

    testresult = 1;
err:
    EC_KEY_free(key1);
    EC_KEY_free(key2);
    EC_KEY_free(complete_key1);
    EC_KEY_free(complete_key2);
    
    return testresult;
}

static int sm2_threshold_sign_test(int flag)
{
    int msg_len = strlen(message);
    int verify_status1 = 0 , verify_status2 = 0;
    EC_KEY *key1 = NULL, *key2 = NULL;
    EC_KEY *complete_key1 = NULL, *complete_key2 = NULL;
    ECDSA_SIG *sig = ECDSA_SIG_new(), *partial_sig = ECDSA_SIG_new();
    BIGNUM *w1 = BN_new();
    SM2_THRESHOLD_MSG *sign_msg = SM2_THRESHOLD_MSG_new();

    /* Generate SM2 threshold private key with partial public key */
    if (!TEST_ptr(key1 = SM2_THRESHOLD_keypair_generate())
            || !TEST_ptr(key2 = SM2_THRESHOLD_keypair_generate()))
        goto err;        

    /*
     * Generate a complete threshold public key using partial 
     * public key from another participant
     */
    if (!TEST_ptr(complete_key1 = SM2_THRESHOLD_complete_keypair_generate(key1, key2))
            || !TEST_ptr(complete_key2 = SM2_THRESHOLD_complete_keypair_generate(key2, key1)))
        goto err;

    /* Test SM2 threshold sign with id */
    if (flag == 0) {
        /* SM2 threshold signature */
        if (!TEST_true(SM2_THRESHOLD_sign_init(complete_key1, EVP_sm3(), (const uint8_t *)userid,
                                               strlen(userid), (const uint8_t *)message, msg_len,
                                               w1, sign_msg))
                || !TEST_true(SM2_THRESHOLD_sign_update(complete_key2, sign_msg, partial_sig))
                || !TEST_true(SM2_THRESHOLD_sign_final(complete_key1, w1, partial_sig, sig)))
            goto err;

        /* Verify signature using complete threshold public key */
        verify_status1 = SM2_THRESHOLD_verify(complete_key1, EVP_sm3(), sig, (const uint8_t *)userid,
                                              strlen(userid), (const uint8_t *)message, msg_len);
        verify_status2 = SM2_THRESHOLD_verify(complete_key2, EVP_sm3(), sig, (const uint8_t *)userid,
                                              strlen(userid), (const uint8_t *)message, msg_len);
    }
    /* Test SM2 threshold sign without id */
    else {
        /* SM2 threshold signature */
        if (!TEST_true(SM2_THRESHOLD_sign_init(complete_key1, EVP_sm3(), NULL, 0,
                                               (const uint8_t *)message, msg_len,
                                               w1, sign_msg))
                || !TEST_true(SM2_THRESHOLD_sign_update(complete_key2, sign_msg, partial_sig))
                || !TEST_true(SM2_THRESHOLD_sign_final(complete_key1, w1, partial_sig, sig)))
            goto err;

        /* Verify signature using complete threshold public key */
        verify_status1 = SM2_THRESHOLD_verify(complete_key1, EVP_sm3(), sig, NULL, 0,
                                              (const uint8_t *)message, msg_len);
        verify_status2 = SM2_THRESHOLD_verify(complete_key2, EVP_sm3(), sig, NULL, 0,
                                              (const uint8_t *)message, msg_len);
    }

    /* Both complete public keys from two parties should be able to 
     * verify the signature successfully with the same id
     */
    TEST_true(verify_status1 && verify_status2);

err:
    EC_KEY_free(key1);
    EC_KEY_free(key2);
    EC_KEY_free(complete_key1);
    EC_KEY_free(complete_key2);
    ECDSA_SIG_free(sig);
    ECDSA_SIG_free(partial_sig);
    BN_free(w1);
    SM2_THRESHOLD_MSG_free(sign_msg);
    
    return verify_status1 && verify_status2;
}

#endif

int setup_tests(void)
{
#ifdef OPENSSL_NO_SM2_THRESHOLD
    TEST_note("SM2 threshold is disabled.");
#else
    ADD_TEST(sm2_threshold_keygen_test);
    ADD_ALL_TESTS(sm2_threshold_sign_test, 2);
#endif
    return 1;
}
