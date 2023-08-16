/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_SM2_THRESHOLD_H
# define HEADER_SM2_THRESHOLD_H

# include <openssl/opensslconf.h>

# if !defined(OPENSSL_NO_SM2_THRESHOLD) && !defined(FIPS_MODULE)

#  include <openssl/ec.h>

#  define DIGEST_LENGTH 32
/********************************************************************/
/*               SM2 threshold struct and functions                 */
/********************************************************************/

typedef struct sm2_threshold_message_st SM2_THRESHOLD_MSG;

/* Create a SM2_THRESHOLD_MSG object */
SM2_THRESHOLD_MSG *SM2_THRESHOLD_MSG_new(void);

/* Free a SM2_THRESHOLD_MSG object. */
void SM2_THRESHOLD_MSG_free(SM2_THRESHOLD_MSG *msg);

/** Encodes SM2_THRESHOLD_MSG to binary
 *  \param  key        EC_KEY object
 *  \param  msg        SM2_THRESHOLD_MSG object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t SM2_THRESHOLD_MSG_encode(EC_KEY *key, SM2_THRESHOLD_MSG *msg,
                                unsigned char *out, size_t size);

/** Decodes binary to SM2_THRESHOLD_MSG
 *  \param  key        EC_KEY object
 *  \param  msg        the resulting SM2_THRESHOLD_MSG object
 *  \param  in         Memory buffer with the encoded SM2_THRESHOLD_MSG object
 *  \param  size       The memory size of the in pointer object
 *  \return 1 on success and 0 otherwise
 */
int SM2_THRESHOLD_MSG_decode(EC_KEY *key, SM2_THRESHOLD_MSG *msg,
                             const unsigned char *in, size_t size);

/** Generate threshold partial public key and store in the input key object
 *  \param  key         EC_KEY object
 *  \return 1 on success and 0 if an error occurred
 */
int SM2_THRESHOLD_partial_pubkey_generate(EC_KEY *key);

/** Generate a sm2 threshold key with partial public key
 *  \param  key         EC_KEY object
 *  \return the EC_KEY object including private key and partial public key
 */
EC_KEY *SM2_THRESHOLD_keypair_generate(void);

/** Generate threshold complete public key and return an complete keypair object
 *  \param  key         EC_KEY object
 *  \param  pkey        partial public key from another participant
 *  \return the EC_KEY object including private key and complete public key
 */
EC_KEY *SM2_THRESHOLD_complete_keypair_generate(const EC_KEY *key, 
                                                const EC_KEY *pkey);

/** Generate the first part of the SM2 threshold signature.
 * \param key           EC_KEY object
 * \param digest        the digest algorithm object (sm3 default)
 * \param id            userid to calculate digest
 * \param id_len        length of userid
 * \param msg           message to calculate digest
 * \param msg_len       length of message
 * \param w1            an output random number used in the 3rd part of signature
 * \param sign_msg      a SM2_THRESHOLD_MSG object including an EC_POINT and 
 *                      message digest.
 * \return 1 on success and 0 if an error occurred.
 */
int SM2_THRESHOLD_sign_init(const EC_KEY *key,
                            const EVP_MD *digest,
                            const uint8_t *id,
                            const size_t id_len,
                            const uint8_t *msg, size_t msg_len,
                            BIGNUM *w1, SM2_THRESHOLD_MSG *sign_msg);

/** The 2nd step of SM2 threshold signature, generate the partial threshold signature
 * \param key           EC_KEY object.
 * \param msg           a SM2_THRESHOLD_MSG object sent from another participant
 * \param partial_sig   the partial signature sent to another participant
 * \return 1 on success and 0 if an error occurred.
 */
int SM2_THRESHOLD_sign_update(const EC_KEY *key, const SM2_THRESHOLD_MSG *msg,
                              ECDSA_SIG *partial_sig);

/** The 3rd step of SM2 threshold signature，generate the final threshold signature
 * \param key           EC_KEY object
 * \param a             the random number generated in the 1st part of signature
 * \param partial_sig   the partial signature sent from another participant
 * \param final_sig     output complete ECDSA_SIG object
 * \return 1 on success and 0 if an error occurred.
 */
int SM2_THRESHOLD_sign_final(const EC_KEY *key, const BIGNUM *w1, 
                             const ECDSA_SIG *partial_sig,
                             ECDSA_SIG *final_sig);

/** Verify a SM2 threshold signature
 * \param key           EC_KEY object
 * \param digest        the digest algorithm object (sm3 default)
 * \param sig           the ECDSA_SIG threshold signature object
 * \param id            userid to calculate digest
 * \param id_len        length of userid
 * \param msg           message to calculate digest
 * \param msg_len       length of message
 * \return 1 on success and 0 if the signature is invalid. 
 */
int SM2_THRESHOLD_verify(const EC_KEY *key,
                         const EVP_MD *digest,
                         const ECDSA_SIG *sig,
                         const uint8_t *id,
                         const size_t id_len,
                         const uint8_t *msg, size_t msg_len);
# endif /* OPENSSL_NO_SM2_THRESHOLD */

#endif
