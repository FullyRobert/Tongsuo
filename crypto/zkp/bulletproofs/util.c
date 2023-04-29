/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/zkpbperr.h>
#include <crypto/ec/ec_local.h>
#include "util.h"

EC_POINT **bp_random_ec_points_new(const EC_GROUP *group, size_t n, BN_CTX *bn_ctx)
{
    size_t i;
    BIGNUM *r = NULL;
    BN_CTX *bctx = NULL;
    EC_POINT **P = NULL;
    const BIGNUM *order;

    if (group == NULL || (n % 2) != 0)
        return NULL;

    if (!(P = OPENSSL_zalloc(n * sizeof(*P)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    order = EC_GROUP_get0_order(group);

    if (bn_ctx == NULL) {
        bctx = bn_ctx = BN_CTX_new_ex(group->libctx);
        if (bn_ctx == NULL)
            goto err;
    }

    BN_CTX_start(bn_ctx);
    r = BN_CTX_get(bn_ctx);
    if (r == NULL)
        goto err;

    for (i = 0; i < n; i++) {
        bp_rand_range(r, order);
        if (!(P[i] = EC_POINT_new(group)) || !EC_POINT_mul(group, P[i], r, NULL,
                                                           NULL, bn_ctx))
            goto err;
    }

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bctx);
    return P;

err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bctx);
    bp_random_ec_points_free(P, n);
    return NULL;
}

void bp_random_ec_points_free(EC_POINT **P, size_t n)
{
    size_t i;

    if (P == NULL)
        return;

    for (i = 0; i < n; i++) {
        EC_POINT_free(P[i]);
    }

    OPENSSL_free(P);
}

EC_POINT *bp_random_ec_point_new(const EC_GROUP *group, BN_CTX *bn_ctx)
{
    BIGNUM *r = NULL;
    BN_CTX *bctx = NULL;
    EC_POINT *P = NULL;
    const BIGNUM *order;

    if (group == NULL)
        return NULL;

    if (bn_ctx == NULL) {
        bctx = bn_ctx = BN_CTX_new_ex(group->libctx);
        if (bn_ctx == NULL)
            goto err;
    }

    order = EC_GROUP_get0_order(group);

    BN_CTX_start(bn_ctx);
    r = BN_CTX_get(bn_ctx);
    if (r == NULL)
        goto err;

    bp_rand_range(r, order);

    if (!(P = EC_POINT_new(group)) || !EC_POINT_mul(group, P, r, NULL, NULL,
                                                    bn_ctx))
        goto err;

    BN_CTX_end(bn_ctx);

    return P;
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bctx);
    bp_random_ec_point_free(P);
    return NULL;
}

void bp_random_ec_point_free(EC_POINT *P)
{
    if (P == NULL)
        return;

    EC_POINT_free(P);
}

int bp_str2bn(const unsigned char *str, size_t len, BIGNUM *ret)
{
    int r = 0;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];

    if (str == NULL || ret == NULL)
        return r;

    memset(hash_res, 0, sizeof(hash_res));

    if (!SHA256(str, len, hash_res))
        goto end;

    if (!BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, ret))
        goto end;

    r = 1;
end:
    return r;
}

int bp_points_hash2bn(const EC_GROUP *group, EC_POINT *A, EC_POINT *B,
                      BIGNUM *ra, BIGNUM *rb, BN_CTX *bn_ctx)
{
    int ret = 0;
    size_t plen;
    unsigned char *transcript_str = NULL;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];
    point_conversion_form_t format = POINT_CONVERSION_COMPRESSED;
    BIGNUM *a;
    EVP_MD *sha256 = NULL;
    EVP_MD_CTX *md_ctx1 = NULL, *md_ctx2 = NULL;

    if (group == NULL || A == NULL || B == NULL || bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    if (ra == NULL && rb == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    BN_CTX_start(bn_ctx);
    a = BN_CTX_get(bn_ctx);
    if (a == NULL)
        goto end;

    plen = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                              format, NULL, 0, bn_ctx);
    if (plen <= 0)
        goto end;

    transcript_str = OPENSSL_zalloc(plen);
    if (transcript_str == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!(md_ctx1 = EVP_MD_CTX_new())
        || !(md_ctx2 = EVP_MD_CTX_new())
        || !(sha256 = EVP_MD_fetch(group->libctx, "sha256", NULL))
        || !EVP_DigestInit_ex(md_ctx1, sha256, NULL)
        || !EVP_DigestInit_ex(md_ctx2, sha256, NULL))
        goto end;

    if (EC_POINT_point2oct(group, A, format, transcript_str, plen, bn_ctx) <= 0
        || !EVP_DigestUpdate(md_ctx1, transcript_str, plen)
        || !EVP_DigestUpdate(md_ctx2, transcript_str, plen)
        || EC_POINT_point2oct(group, B, format, transcript_str, plen, bn_ctx) <= 0
        || !EVP_DigestUpdate(md_ctx1, transcript_str, plen)
        || !EVP_DigestUpdate(md_ctx2, transcript_str, plen)
        || !EVP_DigestFinal(md_ctx1, hash_res, NULL))
        goto end;

    if (!BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, a))
        goto end;

    if (ra != NULL && !BN_copy(ra, a))
        goto end;

    if (rb != NULL && (!EVP_DigestUpdate(md_ctx2, hash_res, SHA256_DIGEST_LENGTH)
                       || !EVP_DigestFinal(md_ctx2, hash_res, NULL)
                       || !BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, rb)))
        goto end;

    ret = 1;
end:
    OPENSSL_free(transcript_str);
    BN_CTX_end(bn_ctx);
    return ret;
}

/* r = SHA256(str_st, bin(P)) */
int bp_bin_point_hash2bn(const EC_GROUP *group, const char *st, size_t len,
                         const EC_POINT *P, BIGNUM *r, BN_CTX *bn_ctx)
{
    int ret = 0;
    size_t plen;
    unsigned char *buf = NULL;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];
    point_conversion_form_t format = POINT_CONVERSION_COMPRESSED;
    EVP_MD *sha256 = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    BN_CTX *bctx = NULL;

    if (group == NULL || P == NULL || r == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    if (bn_ctx == NULL) {
        if (!(bctx = bn_ctx = BN_CTX_new()))
            goto end;
    }

    plen = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                              format, NULL, 0, bn_ctx);
    if (plen <= 0)
        goto end;

    buf = OPENSSL_zalloc(plen);
    if (buf == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!(md_ctx = EVP_MD_CTX_new())
        || !(sha256 = EVP_MD_fetch(group->libctx, "sha256", NULL))
        || !EVP_DigestInit_ex(md_ctx, sha256, NULL))
        goto end;

    if (st && len > 0 && !EVP_DigestUpdate(md_ctx, st, len))
        goto end;

    if (EC_POINT_point2oct(group, P, format, buf, plen, bn_ctx) <= 0
        || !EVP_DigestUpdate(md_ctx, buf, plen)
        || !EVP_DigestFinal(md_ctx, hash_res, NULL))
        goto end;

    if (!BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, r))
        goto end;

    ret = 1;
end:
    OPENSSL_free(buf);
    BN_CTX_free(bctx);
    return ret;
}

/* r = SHA256(bin(bn_st), bin(P)) */
int bp_bn_point_hash2bn(const EC_GROUP *group, const BIGNUM *bn_st,
                        const EC_POINT *P, BIGNUM *r, BN_CTX *bn_ctx)
{
    int ret = 0;
    size_t n;
    char *buf = NULL;

    if (group == NULL || P == NULL || r == NULL)
        goto end;

    if (bn_st == NULL)
        return bp_bin_point_hash2bn(group, NULL, 0, P, r, bn_ctx);

    n = BN_num_bytes(bn_st);
    if (!(buf = OPENSSL_zalloc(n))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if ((n = BN_bn2bin(bn_st, (unsigned char *)buf)) <= 0)
        goto end;

    ret = bp_bin_point_hash2bn(group, buf, n, P, r, bn_ctx);
end:
    OPENSSL_free(buf);
    return ret;
}

int bp_random_bn_gen(const EC_GROUP *group, BIGNUM **r, size_t n, BN_CTX *bn_ctx)
{
    size_t i;
    const BIGNUM *order;

    if (group == NULL || r == NULL || bn_ctx == NULL)
        return 0;

    order = EC_GROUP_get0_order(group);

    for (i = 0; i < n; i++) {
        if (!(r[i] = BN_CTX_get(bn_ctx)) || !bp_rand_range(r[i], order))
            return 0;
    }

    return 1;
}

int bp_str2point(const EC_GROUP *group, const unsigned char *str, size_t len,
                 EC_POINT *r, BN_CTX *bn_ctx)
{
    int ret = 0, i = 0;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];
    unsigned char *p = (unsigned char *)str;
    BN_CTX *ctx = NULL;
    BIGNUM *x;

    memset(hash_res, 0, sizeof(hash_res));

    if (bn_ctx == NULL) {
        if ((ctx = bn_ctx = BN_CTX_new_ex(group->libctx)) == NULL)
            goto end;
    }

    BN_CTX_start(bn_ctx);
    if ((x = BN_CTX_get(bn_ctx)) == NULL)
        goto end;

    do {
        if (!SHA256(p, len, hash_res))
            goto end;

        BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, x);

        p  = &hash_res[0];
        len = sizeof(hash_res);

        if(EC_POINT_set_compressed_coordinates(group, r, x, 0, bn_ctx) == 1) {
            ret = 1;
            break;
        }

        ERR_clear_error();
    } while (i++ < 10);

end:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(ctx);
    return ret;
}

size_t bp_point2oct(const EC_GROUP *group, const EC_POINT *P,
                    unsigned char *buf, BN_CTX *bn_ctx)
{
    size_t plen;
    point_conversion_form_t format = POINT_CONVERSION_COMPRESSED;

    if (group == NULL || P == NULL || bn_ctx == NULL)
        return -1;

    plen = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                              format, NULL, 0, bn_ctx);
    if (plen <= 0 || buf == NULL)
        return plen;

    if (EC_POINT_point2oct(group, P, format, buf, plen, bn_ctx) <= 0)
        return -1;

    return plen;
}

int bp_bin_hash2bn(const unsigned char *data, size_t len, BIGNUM *r)
{
    int ret = 0;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];

    if (data == NULL || len <= 0 || r == NULL)
        return ret;

    if (!SHA256(data, len, hash_res))
        goto end;

    if (!BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, r))
        goto end;

    ret = 1;
end:
    return ret;
}

int bp_next_power_of_two(int num)
{
    int next_power_of_2 = 1;

    while(next_power_of_2 <= num) {
        next_power_of_2 <<= 1;
    }

    return next_power_of_2;
}

int bp_floor_log2(int x)
{
    int result = 0;

    while (x > 1) {
        x >>= 1;
        result++;
    }

    return result;
}

int bp_inner_product(BIGNUM *r, int num, const BIGNUM *a[], const BIGNUM *b[],
                     BN_CTX *bn_ctx)
{
    int ret = 0, i;
    BN_CTX *ctx = NULL;
    BIGNUM *v, *t;
    const BIGNUM *p;

    if (r == NULL || num <= 0 || (a == NULL && b == NULL))
        return 0;

    if (bn_ctx == NULL) {
        if ((ctx = bn_ctx = BN_CTX_new()) == NULL)
            goto end;
    }

    BN_CTX_start(bn_ctx);
    v = BN_CTX_get(bn_ctx);
    if ((t = BN_CTX_get(bn_ctx)) == NULL)
        goto end;

    BN_zero(v);

    for (i = 0; i < num; i++) {
        if (a == NULL) {
            p = b[i];
        } else if (b == NULL) {
            p = a[i];
        } else {
            if (!BN_mul(t, a[i], b[i], bn_ctx))
                goto end;
            p = t;
        }

        if (!BN_add(v, v, p))
            goto end;
    }

    if (!BN_add(r, r, v))
        goto end;

    ret = 1;

end:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(ctx);
    return ret;
}

bp_poly3_t *bp_poly3_new(int n, BN_CTX *bn_ctx)
{
    int i;
    bp_poly3_t *ret = NULL;

    if (bn_ctx == NULL || n <= 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (!(ret = OPENSSL_zalloc(sizeof(*ret)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!(ret->x0 = OPENSSL_zalloc(sizeof(*ret->x0) * n))
        || !(ret->x1 = OPENSSL_zalloc(sizeof(*ret->x1) * n))
        || !(ret->x2 = OPENSSL_zalloc(sizeof(*ret->x2) * n))
        || !(ret->x3 = OPENSSL_zalloc(sizeof(*ret->x3) * n))
        || !(ret->eval = OPENSSL_zalloc(sizeof(*ret->eval) * n))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ret->n = n;

    BN_CTX_start(bn_ctx);

    for (i = 0; i < n; i++) {
        ret->x0[i] = BN_CTX_get(bn_ctx);
        ret->x1[i] = BN_CTX_get(bn_ctx);
        ret->x2[i] = BN_CTX_get(bn_ctx);
        if (!(ret->x3[i] = BN_CTX_get(bn_ctx)))
            goto err;

        BN_zero(ret->x0[i]);
        BN_zero(ret->x1[i]);
        BN_zero(ret->x2[i]);
        BN_zero(ret->x3[i]);
    }

    BN_CTX_end(bn_ctx);
    return ret;
err:
    BN_CTX_end(bn_ctx);
    bp_poly3_free(ret);
    return NULL;
}

void bp_poly3_free(bp_poly3_t *poly3)
{
    if (poly3 == NULL)
        return;

    OPENSSL_free(poly3->x0);
    OPENSSL_free(poly3->x1);
    OPENSSL_free(poly3->x2);
    OPENSSL_free(poly3->x3);
    OPENSSL_free(poly3->eval);
    OPENSSL_free(poly3);
}

#if 0
int bp_poly3_eval(bp_poly3_t *poly3, const BIGNUM *x, BN_CTX *bn_ctx)
{
    int ret = 0, i;
    BIGNUM *x2, *x3, *t, *eval;

    if (poly3 == NULL || bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    BN_CTX_start(bn_ctx);

    x2 = BN_CTX_get(bn_ctx);
    x3 = BN_CTX_get(bn_ctx);
    if (!(t = BN_CTX_get(bn_ctx)))
        goto err;

    if (!BN_sqr(x2, x, bn_ctx) || !BN_mul(x3, x2, x, bn_ctx))
        goto err;

    for (i = 0; i < poly3->n; i++) {
        if (!(eval = BN_CTX_get(bn_ctx)))
            goto err;

        BN_zero(eval);

        if (!BN_add(eval, eval, poly3->x0[i]))
            goto err;

        if (!BN_mul(t, x, poly3->x1[i], bn_ctx) || !BN_add(eval, eval, t)
            || !BN_mul(t, x2, poly3->x2[i], bn_ctx) || !BN_add(eval, eval, t)
            || !BN_mul(t, x3, poly3->x3[i], bn_ctx) || !BN_add(eval, eval, t))
            goto err;

        poly3->eval[i] = eval;
    }

    ret = 1;
err:
    BN_CTX_end(bn_ctx);
    return ret;
}

#else
int bp_poly3_eval(bp_poly3_t *poly3, const BIGNUM *x, BN_CTX *bn_ctx)
{
    int ret = 0, i;
    BIGNUM *eval;

    if (poly3 == NULL || bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    BN_CTX_start(bn_ctx);

    for (i = 0; i < poly3->n; i++) {
        if (!(eval = BN_CTX_get(bn_ctx)))
            goto err;

        if (!BN_mul(eval, x, poly3->x3[i], bn_ctx)
            || !BN_add(eval, eval, poly3->x2[i])
            || !BN_mul(eval, eval, x, bn_ctx)
            || !BN_add(eval, eval, poly3->x1[i])
            || !BN_mul(eval, eval, x, bn_ctx)
            || !BN_add(eval, eval, poly3->x0[i]))
            goto err;

        poly3->eval[i] = eval;
    }

    ret = 1;
err:
    BN_CTX_end(bn_ctx);
    return ret;
}
#endif

int bp_poly3_special_inner_product(bp_poly6_t *r, bp_poly3_t *lhs, bp_poly3_t *rhs,
                                   BN_CTX *bn_ctx)
{
    int ret = 0;
    BIGNUM *t;

    if (r == NULL || lhs == NULL || rhs == NULL || bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    BN_CTX_start(bn_ctx);

    if (!(t = BN_CTX_get(bn_ctx)))
        goto err;

    if (!bp_inner_product(r->t1, lhs->n, (const BIGNUM **)lhs->x1, (const BIGNUM **)rhs->x0, bn_ctx)
        || !bp_inner_product(r->t2, lhs->n, (const BIGNUM **)lhs->x1, (const BIGNUM **)rhs->x1, bn_ctx)
        || !bp_inner_product(t, lhs->n, (const BIGNUM **)lhs->x2, (const BIGNUM **)rhs->x0, bn_ctx)
        || !BN_add(r->t2, r->t2, t)
        || !bp_inner_product(r->t3, lhs->n, (const BIGNUM **)lhs->x2, (const BIGNUM **)rhs->x1, bn_ctx)
        || !bp_inner_product(t, lhs->n, (const BIGNUM **)lhs->x3, (const BIGNUM **)rhs->x0, bn_ctx)
        || !BN_add(r->t3, r->t3, t)
        || !bp_inner_product(r->t4, lhs->n, (const BIGNUM **)lhs->x1, (const BIGNUM **)rhs->x3, bn_ctx)
        || !bp_inner_product(t, lhs->n, (const BIGNUM **)lhs->x3, (const BIGNUM **)rhs->x1, bn_ctx)
        || !BN_add(r->t4, r->t4, t)
        || !bp_inner_product(r->t5, lhs->n, (const BIGNUM **)lhs->x2, (const BIGNUM **)rhs->x3, bn_ctx)
        || !bp_inner_product(r->t6, lhs->n, (const BIGNUM **)lhs->x3, (const BIGNUM **)rhs->x3, bn_ctx))
        goto err;

    ret = 1;

err:
    BN_CTX_end(bn_ctx);
    return ret;
}

bp_poly6_t *bp_poly6_new(BN_CTX *bn_ctx)
{
    bp_poly6_t *ret = NULL;

    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!(ret = OPENSSL_zalloc(sizeof(bp_poly6_t)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    BN_CTX_start(bn_ctx);

    ret->t1 = BN_CTX_get(bn_ctx);
    ret->t2 = BN_CTX_get(bn_ctx);
    ret->t3 = BN_CTX_get(bn_ctx);
    ret->t4 = BN_CTX_get(bn_ctx);
    ret->t5 = BN_CTX_get(bn_ctx);
    ret->t6 = BN_CTX_get(bn_ctx);
    if (ret->t6 == NULL)
        goto err;

    BN_CTX_end(bn_ctx);
    return ret;
err:
    BN_CTX_end(bn_ctx);
    bp_poly6_free(ret);
    return NULL;
}

void bp_poly6_free(bp_poly6_t *poly6)
{
    OPENSSL_free(poly6);
}

int bp_poly6_eval(bp_poly6_t *poly6, BIGNUM *r, const BIGNUM *x, BN_CTX *bn_ctx)
{
    int ret = 0;

    if (poly6 == NULL || r == NULL || bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!BN_mul(r, x, poly6->t6, bn_ctx)
        || !BN_add(r, r, poly6->t5)
        || !BN_mul(r, r, x, bn_ctx)
        || !BN_add(r, r, poly6->t4)
        || !BN_mul(r, r, x, bn_ctx)
        || !BN_add(r, r, poly6->t3)
        || !BN_mul(r, r, x, bn_ctx)
        || !BN_add(r, r, poly6->t2)
        || !BN_mul(r, r, x, bn_ctx)
        || !BN_add(r, r, poly6->t1)
        || !BN_mul(r, r, x, bn_ctx))
        goto err;

    ret = 1;
err:
    return ret;
}

bp_poly_ps_t *bp_poly_ps_new(int num)
{
    bp_poly_ps_t *ret = NULL;

    if (num <= 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (!(ret = OPENSSL_zalloc(sizeof(*ret)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!(ret->points = OPENSSL_zalloc(sizeof(*ret->points) * num))
        || !(ret->scalars = OPENSSL_zalloc(sizeof(*ret->scalars) * num))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ret->pos = 0;
    ret->num = num;

    return ret;
err:
    bp_poly_ps_free(ret);
    return NULL;
}

void bp_poly_ps_free(bp_poly_ps_t *ps)
{
    if (ps == NULL)
        return;

    OPENSSL_free(ps->points);
    OPENSSL_free(ps->scalars);
    OPENSSL_free(ps);
}

int bp_poly_ps_append(bp_poly_ps_t *ps, EC_POINT *point, BIGNUM *scalar)
{
    if (ps == NULL || point == NULL || scalar == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (ps->pos >= ps->num)
        return 0;

    ps->points[ps->pos] = point;
    ps->scalars[ps->pos] = scalar;
    ps->pos++;

    return 1;
}

int bp_poly_ps_eval(bp_poly_ps_t *ps, EC_POINT *r, BIGNUM *scalar,
                    const EC_GROUP *group, BN_CTX *bn_ctx)
{
    if (ps == NULL || r == NULL || group == NULL || bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return EC_POINTs_mul(group, r, scalar, ps->pos,
                         (const EC_POINT **)ps->points,
                         (const BIGNUM **)ps->scalars, bn_ctx);
}
