/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H

#include "include/secp256k1_ecdsa_adaptor.h"
#include "modules/ecdsa_adaptor/dleq_impl.h"

static void rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_serialize(unsigned char *adaptor_sig65, const rustsecp256k1_v0_4_0_adaptor_0_ge *r, const rustsecp256k1_v0_4_0_adaptor_0_scalar *sp) {
    rustsecp256k1_v0_4_0_adaptor_0_dleq_serialize_point(adaptor_sig65, r);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_get_b32(&adaptor_sig65[33], sp);
}

static int rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_deserialize(rustsecp256k1_v0_4_0_adaptor_0_ge *r, rustsecp256k1_v0_4_0_adaptor_0_scalar *sigr, rustsecp256k1_v0_4_0_adaptor_0_scalar *sp, const unsigned char *adaptor_sig65) {
    /* Ensure that whenever you call this function to deserialize r you also
     * check that X fits into a sigr */
    VERIFY_CHECK((r == NULL) || (r != NULL && sigr != NULL));
    if (r != NULL) {
        if (!rustsecp256k1_v0_4_0_adaptor_0_dleq_deserialize_point(r, &adaptor_sig65[0])) {
            return 0;
        }
    }
    if (sigr != NULL) {
        int overflow;
        rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(sigr, &adaptor_sig65[1], &overflow);
        if(overflow) {
            return 0;
        }
    }
    if (sp != NULL) {
        int overflow;
        rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(sp, &adaptor_sig65[33], &overflow);
        if(overflow) {
            return 0;
        }
    }
    return 1;
}

static void rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_proof_serialize(unsigned char *adaptor_proof97, const rustsecp256k1_v0_4_0_adaptor_0_ge *rp, const rustsecp256k1_v0_4_0_adaptor_0_scalar *dleq_proof_s, const rustsecp256k1_v0_4_0_adaptor_0_scalar *dleq_proof_e) {
    rustsecp256k1_v0_4_0_adaptor_0_dleq_serialize_point(adaptor_proof97, rp);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_get_b32(&adaptor_proof97[33], dleq_proof_s);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_get_b32(&adaptor_proof97[33+32], dleq_proof_e);
}

static int rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_proof_deserialize(rustsecp256k1_v0_4_0_adaptor_0_ge *rp, rustsecp256k1_v0_4_0_adaptor_0_scalar *dleq_proof_s, rustsecp256k1_v0_4_0_adaptor_0_scalar *dleq_proof_e, const unsigned char *adaptor_proof97) {
    int overflow;
    if (!rustsecp256k1_v0_4_0_adaptor_0_dleq_deserialize_point(rp, &adaptor_proof97[0])) {
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(dleq_proof_s, &adaptor_proof97[33], &overflow);
    if (overflow) {
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(dleq_proof_e, &adaptor_proof97[33 + 32], &overflow);
    if (overflow) {
        return 0;
    }
    return 1;
}

int rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_fe_to_scalar(rustsecp256k1_v0_4_0_adaptor_0_scalar *s, const rustsecp256k1_v0_4_0_adaptor_0_fe *fe) {
    unsigned char b[32];
    int overflow;

    rustsecp256k1_v0_4_0_adaptor_0_fe_get_b32(b, fe);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(s, b, &overflow);
    return !overflow;
}

/* 5. s' = k⁻¹(H(m) + x_coord(R)x) */
int rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sign_helper(rustsecp256k1_v0_4_0_adaptor_0_scalar *sigs, rustsecp256k1_v0_4_0_adaptor_0_scalar *message, rustsecp256k1_v0_4_0_adaptor_0_scalar *k, rustsecp256k1_v0_4_0_adaptor_0_ge *r, rustsecp256k1_v0_4_0_adaptor_0_scalar *sk) {
    rustsecp256k1_v0_4_0_adaptor_0_scalar sigr;
    rustsecp256k1_v0_4_0_adaptor_0_scalar n;

    rustsecp256k1_v0_4_0_adaptor_0_fe_normalize(&r->x);
    if (!rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_fe_to_scalar(&sigr, &r->x)) {
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_scalar_mul(&n, &sigr, sk);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_add(&n, &n, message);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_inverse(sigs, k);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_mul(sigs, sigs, &n);

    rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&n);
    return !rustsecp256k1_v0_4_0_adaptor_0_scalar_is_zero(sigs);
}

int rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sign(const rustsecp256k1_v0_4_0_adaptor_0_context* ctx, unsigned char *adaptor_sig65, unsigned char *adaptor_proof97, unsigned char *seckey32, const rustsecp256k1_v0_4_0_adaptor_0_pubkey *adaptor, const unsigned char *msg32) {
    unsigned char nonce32[32];
    unsigned char buf33[33];
    rustsecp256k1_v0_4_0_adaptor_0_sha256 sha;
    rustsecp256k1_v0_4_0_adaptor_0_scalar k;
    rustsecp256k1_v0_4_0_adaptor_0_gej rj, rpj;
    rustsecp256k1_v0_4_0_adaptor_0_ge r, rp;
    rustsecp256k1_v0_4_0_adaptor_0_ge adaptor_ge;
    rustsecp256k1_v0_4_0_adaptor_0_scalar dleq_proof_s;
    rustsecp256k1_v0_4_0_adaptor_0_scalar dleq_proof_e;
    rustsecp256k1_v0_4_0_adaptor_0_scalar sk;
    rustsecp256k1_v0_4_0_adaptor_0_scalar msg;
    rustsecp256k1_v0_4_0_adaptor_0_scalar sp;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(adaptor_sig65 != NULL);
    ARG_CHECK(adaptor_proof97 != NULL);
    ARG_CHECK(adaptor != NULL);
    ARG_CHECK(msg32 != NULL);

    /* 1. Choose k randomly, R' = k*G */
    /* Include msg32 and adaptor in nonce derivation */
    rustsecp256k1_v0_4_0_adaptor_0_sha256_initialize(&sha);
    rustsecp256k1_v0_4_0_adaptor_0_sha256_write(&sha, msg32, 32);
    if (!rustsecp256k1_v0_4_0_adaptor_0_pubkey_load(ctx, &adaptor_ge, adaptor)) {
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_dleq_serialize_point(buf33, &adaptor_ge);
    rustsecp256k1_v0_4_0_adaptor_0_sha256_write(&sha, buf33, 33);
    rustsecp256k1_v0_4_0_adaptor_0_sha256_finalize(&sha, buf33);
    if (!nonce_function_dleq(nonce32, buf33, seckey32, (unsigned char *)"ECDSAAdaptorNon")) {
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(&k, nonce32, NULL);
    if (rustsecp256k1_v0_4_0_adaptor_0_scalar_is_zero(&k)) {
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_ecmult_gen(&ctx->ecmult_gen_ctx, &rpj, &k);

    /* 2. R = k*Y; */
    rustsecp256k1_v0_4_0_adaptor_0_ecmult_const(&rj, &adaptor_ge, &k, 256);

    /* 4. [sic] proof = DLEQ_prove((G,R'),(Y, R)) */
    if (!rustsecp256k1_v0_4_0_adaptor_0_dleq_proof(&ctx->ecmult_gen_ctx, &dleq_proof_s, &dleq_proof_e, (unsigned char *)"ECDSAAdaptorSig", &k, &adaptor_ge)) {
        return 0;
    }

    /* 5. s' = k⁻¹(H(m) + x_coord(R)x) */
    rustsecp256k1_v0_4_0_adaptor_0_ge_set_gej(&r, &rj);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(&sk, seckey32, &overflow);
    if (overflow || rustsecp256k1_v0_4_0_adaptor_0_scalar_is_zero(&sk)) {
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(&msg, msg32, NULL);
    if(!rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sign_helper(&sp, &msg, &k, &r, &sk)) {
        rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&k);
        rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&sk);
        return 0;
    }

    /* 6. return (R, R', s', proof) */
    rustsecp256k1_v0_4_0_adaptor_0_ge_set_gej(&rp, &rpj);
    rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_proof_serialize(adaptor_proof97, &rp, &dleq_proof_s, &dleq_proof_e);
    rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_serialize(adaptor_sig65, &r, &sp);

    rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&k);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&sk);
    return 1;
}

SECP256K1_API int rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_verify_helper(const rustsecp256k1_v0_4_0_adaptor_0_context* ctx, rustsecp256k1_v0_4_0_adaptor_0_ge *result, rustsecp256k1_v0_4_0_adaptor_0_scalar *sigr, rustsecp256k1_v0_4_0_adaptor_0_scalar *sigs, const rustsecp256k1_v0_4_0_adaptor_0_ge *pubkey, const rustsecp256k1_v0_4_0_adaptor_0_scalar *message) {
    rustsecp256k1_v0_4_0_adaptor_0_scalar sn, u1, u2;
    rustsecp256k1_v0_4_0_adaptor_0_gej pubkeyj;
    rustsecp256k1_v0_4_0_adaptor_0_gej pr;

    if (rustsecp256k1_v0_4_0_adaptor_0_scalar_is_zero(sigr) || rustsecp256k1_v0_4_0_adaptor_0_scalar_is_zero(sigs)) {
        return 0;
    }

    rustsecp256k1_v0_4_0_adaptor_0_scalar_inverse_var(&sn, sigs);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_mul(&u1, &sn, message);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_mul(&u2, &sn, sigr);

    rustsecp256k1_v0_4_0_adaptor_0_gej_set_ge(&pubkeyj, pubkey);
    rustsecp256k1_v0_4_0_adaptor_0_ecmult(&ctx->ecmult_ctx, &pr, &pubkeyj, &u2, &u1);
    if (rustsecp256k1_v0_4_0_adaptor_0_gej_is_infinity(&pr)) {
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_ge_set_gej(result, &pr);
    return 1;
}

int rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_verify(const rustsecp256k1_v0_4_0_adaptor_0_context* ctx, const unsigned char *adaptor_sig65, const rustsecp256k1_v0_4_0_adaptor_0_pubkey *pubkey, const unsigned char *msg32, const rustsecp256k1_v0_4_0_adaptor_0_pubkey *adaptor, const unsigned char *adaptor_proof97) {
    rustsecp256k1_v0_4_0_adaptor_0_scalar dleq_proof_s, dleq_proof_e;
    rustsecp256k1_v0_4_0_adaptor_0_scalar msg;
    rustsecp256k1_v0_4_0_adaptor_0_ge q;
    rustsecp256k1_v0_4_0_adaptor_0_ge r, rp;
    rustsecp256k1_v0_4_0_adaptor_0_scalar sp;
    rustsecp256k1_v0_4_0_adaptor_0_scalar sigr;
    rustsecp256k1_v0_4_0_adaptor_0_ge adaptor_ge;
    rustsecp256k1_v0_4_0_adaptor_0_ge rhs;
    rustsecp256k1_v0_4_0_adaptor_0_gej lhs;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(adaptor_sig65 != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(adaptor != NULL);
    ARG_CHECK(adaptor_proof97 != NULL);

    /* 1. DLEQ_verify((G,R'),(Y, R)) */
    if (!rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_proof_deserialize(&rp, &dleq_proof_s, &dleq_proof_e, adaptor_proof97)) {
        return 0;
    }
    if (!rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_deserialize(&r, &sigr, &sp, adaptor_sig65)) {
        return 0;
    }
    if (!rustsecp256k1_v0_4_0_adaptor_0_pubkey_load(ctx, &adaptor_ge, adaptor)) {
        return 0;
    }
    if(!rustsecp256k1_v0_4_0_adaptor_0_dleq_verify(&ctx->ecmult_ctx, (unsigned char *)"ECDSAAdaptorSig", &dleq_proof_s, &dleq_proof_e, &rp, &adaptor_ge, &r)) {
        return 0;
    }

    /* 2. return x_coord(R') == x_coord(s'⁻¹(H(m) * G + x_coord(R) * X)) */
    rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(&msg, msg32, NULL);
    if (!rustsecp256k1_v0_4_0_adaptor_0_pubkey_load(ctx, &q, pubkey)) {
        return 0;
    }
    if (!rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_verify_helper(ctx, &rhs, &sigr, &sp, &q, &msg)) {
        return 0;
    }

    rustsecp256k1_v0_4_0_adaptor_0_gej_set_ge(&lhs, &rp);
    rustsecp256k1_v0_4_0_adaptor_0_ge_neg(&rhs, &rhs);
    rustsecp256k1_v0_4_0_adaptor_0_gej_add_ge_var(&lhs, &lhs, &rhs, NULL);
    return rustsecp256k1_v0_4_0_adaptor_0_gej_is_infinity(&lhs);
}

int rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_adapt(const rustsecp256k1_v0_4_0_adaptor_0_context* ctx, rustsecp256k1_v0_4_0_adaptor_0_ecdsa_signature *sig, const unsigned char *adaptor_secret32, const unsigned char *adaptor_sig65) {
    rustsecp256k1_v0_4_0_adaptor_0_scalar adaptor_secret;
    rustsecp256k1_v0_4_0_adaptor_0_scalar sp;
    rustsecp256k1_v0_4_0_adaptor_0_scalar s;
    rustsecp256k1_v0_4_0_adaptor_0_scalar sigr;
    int overflow;
    unsigned char buf32[32];
    int high;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(adaptor_secret32 != NULL);
    ARG_CHECK(adaptor_sig65 != NULL);

    rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(&adaptor_secret, adaptor_secret32, &overflow);
    if (overflow) {
        return 0;
    }

    if (!rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_deserialize(NULL, &sigr, &sp, adaptor_sig65)) {
        rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&adaptor_secret);
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_scalar_inverse(&s, &adaptor_secret);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_mul(&s, &s, &sp);
    high = rustsecp256k1_v0_4_0_adaptor_0_scalar_is_high(&s);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_cond_negate(&s, high);

    rustsecp256k1_v0_4_0_adaptor_0_ecdsa_signature_save(sig, &sigr, &s);

    memset(buf32, 0, sizeof(buf32));
    rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&adaptor_secret);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&sp);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&s);

    return 1;
}

int rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_extract_secret(const rustsecp256k1_v0_4_0_adaptor_0_context* ctx, unsigned char *adaptor_secret32, const rustsecp256k1_v0_4_0_adaptor_0_ecdsa_signature *sig, const unsigned char *adaptor_sig65, const rustsecp256k1_v0_4_0_adaptor_0_pubkey *adaptor) {
    rustsecp256k1_v0_4_0_adaptor_0_scalar sp;
    rustsecp256k1_v0_4_0_adaptor_0_scalar s, r;
    rustsecp256k1_v0_4_0_adaptor_0_scalar adaptor_secret;
    rustsecp256k1_v0_4_0_adaptor_0_ge adaptor_expected_ge;
    rustsecp256k1_v0_4_0_adaptor_0_gej adaptor_expected_gej;
    rustsecp256k1_v0_4_0_adaptor_0_pubkey adaptor_expected;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(adaptor_secret32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(adaptor_sig65 != NULL);
    ARG_CHECK(adaptor != NULL);

    if (!rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_deserialize(NULL, NULL, &sp, adaptor_sig65)) {
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_ecdsa_signature_load(ctx, &r, &s, sig);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_inverse(&adaptor_secret, &s);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_mul(&adaptor_secret, &adaptor_secret, &sp);

    /* Deal with ECDSA malleability */
    rustsecp256k1_v0_4_0_adaptor_0_ecmult_gen(&ctx->ecmult_gen_ctx, &adaptor_expected_gej, &adaptor_secret);
    rustsecp256k1_v0_4_0_adaptor_0_ge_set_gej(&adaptor_expected_ge, &adaptor_expected_gej);
    rustsecp256k1_v0_4_0_adaptor_0_pubkey_save(&adaptor_expected, &adaptor_expected_ge);
    if (memcmp(&adaptor_expected, adaptor, sizeof(adaptor_expected)) != 0) {
        rustsecp256k1_v0_4_0_adaptor_0_scalar_negate(&adaptor_secret, &adaptor_secret);
    }
    rustsecp256k1_v0_4_0_adaptor_0_scalar_get_b32(adaptor_secret32, &adaptor_secret);

    rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&adaptor_secret);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&sp);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&s);

    return 1;
}

#endif /* SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H */
