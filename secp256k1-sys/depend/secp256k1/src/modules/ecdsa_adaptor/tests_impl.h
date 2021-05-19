#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H

#include "include/secp256k1_ecdsa_adaptor.h"

void rand_scalar(rustsecp256k1_v0_4_0_adaptor_0_scalar *scalar) {
    unsigned char buf32[32];
    rustsecp256k1_v0_4_0_adaptor_0_rand256(buf32);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(scalar, buf32, NULL);
}

void rand_point(rustsecp256k1_v0_4_0_adaptor_0_ge *point) {
    rustsecp256k1_v0_4_0_adaptor_0_scalar x;
    rustsecp256k1_v0_4_0_adaptor_0_gej pointj;
    rand_scalar(&x);

    rustsecp256k1_v0_4_0_adaptor_0_ecmult_gen(&ctx->ecmult_gen_ctx, &pointj, &x);
    rustsecp256k1_v0_4_0_adaptor_0_ge_set_gej(point, &pointj);
}

void dleq_tests(void) {
    rustsecp256k1_v0_4_0_adaptor_0_scalar s, e;
    unsigned char algo16[16] = { 0 };
    rustsecp256k1_v0_4_0_adaptor_0_scalar sk;
    rustsecp256k1_v0_4_0_adaptor_0_ge gen2;
    rustsecp256k1_v0_4_0_adaptor_0_ge p1, p2;

    rand_point(&gen2);
    rand_scalar(&sk);
    CHECK(rustsecp256k1_v0_4_0_adaptor_0_dleq_proof(&ctx->ecmult_gen_ctx, &s, &e, algo16, &sk, &gen2) == 1);
    rustsecp256k1_v0_4_0_adaptor_0_dleq_pair(&ctx->ecmult_gen_ctx, &p1, &p2, &sk, &gen2);
    CHECK(rustsecp256k1_v0_4_0_adaptor_0_dleq_verify(&ctx->ecmult_ctx, algo16, &s, &e, &p1, &gen2, &p2) == 1);

    {
        unsigned char algo16_tmp[16] = { 1 };
        CHECK(rustsecp256k1_v0_4_0_adaptor_0_dleq_verify(&ctx->ecmult_ctx, algo16_tmp, &s, &e, &p1, &gen2, &p2) == 0);
    }
    {
        rustsecp256k1_v0_4_0_adaptor_0_scalar tmp;
        rustsecp256k1_v0_4_0_adaptor_0_scalar_set_int(&tmp, 1);
        CHECK(rustsecp256k1_v0_4_0_adaptor_0_dleq_verify(&ctx->ecmult_ctx, algo16, &tmp, &e, &p1, &gen2, &p2) == 0);
        CHECK(rustsecp256k1_v0_4_0_adaptor_0_dleq_verify(&ctx->ecmult_ctx, algo16, &s, &tmp, &p1, &gen2, &p2) == 0);
    }
    {
        rustsecp256k1_v0_4_0_adaptor_0_ge p_tmp;
        rand_point(&p_tmp);
        CHECK(rustsecp256k1_v0_4_0_adaptor_0_dleq_verify(&ctx->ecmult_ctx, algo16, &s, &e, &p_tmp, &gen2, &p2) == 0);
        CHECK(rustsecp256k1_v0_4_0_adaptor_0_dleq_verify(&ctx->ecmult_ctx, algo16, &s, &e, &p1, &p_tmp, &p2) == 0);
        CHECK(rustsecp256k1_v0_4_0_adaptor_0_dleq_verify(&ctx->ecmult_ctx, algo16, &s, &e, &p1, &gen2, &p_tmp) == 0);
    }
}

void rand_flip_bit(unsigned char *array, size_t n) {
    array[rustsecp256k1_v0_4_0_adaptor_0_rand_int(n)] ^= 1 << rustsecp256k1_v0_4_0_adaptor_0_rand_int(8);
}

void adaptor_tests(void) {
    unsigned char seckey[32];
    rustsecp256k1_v0_4_0_adaptor_0_pubkey pubkey;
    unsigned char msg[32];
    unsigned char adaptor_secret[32];
    rustsecp256k1_v0_4_0_adaptor_0_pubkey adaptor;
    unsigned char adaptor_sig[65];
    unsigned char adaptor_proof[97];
    rustsecp256k1_v0_4_0_adaptor_0_ecdsa_signature sig;

    rustsecp256k1_v0_4_0_adaptor_0_rand256(seckey);
    rustsecp256k1_v0_4_0_adaptor_0_rand256(msg);
    rustsecp256k1_v0_4_0_adaptor_0_rand256(adaptor_secret);

    CHECK(rustsecp256k1_v0_4_0_adaptor_0_ec_pubkey_create(ctx, &pubkey, seckey) == 1);
    CHECK(rustsecp256k1_v0_4_0_adaptor_0_ec_pubkey_create(ctx, &adaptor, adaptor_secret) == 1);
    CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sign(ctx, adaptor_sig, adaptor_proof, seckey, &adaptor, msg) == 1);
    {
        /* Test adaptor_sig_serialize roundtrip */
        rustsecp256k1_v0_4_0_adaptor_0_ge r;
        rustsecp256k1_v0_4_0_adaptor_0_scalar sigr;
        rustsecp256k1_v0_4_0_adaptor_0_scalar sp;
        unsigned char adaptor_sig_tmp[65];
        CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_deserialize(&r, &sigr, &sp, adaptor_sig) == 1);
        rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_serialize(adaptor_sig_tmp, &r, &sp);
        CHECK(memcmp(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp)) == 0);
    }

    /* Test adaptor_sig_verify */
    CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_verify(ctx, adaptor_sig, &pubkey, msg, &adaptor, adaptor_proof) == 1);
    {
        unsigned char adaptor_sig_tmp[65];
        memcpy(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp));
        rand_flip_bit(&adaptor_sig_tmp[1], sizeof(adaptor_sig_tmp) - 1);
        CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_verify(ctx, adaptor_sig_tmp, &pubkey, msg, &adaptor, adaptor_proof) == 0);
    }
    CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_verify(ctx, adaptor_sig, &adaptor, msg, &adaptor, adaptor_proof) == 0);
    {
        unsigned char msg_tmp[32];
        memcpy(msg_tmp, msg, sizeof(msg_tmp));
        rand_flip_bit(msg_tmp, sizeof(msg_tmp));
        CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_verify(ctx, adaptor_sig, &pubkey, msg_tmp, &adaptor, adaptor_proof) == 0);
    }
    CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_verify(ctx, adaptor_sig, &pubkey, msg, &pubkey, adaptor_proof) == 0);
    {
        unsigned char adaptor_proof_tmp[97];
        memcpy(adaptor_proof_tmp, adaptor_proof, sizeof(adaptor_proof_tmp));
        rand_flip_bit(adaptor_proof_tmp, sizeof(adaptor_proof_tmp));
        CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_sig_verify(ctx, adaptor_sig, &pubkey, msg, &adaptor, adaptor_proof_tmp) == 0);
    }

    /* Test adaptor_adapt */
    CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_adapt(ctx, &sig, adaptor_secret, adaptor_sig) == 1);
    CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecdsa_verify(ctx, &sig, msg, &pubkey) == 1);

    {
        /* Test adaptor_extract_secret */
        unsigned char adaptor_secret_tmp[32];
        CHECK(rustsecp256k1_v0_4_0_adaptor_0_ecdsa_adaptor_extract_secret(ctx, adaptor_secret_tmp, &sig, adaptor_sig, &adaptor) == 1);
        CHECK(memcmp(adaptor_secret, adaptor_secret_tmp, sizeof(adaptor_secret)) == 0);
    }
}

/*/\* TODO: test multi hop lock *\/ */
/* struct agent { */
/*     rustsecp256k1_v0_4_0_adaptor_0_pubkey left_lock; */
/*     rustsecp256k1_v0_4_0_adaptor_0_pubkey right_lock; */
/*     /\* adaptor secret for right_lock - left_lock *\/ */
/*     unsigned char adaptor_secret[32]; */
/*     rustsecp256k1_v0_4_0_adaptor_0_pubkey pubkey; */
/*     unsigned char secret[32]; */
/* }; */

/* void multi_hop_lock_test(void) { */
/*     struct agent Sender; */
/*     struct agent Intermediate; */
/*     struct agent Receiver; */

/* } */

void run_ecdsa_adaptor_tests(void) {
    int i;
    for (i = 0; i < count; i++) {
        dleq_tests();
    }
    for (i = 0; i < count; i++) {
        adaptor_tests();
    }
}

#endif /* SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H */
