#ifndef _SECP256K1_DLEQ_IMPL_H_
#define _SECP256K1_DLEQ_IMPL_H_

/* Remove terminating NUL bytes */
static int algo16_len(const unsigned char *algo16) {
    int algo16_len = 16;

     /* Remove terminating null bytes */
     while (algo16_len > 0 && !algo16[algo16_len - 1]) {
        algo16_len--;
     }
     return algo16_len;
}

/* Modified bip340 nonce function */
static int nonce_function_dleq(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16) {
    rustsecp256k1_v0_4_0_adaptor_0_sha256 sha;

    if (algo16 == NULL) {
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_sha256_initialize_tagged(&sha, algo16, algo16_len(algo16));
    rustsecp256k1_v0_4_0_adaptor_0_sha256_write(&sha, key32, 32);
    rustsecp256k1_v0_4_0_adaptor_0_sha256_write(&sha, msg32, 32);
    rustsecp256k1_v0_4_0_adaptor_0_sha256_finalize(&sha, nonce32);
    return 1;
}

static void rustsecp256k1_v0_4_0_adaptor_0_dleq_serialize_point(unsigned char *buf33, const rustsecp256k1_v0_4_0_adaptor_0_ge *p) {
    rustsecp256k1_v0_4_0_adaptor_0_fe x = p->x;
    rustsecp256k1_v0_4_0_adaptor_0_fe y = p->y;

    rustsecp256k1_v0_4_0_adaptor_0_fe_normalize(&y);
    buf33[0] = rustsecp256k1_v0_4_0_adaptor_0_fe_is_odd(&y);
    rustsecp256k1_v0_4_0_adaptor_0_fe_normalize(&x);
    rustsecp256k1_v0_4_0_adaptor_0_fe_get_b32(&buf33[1], &x);
}

static int rustsecp256k1_v0_4_0_adaptor_0_dleq_deserialize_point(rustsecp256k1_v0_4_0_adaptor_0_ge *p, const unsigned char *buf33) {
    rustsecp256k1_v0_4_0_adaptor_0_fe x;

    if (!rustsecp256k1_v0_4_0_adaptor_0_fe_set_b32(&x, &buf33[1])) {
        return 0;
    }
    if (buf33[0] > 1) {
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_ge_set_xo_var(p, &x, buf33[0]);
    return 1;
}

/* TODO: Remove these debuggin functions */
static void print_buf(const unsigned char *buf, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}
static void print_scalar(const rustsecp256k1_v0_4_0_adaptor_0_scalar *x) {
    unsigned char buf32[32];
    rustsecp256k1_v0_4_0_adaptor_0_scalar_get_b32(buf32, x);
    print_buf(buf32, 32);
}

static void print_ge(const rustsecp256k1_v0_4_0_adaptor_0_ge *p) {
    unsigned char buf33[33];
    rustsecp256k1_v0_4_0_adaptor_0_dleq_serialize_point(buf33, p);
    print_buf(buf33, 33);
}

static void rustsecp256k1_v0_4_0_adaptor_0_dleq_hash_point(rustsecp256k1_v0_4_0_adaptor_0_sha256 *sha, const rustsecp256k1_v0_4_0_adaptor_0_ge *p) {
    unsigned char buf33[33];
    rustsecp256k1_v0_4_0_adaptor_0_dleq_serialize_point(buf33, p);
    rustsecp256k1_v0_4_0_adaptor_0_sha256_write(sha, buf33, 33);
}

static void rustsecp256k1_v0_4_0_adaptor_0_dleq_challenge_hash(rustsecp256k1_v0_4_0_adaptor_0_scalar *e, const unsigned char *algo16, const rustsecp256k1_v0_4_0_adaptor_0_ge *gen2, const rustsecp256k1_v0_4_0_adaptor_0_ge *r1, const rustsecp256k1_v0_4_0_adaptor_0_ge *r2, const rustsecp256k1_v0_4_0_adaptor_0_ge *p1, const rustsecp256k1_v0_4_0_adaptor_0_ge *p2) {
    rustsecp256k1_v0_4_0_adaptor_0_sha256 sha;
    unsigned char buf32[32];

    rustsecp256k1_v0_4_0_adaptor_0_sha256_initialize_tagged(&sha, algo16, algo16_len(algo16));
    rustsecp256k1_v0_4_0_adaptor_0_dleq_hash_point(&sha, gen2);
    rustsecp256k1_v0_4_0_adaptor_0_dleq_hash_point(&sha, r1);
    rustsecp256k1_v0_4_0_adaptor_0_dleq_hash_point(&sha, r2);
    rustsecp256k1_v0_4_0_adaptor_0_dleq_hash_point(&sha, p1);
    rustsecp256k1_v0_4_0_adaptor_0_dleq_hash_point(&sha, p2);
    rustsecp256k1_v0_4_0_adaptor_0_sha256_finalize(&sha, buf32);

    rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(e, buf32, NULL);
}

/* p1 = x*G, p2 = x*gen2, constant time */
static void rustsecp256k1_v0_4_0_adaptor_0_dleq_pair(const rustsecp256k1_v0_4_0_adaptor_0_ecmult_gen_context *ecmult_gen_ctx, rustsecp256k1_v0_4_0_adaptor_0_ge *p1, rustsecp256k1_v0_4_0_adaptor_0_ge *p2, const rustsecp256k1_v0_4_0_adaptor_0_scalar *sk, const rustsecp256k1_v0_4_0_adaptor_0_ge *gen2) {
    rustsecp256k1_v0_4_0_adaptor_0_gej p1j, p2j;
    rustsecp256k1_v0_4_0_adaptor_0_ecmult_gen(ecmult_gen_ctx, &p1j, sk);
    rustsecp256k1_v0_4_0_adaptor_0_ge_set_gej(p1, &p1j);
    rustsecp256k1_v0_4_0_adaptor_0_ecmult_const(&p2j, gen2, sk, 256);
    rustsecp256k1_v0_4_0_adaptor_0_ge_set_gej(p2, &p2j);
}

/* TODO: allow signing a message by including it in the challenge hash */
static int rustsecp256k1_v0_4_0_adaptor_0_dleq_proof(const rustsecp256k1_v0_4_0_adaptor_0_ecmult_gen_context *ecmult_gen_ctx, rustsecp256k1_v0_4_0_adaptor_0_scalar *s, rustsecp256k1_v0_4_0_adaptor_0_scalar *e, const unsigned char *algo16, const rustsecp256k1_v0_4_0_adaptor_0_scalar *sk, const rustsecp256k1_v0_4_0_adaptor_0_ge *gen2) {
    unsigned char nonce32[32];
    unsigned char key32[32];
    rustsecp256k1_v0_4_0_adaptor_0_ge p1, p2;
    rustsecp256k1_v0_4_0_adaptor_0_sha256 sha;
    rustsecp256k1_v0_4_0_adaptor_0_gej r1j, r2j;
    rustsecp256k1_v0_4_0_adaptor_0_ge r1, r2;
    unsigned char buf32[32];
    rustsecp256k1_v0_4_0_adaptor_0_scalar k;

    rustsecp256k1_v0_4_0_adaptor_0_dleq_pair(ecmult_gen_ctx, &p1, &p2, sk, gen2);

    /* Everything that goes into the challenge hash must go into the nonce as well... */
    rustsecp256k1_v0_4_0_adaptor_0_sha256_initialize(&sha);
    rustsecp256k1_v0_4_0_adaptor_0_dleq_hash_point(&sha, gen2);
    rustsecp256k1_v0_4_0_adaptor_0_dleq_hash_point(&sha, &p1);
    rustsecp256k1_v0_4_0_adaptor_0_dleq_hash_point(&sha, &p2);
    rustsecp256k1_v0_4_0_adaptor_0_sha256_finalize(&sha, buf32);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_get_b32(key32, sk);
    if (!nonce_function_dleq(nonce32, buf32, key32, algo16)) {
        return 0;
    }
    rustsecp256k1_v0_4_0_adaptor_0_scalar_set_b32(&k, nonce32, NULL);
    if (rustsecp256k1_v0_4_0_adaptor_0_scalar_is_zero(&k)) {
        return 0;
    }

    rustsecp256k1_v0_4_0_adaptor_0_ecmult_gen(ecmult_gen_ctx, &r1j, &k);
    rustsecp256k1_v0_4_0_adaptor_0_ge_set_gej(&r1, &r1j);
    rustsecp256k1_v0_4_0_adaptor_0_ecmult_const(&r2j, gen2, &k, 256);
    rustsecp256k1_v0_4_0_adaptor_0_ge_set_gej(&r2, &r2j);

    rustsecp256k1_v0_4_0_adaptor_0_dleq_challenge_hash(e, algo16, gen2, &r1, &r2, &p1, &p2);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_mul(s, e, sk);
    rustsecp256k1_v0_4_0_adaptor_0_scalar_add(s, s, &k);

    rustsecp256k1_v0_4_0_adaptor_0_scalar_clear(&k);
    return 1;
}

static int rustsecp256k1_v0_4_0_adaptor_0_dleq_verify(const rustsecp256k1_v0_4_0_adaptor_0_ecmult_context *ecmult_ctx, const unsigned char *algo16, const rustsecp256k1_v0_4_0_adaptor_0_scalar *s, const rustsecp256k1_v0_4_0_adaptor_0_scalar *e, const rustsecp256k1_v0_4_0_adaptor_0_ge *p1, const rustsecp256k1_v0_4_0_adaptor_0_ge *gen2, const rustsecp256k1_v0_4_0_adaptor_0_ge *p2) {
    rustsecp256k1_v0_4_0_adaptor_0_scalar e_neg;
    rustsecp256k1_v0_4_0_adaptor_0_scalar e_expected;
    rustsecp256k1_v0_4_0_adaptor_0_gej gen2j;
    rustsecp256k1_v0_4_0_adaptor_0_gej p1j, p2j;
    rustsecp256k1_v0_4_0_adaptor_0_gej r1j, r2j;
    rustsecp256k1_v0_4_0_adaptor_0_ge r1, r2;
    rustsecp256k1_v0_4_0_adaptor_0_gej tmpj;

    rustsecp256k1_v0_4_0_adaptor_0_gej_set_ge(&p1j, p1);
    rustsecp256k1_v0_4_0_adaptor_0_gej_set_ge(&p2j, p2);

    rustsecp256k1_v0_4_0_adaptor_0_scalar_negate(&e_neg, e);
    /* R1 = s*G  - e*P1 */
    rustsecp256k1_v0_4_0_adaptor_0_ecmult(ecmult_ctx, &r1j, &p1j, &e_neg, s);
    /* R2 = s*gen2 - e*P2 */
    rustsecp256k1_v0_4_0_adaptor_0_ecmult(ecmult_ctx, &tmpj, &p2j, &e_neg, &rustsecp256k1_v0_4_0_adaptor_0_scalar_zero);
    rustsecp256k1_v0_4_0_adaptor_0_gej_set_ge(&gen2j, gen2);
    rustsecp256k1_v0_4_0_adaptor_0_ecmult(ecmult_ctx, &r2j, &gen2j, s, &rustsecp256k1_v0_4_0_adaptor_0_scalar_zero);
    rustsecp256k1_v0_4_0_adaptor_0_gej_add_var(&r2j, &r2j, &tmpj, NULL);

    rustsecp256k1_v0_4_0_adaptor_0_ge_set_gej(&r1, &r1j);
    rustsecp256k1_v0_4_0_adaptor_0_ge_set_gej(&r2, &r2j);
    rustsecp256k1_v0_4_0_adaptor_0_dleq_challenge_hash(&e_expected, algo16, gen2, &r1, &r2, p1, p2);

    rustsecp256k1_v0_4_0_adaptor_0_scalar_add(&e_expected, &e_expected, &e_neg);
    return rustsecp256k1_v0_4_0_adaptor_0_scalar_is_zero(&e_expected);
}

#endif /* _SECP256K1_DLEQ_IMPL_H_ */
