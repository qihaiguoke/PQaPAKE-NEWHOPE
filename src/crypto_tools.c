#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "crypto_tools.h"
#include "api.h"

#if (CRYPTO_N == 512)
#define AE_OPT EVP_aes_128_gcm()
#define MAC_OPT OSSL_DIGEST_NAME_SHA2_256
#elif (CRYPTO_N == 1024)
#define AE_OPT EVP_aes_256_gcm()
#define MAC_OPT OSSL_DIGEST_NAME_SHA2_512
#endif

void ae_encrypt(const uint8_t *key, uint8_t *plaintext, int in_nbytes, uint8_t *ciphertext, int *out_nbytes)
{
    uint8_t iv[IV_LENGTH];
    RAND_bytes(iv, IV_LENGTH);
    memcpy(ciphertext, iv, IV_LENGTH);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, AE_OPT, key, iv);

    int len = 0;
    EVP_EncryptUpdate(ctx, ciphertext + IV_LENGTH, &len, plaintext, in_nbytes);
    EVP_EncryptFinal(ctx, ciphertext + IV_LENGTH + len, out_nbytes);
    *out_nbytes += len + AUTH_TAG_LENGTH + IV_LENGTH;

    uint8_t auth_tag[AUTH_TAG_LENGTH];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_LENGTH, auth_tag);
    memcpy(ciphertext + *out_nbytes - AUTH_TAG_LENGTH, auth_tag, AUTH_TAG_LENGTH);

    EVP_CIPHER_CTX_free(ctx);
}

void ae_decrypt(const uint8_t *key, uint8_t *ciphertext, int in_nbytes, uint8_t *plaintext, int *out_nbytes)
{
    uint8_t iv[IV_LENGTH];
    memcpy(iv, ciphertext, IV_LENGTH);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, AE_OPT, key, iv);
    int len = 0;
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + IV_LENGTH, in_nbytes - IV_LENGTH - AUTH_TAG_LENGTH);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AUTH_TAG_LENGTH, ciphertext + in_nbytes - AUTH_TAG_LENGTH);

    EVP_DecryptFinal(ctx, plaintext + len, out_nbytes);
    if(out_nbytes!=NULL) *out_nbytes += len;

    EVP_CIPHER_CTX_free(ctx);
}

void transcript_hmac(uint8_t **input, size_t *in_nbytes, int round, const uint8_t *key, size_t key_length, uint8_t *hmac)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);

    mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST,
            MAC_OPT,
            0),
        OSSL_PARAM_construct_end()};

    EVP_MAC_init(ctx, key, key_length, params);

    for (int i = 0; i < round; ++i)
    {
        EVP_MAC_update(ctx, input[i], in_nbytes[i]);
    }
    size_t out_nbytes = 0;
    EVP_MAC_final(ctx, hmac, &out_nbytes, HMAC_LENGTH);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

void generate_salt(char *salt, int salt_len)
{
    uint8_t salt_bytes[salt_len / 2];
    RAND_bytes(salt_bytes, salt_len / 2);
    int s = 0;

    for (int i = 0; i < salt_len / 2; ++i)
    {
        s = salt_bytes[i] >> 4;
        salt[2 * i] = s <= 9 ? s + '0' : s - 10 + 'a';
        s = salt_bytes[i] & 0x0f;
        salt[2 * i + 1] = s <= 9 ? s + '0' : s - 10 + 'a';
    }
}

void derive_key(const uint8_t *password, int pwsize, char *salt, uint8_t *key)
{

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_SCRYPT, NULL);
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);

    // OWASP recommended settings.
    uint64_t scrypt_n = 65536;
    uint32_t scrypt_r = 8;
    uint32_t scrypt_p = 1;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD,
            (char *)password, pwsize),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, (char *)salt, SALT_LENGTH),
        OSSL_PARAM_construct_uint64(
            OSSL_KDF_PARAM_SCRYPT_N, &scrypt_n),
        OSSL_PARAM_construct_uint32(
            OSSL_KDF_PARAM_SCRYPT_R, &scrypt_r),
        OSSL_PARAM_construct_uint32(
            OSSL_KDF_PARAM_SCRYPT_P, &scrypt_p),
        OSSL_PARAM_construct_end()};

    EVP_KDF_derive(ctx, key, KEY_LENGTH, params);
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
}
