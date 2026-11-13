#include <stdint.h>

#include "pdc_tf_builtin_common.h"
#include "pdc_client_server_common.h"
#include "pdc_tf_common.h"
#include "pdc_tf_user.h"
#include "pdc_logger.h"

#ifdef ENABLE_TF_ENCRYPTION
// #include <sodium.h>
#include <enc_wrapper.h>

typedef struct encrypt_params_t {
    pdc_tf_region_t unencrypted_region;
} encrypt_params_t;

bool
pdc_tf_builtin_ew_encrypt(pdc_tf_internal_param *internal_param, char *params_str, void **region_data,
                       pdc_tf_region_t input_region, pdc_tf_region_t *output_region)
{
    LOG_DEBUG("pdc_tf_builtin_ew_encrypt called\n");
    PDCtf_log_pdc_region_t(input_region);

    enc_config conf = {
        .alg = aes256,
        .lib = enc_lib_gcrypt
    };

    enc_load_config(conf);

    char *key, *nonce;
    size_t key_size, nonce_size;
    key_size = enc_get_key_size();
    nonce_size = enc_get_nonce_size();

    key = calloc(key_size, 1);
    nonce = enc_make_nonce();

    size_t plaintext_len = PDCtf_get_pdc_region_t_bytes(input_region);
    size_t ciphertext_len = plaintext_len + nonce_size;
    char *ciphertext     = malloc(ciphertext_len);
    if (!ciphertext) {
        LOG_ERROR("Failed to allocate ciphertext buffer\n");
        return false;
    }

    enc_encrypt((char*)*region_data, plaintext_len, ciphertext, plaintext_len);
    memcpy(ciphertext + plaintext_len, nonce, nonce_size);

    output_region->ndim         = 1;
    output_region->pdc_var_type = PDC_CHAR;
    output_region->size[0]      = ciphertext_len;
    
    encrypt_params_t *out_params = (encrypt_params_t *)malloc(sizeof(encrypt_params_t));
    PDCtf_copy_tf_region_t(&input_region, &out_params->unencrypted_region);
    SET_FUNC_PARAMS("ew_encrypt", PDC_TF_CPU_DEVICE, out_params, sizeof(encrypt_params_t));

    *region_data = ciphertext;
    LOG_DEBUG("Encryption succeeded, ciphertext length: %zu bytes\n", ciphertext_len);

    free(nonce);
    free(key);

    return true;
}

bool
pdc_tf_builtin_ew_decrypt(pdc_tf_internal_param *internal_param, char *params_str, void **region_data,
                       pdc_tf_region_t input_region, pdc_tf_region_t *output_region)
{
    LOG_DEBUG("pdc_tf_builtin_ew_decrypt called\n");
    PDCtf_log_pdc_region_t(input_region);

    enc_config conf = {
        .alg = aes256,
        .lib = enc_lib_gcrypt
    };

    enc_load_config(conf);

    char *key, *nonce;
    size_t key_size, nonce_size;
    key_size = enc_get_key_size();
    nonce_size = enc_get_nonce_size();

    key = calloc(key_size, 1);
    nonce = malloc(nonce_size);

    size_t ciphertext_len = PDCtf_get_pdc_region_t_bytes(input_region);

    encrypt_params_t *in_params;
    uint64_t          in_params_size;
    GET_FUNC_PARAMS("ew_encrypt", PDC_TF_CPU_DEVICE, (void **)&in_params, &in_params_size);

    if (ciphertext_len < nonce_size) {
        LOG_ERROR("Ciphertext too short\n");
        return false;
    }

    size_t plaintext_len = PDC_get_region_desc_size_bytes(
        in_params->unencrypted_region.size, PDC_get_var_type_size(in_params->unencrypted_region.pdc_var_type),
        in_params->unencrypted_region.ndim);

    unsigned char *plaintext = malloc(plaintext_len);
    if (!plaintext) {
        LOG_ERROR("Failed to allocate plaintext buffer\n");
        return false;
    }

    memcpy(nonce, (char*)*region_data + plaintext_len, nonce_size);
    enc_set_nonce(nonce, nonce_size);
    enc_decrypt((char*)*region_data, plaintext_len, plaintext, plaintext_len);

    PDCtf_copy_tf_region_t(&in_params->unencrypted_region, output_region);
    *region_data = plaintext;

    free(nonce);
    free(key);

    LOG_DEBUG("Decryption succeeded, plaintext length: %zu bytes\n", plaintext_len);
    return true;
}

#endif // ENABLE_TF_ENCRYPTION
