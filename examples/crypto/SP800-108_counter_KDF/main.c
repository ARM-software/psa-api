/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <psa/crypto.h>

#define CMAC_KEY_LENGTH  (16)
#define OTUPUT_LENGTH    (42)
#define AES_BLOCK_SIZE    PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES)
#define L_LENGTH 	(sizeof(uint32_t))

/* 2^29 -1 */
#define PSA_ALG_SP800_108_COUNTER_CMAC_INIT_CAPACITY (0x1fffffff)

static uint8_t m_input_cmac_key[CMAC_KEY_LENGTH] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
						  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0d, 0x0f};

static uint8_t m_input_hmac_key[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0d, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0d, 0x0f};

/* Label that identifies the purpose for the derived keying material */
static uint8_t m_label[] = {"PSA_ALG_SP800_108_COUNTER Sample"};
/* Don't include the NULL terminator in the length */
const size_t label_length = sizeof(m_label) - 1;

/* Context containing the information related to the derived keying material */
static uint8_t m_context[] = {"Sample key creation via SP 800-108r1 Counter mode"};
/* Don't include the NULL terminator in the length */
const size_t context_length = sizeof(m_context) - 1;

/* Buffer to hold the key generated from CMAC_CTR_KDF */
static uint8_t m_output[OTUPUT_LENGTH] = {0};

static size_t min(size_t a, size_t b){
	return a < b ? a : b;
}

static void print_hex(const uint8_t *out, const size_t out_length)
{
	printf("----------------------------------- len: %lu -----------------------------------\n",
	       out_length);
	printf("%02x ", out[0]);
	for (size_t i = 1; i < out_length; i++) {
		if (i % 16 == 0) {
			printf("\n");
		}
		printf("%02x ", out[i]);
	}
	printf("\n------------------------------------- end "
	       "-------------------------------------\n");
}

static void print_parameters(const uint8_t *key_buffer, const size_t key_buffer_length,
			     uint8_t *label, const size_t label_length, const uint8_t *context,
			     const size_t context_length, const size_t capacity)
{
	printf("Key:\n");
	print_hex(key_buffer, key_buffer_length);
	printf("Label:\n");
	print_hex(label, label_length);
	if (context_length > 0) {
		printf("Context:\n");
		print_hex(context, context_length);
	}
	printf("Capacity: %#lx\n\n", (unsigned long) capacity);
}

static psa_status_t import_hmac_key(const uint8_t *key_buffer, const size_t key_buffer_length,
				    const psa_algorithm_t alg, psa_key_id_t *key_id)
{
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	/* Configure the input key attributes */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_HMAC(alg));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_HMAC);

	/* Import the master key into the keystore */
	return psa_import_key(&key_attributes, key_buffer, key_buffer_length, key_id);
}

/* Adds ( label || 0x00 || context|| [L]_4 ) to given mac operation */
static psa_status_t mac_update_fixed_input(psa_mac_operation_t *op, const uint8_t *label,
					   const size_t label_length, const uint8_t *context,
					   const size_t context_length, const uint8_t * L)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	/* 0x00 byte used to separate the label from the context */
	uint8_t zero_byte = 0x00;

	status = psa_mac_update(op, label, label_length);
	if (status != PSA_SUCCESS) {
		printf("\npsa_mac_update label failed! (Error: %d)\n", status);
		return status;
	}

	status = psa_mac_update(op, &zero_byte, sizeof(zero_byte));
	if (status != PSA_SUCCESS) {
		printf("\npsa_mac_update zero_byte failed! (Error: %d)\n", status);
		return status;
	}

	status = psa_mac_update(op, context, context_length);
	if (status != PSA_SUCCESS) {
		printf("\npsa_mac_update context failed! (Error: %d)\n", status);
		return status;
	}

	status = psa_mac_update(op, L, L_LENGTH);
	if (status != PSA_SUCCESS) {
		printf("\npsa_mac_update L failed! (Error: %d)\n", status);
		return status;
	}

	return PSA_SUCCESS;
}

static psa_status_t sp800_108_counter_hmac_kdf(psa_algorithm_t hash_alg, const uint8_t *key_buffer,
					       const size_t key_buffer_length, const uint8_t *label,
					       const size_t label_length, const uint8_t *context,
					       const size_t context_length, const size_t capacity,
					       uint8_t *output, const size_t output_length)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
	psa_key_id_t key_id;
	size_t output_size;
	size_t bytes_produced = 0;
	/* Set the capacity in bits and big-endian*/
	uint8_t L[L_LENGTH] = {PSA_BYTES_TO_BITS(capacity) >> 24, PSA_BYTES_TO_BITS(capacity) >> 16, PSA_BYTES_TO_BITS(capacity) >> 8, PSA_BYTES_TO_BITS(capacity)};

	printf("Deriving a key using SP800-108 HMAC(SHA256) counter mode...");

	/* Can only output 2^29 -1 bytes*/
	if (capacity > PSA_ALG_SP800_108_COUNTER_CMAC_INIT_CAPACITY &&
	    output_length > PSA_ALG_SP800_108_COUNTER_CMAC_INIT_CAPACITY) {
		printf("\ncapacity or output_length is greater than 2^29-1\n");
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = import_hmac_key(key_buffer, key_buffer_length, hash_alg, &key_id);
	if (status != PSA_SUCCESS) {
		printf("\nimport_hmac_key failed! (Error: %d)\n", status);
		return status;
	}

	/* K_i = HMAC(K_in, [i]_4 || label || 0x00 || context || [L]_4 ) */
	for (uint32_t i = 1; bytes_produced < output_length; i++) {
		uint8_t K_i[PSA_HASH_MAX_SIZE] = {0};

		/* Initialize the HMAC operation and input K_in */
		status = psa_mac_sign_setup(&operation, key_id, PSA_ALG_HMAC(hash_alg));
		if (status != PSA_SUCCESS) {
			printf("\n\npsa_mac_sign_setup failed! (Error: %d)\n", status);
			goto error;
		}

		/* counter is needed as 4 byte big-endian */
		uint8_t counter_be[sizeof(i)] = {i >> 24, i >> 16, i >> 8, i};

		/* [i]_4  */
		status = psa_mac_update(&operation, counter_be, sizeof(i));
		if (status != PSA_SUCCESS) {
			printf("\npsa_mac_update [i]_4 failed! (Error: %d)\n", status);
			goto error;
		}

		/* label || 0x00 || context || [L]_4 */
		status = mac_update_fixed_input(&operation, label, label_length, context,
						context_length, L);
		if (status != PSA_SUCCESS) {
			printf("\nmac_update_fixed_input failed! (Error: %d)\n", status);
			goto error;
		}

		status = psa_mac_sign_finish(&operation, K_i, sizeof(K_i), &output_size);
		if (status != PSA_SUCCESS) {
			printf("\npsa_mac_sign_finish failed! (Error: %d)\n", status);
			goto error;
		}

		memcpy(output + bytes_produced, K_i,
		       min(output_size, output_length - bytes_produced));
		bytes_produced += min(output_size, output_length - bytes_produced);
	}
	psa_destroy_key(key_id);
	printf("Done\n");

	return PSA_SUCCESS;

error:
	psa_destroy_key(key_id);
	psa_mac_abort(&operation);
	return status;
}

static psa_status_t import_cmac_key(const uint8_t *key_buffer, const uint8_t key_buffer_length,
				    psa_key_id_t *key_id)
{
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	/* Configure the input key attributes */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_CMAC);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attributes, PSA_BYTES_TO_BITS(CMAC_KEY_LENGTH));

	/* Import the master key into the keystore */
	return psa_import_key(&key_attributes, key_buffer, key_buffer_length, key_id);
}

static psa_status_t sp800_108_counter_cmac_kdf(const uint8_t *key_buffer,
					       const size_t key_buffer_length, uint8_t *label,
					       const size_t label_length, const uint8_t *context,
					       const size_t context_length, const size_t capacity,
					       uint8_t *output, const size_t output_length)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
	psa_key_id_t key_id;
	uint8_t K_0[AES_BLOCK_SIZE] = {0};
	size_t output_size;
	size_t bytes_produced = 0;
	/* Set the capacity in bits and big-endian*/
	uint8_t L[L_LENGTH] = {PSA_BYTES_TO_BITS(capacity) >> 24, PSA_BYTES_TO_BITS(capacity) >> 16, PSA_BYTES_TO_BITS(capacity) >> 8, PSA_BYTES_TO_BITS(capacity)};

	if (key_buffer_length != CMAC_KEY_LENGTH) {
		printf("\nwrong key size got %lu expected %d\n", key_buffer_length, CMAC_KEY_LENGTH);
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* Can only output 2^29 -1 bytes*/
	if (capacity > PSA_ALG_SP800_108_COUNTER_CMAC_INIT_CAPACITY &&
	    output_length > PSA_ALG_SP800_108_COUNTER_CMAC_INIT_CAPACITY) {
		printf("\ncapacity or output_length is greater than 2^29-1\n");
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	printf("Deriving a key using SP800-108 CMAC counter mode...");

	status = import_cmac_key(key_buffer, key_buffer_length, &key_id);
	if (status != PSA_SUCCESS) {
		printf("\nimport_cmac_key failed! (Error: %d)\n", status);
		return status;
	}

	/* Generate K_0 = CMAC(K_in, label || 0x00 || context|| [L]_4) */
	status = psa_mac_sign_setup(&operation, key_id, PSA_ALG_CMAC);
	if (status != PSA_SUCCESS) {
		printf("\npsa_mac_sign_setup failed! (Error: %d)\n", status);
		goto error;
	}

	status =
		mac_update_fixed_input(&operation, label, label_length, context, context_length, L);
	if (status != PSA_SUCCESS) {
		printf("\nmac_update_fixed_input failed! (Error: %d)\n", status);
		goto error;
	}

	status = psa_mac_sign_finish(&operation, K_0, sizeof(K_0), &output_size);
	if (status != PSA_SUCCESS) {
		printf("\npsa_mac_sign_finish failed! (Error: %d)\n", status);
		goto error;
	}

	/* K_i = CMAC(K_in, [i]_4 || label || 0x00 || context || [L]_4 || K_0) */
	for (uint32_t i = 1; bytes_produced < output_length; i++) {
		uint8_t K_i[AES_BLOCK_SIZE] = {0};
		/* Setup a new operation */
		status = psa_mac_sign_setup(&operation, key_id, PSA_ALG_CMAC);
		if (status != PSA_SUCCESS) {
			printf("\npsa_mac_sign_setup - 2 failed! (Error: %d)\n", status);
			goto error;
		}

		/* counter is needed as 4 byte big-endian */
		uint8_t counter_be[sizeof(i)] = {i >> 24, i >> 16, i >> 8, i};

		/* [i]_4  */
		status = psa_mac_update(&operation, counter_be, sizeof(i));
		if (status != PSA_SUCCESS) {
			printf("\npsa_mac_update [i]_4 failed! (Error: %d)\n", status);
			goto error;
		}

		/* label || 0x00 || context || [L]_4 */
		status = mac_update_fixed_input(&operation, label, label_length, context,
						context_length, L);
		if (status != PSA_SUCCESS) {
			printf("\nmac_update_fixed_input failed! (Error: %d)\n", status);
			goto error;
		}

		/* K_0 */
		status = psa_mac_update(&operation, K_0, sizeof(K_0));
		if (status != PSA_SUCCESS) {
			printf("\npsa_mac_update K_0 failed! (Error: %d)\n", status);
			goto error;
		}

		status = psa_mac_sign_finish(&operation, K_i, sizeof(K_i), &output_size);
		if (status != PSA_SUCCESS) {
			printf("\npsa_mac_sign_finish failed! (Error: %d)\n", status);
			goto error;
		}

		memcpy(output + bytes_produced, K_i,
		       min(output_size, output_length - bytes_produced));
		bytes_produced += min(output_size, output_length - bytes_produced);
	}
	psa_destroy_key(key_id);
	printf("Done\n");

	return PSA_SUCCESS;
error:
	psa_destroy_key(key_id);
	psa_mac_abort(&operation);
	return status;
}

int main(void)
{
	psa_status_t status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		printf("psa_crypto_init failed! (Error: %d)\n", status);
		return EXIT_FAILURE;
	}

	/* Do a SP800-108 counter HMAC kdf with SHA256 */
	status = sp800_108_counter_hmac_kdf(
		PSA_ALG_SHA_256, m_input_hmac_key, sizeof(m_input_hmac_key), m_label, label_length,
		m_context, context_length, OTUPUT_LENGTH, m_output, sizeof(m_output));
	if (status != PSA_SUCCESS){
		return EXIT_FAILURE;
	}

	print_parameters(m_input_hmac_key, sizeof(m_input_hmac_key), m_label, label_length,
				m_context, context_length, OTUPUT_LENGTH);
	printf("HMAC derived key:\n");
	print_hex(m_output, sizeof(m_output));
	printf("\n\n");


	status = sp800_108_counter_hmac_kdf(PSA_ALG_SHA_256, m_input_hmac_key,
					    sizeof(m_input_hmac_key), m_label, label_length,
					    m_context, 0, OTUPUT_LENGTH, m_output, sizeof(m_output));
	if (status != PSA_SUCCESS){
		return EXIT_FAILURE;
	}

	print_parameters(m_input_hmac_key, sizeof(m_input_hmac_key), m_label, label_length,
				m_context, 0, OTUPUT_LENGTH);
	printf("HMAC without context derived key:\n");
	print_hex(m_output, sizeof(m_output));
	printf("\n\n");


	/* Do a SP800-108 counter CMAC kdf */
	status = sp800_108_counter_cmac_kdf(m_input_cmac_key, sizeof(m_input_cmac_key), m_label,
					    label_length, m_context, context_length, OTUPUT_LENGTH,
					    m_output, sizeof(m_output));

	if (status != PSA_SUCCESS){
		return EXIT_FAILURE;
	}

	print_parameters(m_input_cmac_key, sizeof(m_input_cmac_key), m_label, label_length,
				m_context, context_length, OTUPUT_LENGTH);
	printf("CMAC derived key:\n");
	print_hex(m_output, sizeof(m_output));
	printf("\n\n");


	status = sp800_108_counter_cmac_kdf(m_input_cmac_key, sizeof(m_input_cmac_key), m_label,
					    label_length, m_context, 0, OTUPUT_LENGTH, m_output,
					    sizeof(m_output));

	if (status != PSA_SUCCESS){
		return EXIT_FAILURE;
	}

	print_parameters(m_input_cmac_key, sizeof(m_input_cmac_key), m_label, label_length,
				m_context, 0, OTUPUT_LENGTH);
	printf("CMAC without context derived key:\n");
	print_hex(m_output, sizeof(m_output));
	printf("\n\n");
}
