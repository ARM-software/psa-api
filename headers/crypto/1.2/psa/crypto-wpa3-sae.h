/* This file contains reference definitions for implementations of 
 * WPA3-SAE and WPA3-SAE-PT in addition to the PSA Certified Crypto
 * API v1.2 PAKE Extension
 *
 * These definitions must be embedded in, or included by, psa/crypto.h
 */
 
#define PSA_KEY_TYPE_WPA3_SAE_PT_BASE          ((psa_key_type_t) 0x7800)
#define PSA_KEY_TYPE_WPA3_SAE_GROUP_MASK       ((psa_key_type_t) 0x00ff)

/** WPA3-SAE-PT key.
 *
 * The key is used to store the out of band calculated group element
 * used in the Hash-To-Element variant of WPA3-SAE. It can be used as
 * input to the WPA3-SAE PAKE instead of a password key.
 *
 * \param group A value of type ::psa_ec_family_t or ::psa_dh_family_t
 *              that identifies the group to be used.
 */
#define PSA_KEY_TYPE_WPA3_SAE_PT(group) \
    ((psa_key_type_t) (PSA_KEY_TYPE_WPA3_SAE_PT_BASE | (group)))

 /** Whether a key type is a WPA3-SAE-PT. */
#define PSA_KEY_TYPE_IS_WPA3_SAE_PT(type)                    \
    (((type) & ~PSA_KEY_TYPE_WPA3_SAE_GROUP_MASK) ==         \
     PSA_KEY_TYPE_WPA3_SAE_PT_BASE)
 /** Extract the group from a WPA3-SAE key type. */
#define PSA_KEY_TYPE_WPA3_SAE_PT_GET_FAMILY(type)            \
    ((psa_ecc_family_t) (PSA_KEY_TYPE_IS_WPA3_SAE_PT(type) ? \
      ((type) & PSA_KEY_TYPE_WPA3_SAE_GROUP_MASK) :          \
      0))

#define PSA_ALG_WPA3_SAE_PT_BASE          ((psa_algorithm_t) 0x08800400)
/** The WPA3-SAE password to PT KDF.
 * It takes the password p, a salt (uuid), and optionally a password id.
 * 
 * This key derivation algorithm uses the following inputs, which must be
 * provided in the following order:
 * - #PSA_KEY_DERIVATION_INPUT_SALT for the uuid.
 * - #PSA_KEY_DERIVATION_INPUT_SECRET for the password.
 * - optionally; #PSA_KEY_DERIVATION_INPUT_INFO for the password id.
 * The output has to be read as a key of type PSA_KEY_TYPE_WPA3_SAE_PT.
 *
 * \param hash_alg      A hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true).
 *
 * \return              The corresponding counter-mode KDF algorithm.
 * \return              Unspecified if \p hash_alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_WPA3_SAE_PT(hash_alg)                            \
    (PSA_ALG_WPA3_SAE_PT_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))

/** Whether the specified algorithm is a key derivation algorithm constructed
 * using #PSA_ALG_WPA3_SAE_PT(\p hash_alg).
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a key derivation algorithm constructed using #PSA_ALG_WPA3_SAE_PT(),
 *         0 otherwise. This macro may return either 0 or 1 if \c alg is not a supported
 *         key derivation algorithm identifier.
 */
#define PSA_ALG_IS_WPA3_SAE_PT(alg)                         \
    (((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_WPA3_SAE_PT_BASE)

/** The WPA3-SAE key exchange algorithm.
 *
 * This is WPA3-SAE as defined by "IEEE Std 802.11-REVme/D7.0 2024, 
 * chapter 12.4", including the Hash-To-Element (H2E) variant.
 * It is instantiated with the following parameters:
 *
 * - The group is defined over a finite field or an elliptic curve.
 * - A cryptographic hash function.
 *
 * For WPA3-SAE selected by the AKM suites 8 and 9, use the
 * PSA_ALG_WPA3_SAE_FIXED() algorithm, parameterized by the required hash
 * algorithm.
 * For WPA3-SAE selected by the AKM suites 24 and 25 (SAE using group-dependent
 * hash), use the PSA_ALG_WPA3_SAE_GDH() algorithm, parameterized by the
 * required hash algorithm.
 * 
 * To select these parameters and set up the cipher suite, call these functions:
 *
 * \code
 * psa_pake_cipher_suite_t cipher_suite = PSA_PAKE_CIPHER_SUITE_INIT;
 * psa_pake_cs_set_algorithm(cipher_suite, PSA_ALG_WPA3_SAE_FIXED(hash));
 * psa_pake_cs_set_primitive(&cipher_suite,
 *                           PSA_PAKE_PRIMITIVE(type, family, bits));
 * \endcode
 *
 * After initializing a WPA3-SAE operation, call:
 *
 * \code
 * psa_pake_setup(operation, password, cipher_suite);
 * psa_pake_set_user(operation, ...);
 * psa_pake_set_peer(operation, ...);
 * \endcode
 * 
 * For basic SAE the password must be of type #PSA_KEY_TYPE_PASSWORD,
 * for SAE-H2E the password must be of type #PSA_KEY_TYPE_WPA3_SAE_PT.
 *
 * \c psa_pake_set_role() must not be called because WPA3-SAE is a symmetric PAKE.
 * 
 * For a key exchange first call the following functions in any order:
 * \code
 * // send commit message
 * psa_pake_output(operation, #PSA_PAKE_STEP_COMMIT, ...);
 * // receive commit message
 * psa_pake_input(operation, #PSA_PAKE_STEP_COMMIT, ...);
 * \endcode
 *
 * If the Hash-To-Element variant is used and a list of rejected groups
 * is available, it must be provided as a salt:
 *
 * \code
 * // input salt
 * psa_pake_input(operation, #PSA_PAKE_STEP_SALT, ...);
 * \endcode
 *
 * Then call the following functions in any order:
 * \code
 * // set send-confirm counter
 * psa_pake_input(operation, #PSA_PAKE_STEP_SEND_CONFIRM, ...);
 * // send confirm message
 * psa_pake_output(operation, #PSA_PAKE_STEP_CONFIRM, ...);
 * // receive confirm message
 * psa_pake_input(operation, #PSA_PAKE_STEP_CONFIRM, ...);
 * // get key id (optional)
 * psa_pake_output(operation, #PSA_PAKE_STEP_KEYID, ...);
 * \endcode
 * 
 * Remarks:
 * \c psa_pake_input(#PSA_PAKE_STEP_SEND_CONFIRM) must be called before
 * \c psa_pake_output(#PSA_PAKE_STEP_CONFIRM) to set the send-confirm counter.
 * The #PSA_PAKE_STEP_SEND_CONFIRM and #PSA_PAKE_STEP_CONFIRM steps may be used
 * multiple times to handle repeated confirm messages with varying counts.
 *
 * Finally get the shared secret: 
 *
 * \code
 * // get secret
 * psa_pake_get_shared_key();
 * \endcode
 *
 * The shared secret produced by WPA3-SAE is pseudorandom.
 * It can be used directly as an encryption key or as input to a key derivation
 * operation.
 */
#define PSA_ALG_WPA3_SAE_FIXED_BASE             ((psa_algorithm_t) 0x0a000800)
#define PSA_ALG_WPA3_SAE_FIXED(hash_alg) (PSA_ALG_WPA3_SAE_FIXED_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))
#define PSA_ALG_WPA3_SAE_GDH_BASE               ((psa_algorithm_t) 0x0a000900)
#define PSA_ALG_WPA3_SAE_GDH(hash_alg) (PSA_ALG_WPA3_SAE_GDH_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))
#define PSA_ALG_IS_WPA3_SAE(alg) (((alg) & ~0x000001ff) == PSA_ALG_WPA3_SAE_FIXED_BASE)
#define PSA_ALG_IS_WPA3_SAE_FIXED(alg) (((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_WPA3_SAE_FIXED_BASE)
#define PSA_ALG_IS_WPA3_SAE_GDH(alg) (((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_WPA3_SAE_GDH_BASE)

/** The key confirmation value.
 * 
 * This value is used during the key confirmation phase of a PAKE protocol.
 * The format of the value depends on the algorithm and cipher suite:
 *
 * For SPAKE2+ algorithms, the format for both input and output at this step is
 * the same as the output of the MAC algorithm specified in the cipher suite.
 *
 * For PSA_ALG_SRP_6, the format for both input and output at this step is
 * the same as the output of the hash algorithm specified.
 *
 * For WPA3_SAE algorithms, the format for both input and output at this step
 * is a 2 byte little-endian "send-confirm" counter followed by the output of
 * the hash algorithm specified.
 */
#define PSA_PAKE_STEP_CONFIRM                   ((psa_pake_step_t)0x04)

/** The WPA3-SAE commit step.
 *
 * The format for both input and output at this step is a 2 byte number
 * specifying the group used followed by a scalar and an element of the
 * specified group.
 */
#define PSA_PAKE_STEP_COMMIT                    ((psa_pake_step_t)0x06)

/** The WPA3-SAE send-confirm input step.
 *
 * The format for the input at this step is a 2 byte little-endian number
 * specifying the send-confirm counter to be used in the following confirm
 * output step.
 */
#define PSA_PAKE_STEP_SEND_CONFIRM              ((psa_pake_step_t)0x07)

/** The WPA3-SAE key id output step.
 *
 * The format of the output at this step is a 16 byte key id (PMKID).
 */
#define PSA_PAKE_STEP_KEYID                     ((psa_pake_step_t)0x08)

/** A sufficient output buffer size for psa_pake_output().
 *
 * If the size of the output buffer is at least this large, it is guaranteed
 * that psa_pake_output() will not fail due to an insufficient output buffer
 * size. The actual size of the output might be smaller in any given call.
 *
 * See also #PSA_PAKE_OUTPUT_MAX_SIZE
 *
 * \param alg           A PAKE algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_PAKE(\p alg) is true).
 * \param primitive     A primitive of type ::psa_pake_primitive_t that is
 *                      compatible with algorithm \p alg.
 * \param output_step   A value of type ::psa_pake_step_t that is valid for the
 *                      algorithm \p alg.
 * \return              A sufficient output buffer size for the specified
 *                      PAKE algorithm, primitive, and output step. If the
 *                      PAKE algorithm, primitive, or output step is not
 *                      recognized, or the parameters are incompatible,
 *                      return 0.
 */
#define PSA_PAKE_OUTPUT_SIZE(alg, primitive, output_step)               \
    (output_step == PSA_PAKE_STEP_KEY_SHARE ? \
        PSA_PAKE_PRIMITIVE_GET_TYPE(primitive) == PSA_PAKE_PRIMITIVE_TYPE_DH ? \
            PSA_BITS_TO_BYTES(PSA_PAKE_PRIMITIVE_GET_BITS(primitive)) : \
            PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_PAKE_PRIMITIVE_GET_BITS(primitive)) : \
     output_step == PSA_PAKE_STEP_ZK_PUBLIC ? \
        PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_PAKE_PRIMITIVE_GET_BITS(primitive)) : \
     output_step == PSA_PAKE_STEP_ZK_PROOF ? \
        PSA_BITS_TO_BYTES(PSA_PAKE_PRIMITIVE_GET_BITS(primitive)) : \
     output_step == PSA_PAKE_STEP_COMMIT ? \
        PSA_BITS_TO_BYTES(PSA_PAKE_PRIMITIVE_GET_BITS(primitive)) * 3 + 2 : \
     output_step == PSA_PAKE_STEP_CONFIRM ? \
        PSA_ALG_IS_SPAKE2P_CMAC(alg) ? \
            PSA_MAC_LENGTH(PSA_KEY_TYPE_AES, 128, PSA_ALG_CMAC) : \
            PSA_HASH_LENGTH(alg) + (PSA_ALG_IS_WPA3_SAE(alg) ? 2 : 0) : \
     output_step == PSA_PAKE_STEP_KEYID ? \
        16u : \
     0u)

/** A sufficient input buffer size for psa_pake_input().
 *
 * The value returned by this macro is guaranteed to be large enough for any
 * valid input to psa_pake_input() in an operation with the specified
 * parameters.
 *
 * See also #PSA_PAKE_INPUT_MAX_SIZE
 *
 * \param alg           A PAKE algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_PAKE(\p alg) is true).
 * \param primitive     A primitive of type ::psa_pake_primitive_t that is
 *                      compatible with algorithm \p alg.
 * \param input_step    A value of type ::psa_pake_step_t that is valid for the
 *                      algorithm \p alg.
 * \return              A sufficient input buffer size for the specified
 *                      input, cipher suite and algorithm. If the cipher suite,
 *                      the input type or PAKE algorithm is not recognized, or
 *                      the parameters are incompatible, return 0.
 */
#define PSA_PAKE_INPUT_SIZE(alg, primitive, input_step)                 \
    (input_step == PSA_PAKE_STEP_KEY_SHARE ? \
        PSA_PAKE_PRIMITIVE_GET_TYPE(primitive) == PSA_PAKE_PRIMITIVE_TYPE_DH ? \
            PSA_BITS_TO_BYTES(PSA_PAKE_PRIMITIVE_GET_BITS(primitive)) : \
            PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_PAKE_PRIMITIVE_GET_BITS(primitive)) : \
     input_step == PSA_PAKE_STEP_ZK_PUBLIC ? \
        PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_PAKE_PRIMITIVE_GET_BITS(primitive)) : \
     input_step == PSA_PAKE_STEP_ZK_PROOF ? \
        PSA_BITS_TO_BYTES(PSA_PAKE_PRIMITIVE_GET_BITS(primitive)) : \
     input_step == PSA_PAKE_STEP_COMMIT ? \
        PSA_BITS_TO_BYTES(PSA_PAKE_PRIMITIVE_GET_BITS(primitive)) * 3 + 2 : \
     input_step == PSA_PAKE_STEP_CONFIRM ? \
        PSA_ALG_IS_SPAKE2P_CMAC(alg) ? \
            PSA_MAC_LENGTH(PSA_KEY_TYPE_AES, 128, PSA_ALG_CMAC) : \
            PSA_HASH_LENGTH(alg) + (PSA_ALG_IS_WPA3_SAE(alg) ? 2 : 0) : \
     input_step == PSA_PAKE_STEP_SALT ? \
        64u : \
     input_step == PSA_PAKE_STEP_SEND_CONFIRM ? \
        2u : \
     0u)

/** Output buffer size for psa_pake_output() for any of the supported PAKE
 * algorithm and primitive suites and output step.
 *
 * This macro must expand to a compile-time constant integer.
 *
 * The value of this macro must be at least as large as the largest value
 * returned by PSA_PAKE_OUTPUT_SIZE()
 *
 * See also #PSA_PAKE_OUTPUT_SIZE(\p alg, \p primitive, \p output_step).
 */
#ifdef PSA_WANT_ALG_SRP_6
#define PSA_PAKE_OUTPUT_MAX_SIZE PSA_BITS_TO_BYTES(PSA_VENDOR_FFDH_MAX_KEY_BITS)
#else
#ifdef PSA_WANT_ALG_WPA3_SAE
#define PSA_PAKE_OUTPUT_MAX_SIZE (PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS) * 3 + 2)
#else
#define PSA_PAKE_OUTPUT_MAX_SIZE PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)
#endif
#endif

/** Input buffer size for psa_pake_input() for any of the supported PAKE
 * algorithm and primitive suites and input step.
 *
 * This macro must expand to a compile-time constant integer.
 *
 * The value of this macro must be at least as large as the largest value
 * returned by PSA_PAKE_INPUT_SIZE()
 *
 * See also #PSA_PAKE_INPUT_SIZE(\p alg, \p primitive, \p output_step).
 */
#ifdef PSA_WANT_ALG_SRP_6
#define PSA_PAKE_INPUT_MAX_SIZE PSA_BITS_TO_BYTES(PSA_VENDOR_FFDH_MAX_KEY_BITS)
#else
#ifdef PSA_WANT_ALG_WPA3_SAE
#define PSA_PAKE_INPUT_MAX_SIZE (PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS) * 3 + 2)
#else
#define PSA_PAKE_INPUT_MAX_SIZE PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)
#endif
#endif
