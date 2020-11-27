#include "hblk_crypto.h"

/**
 * ec_verify - verifies the signature of a given set of bytes using a given
 *             EC_KEY public key
 *
 * @key: points to EC_KEY structure containing public key
 * @msg: points to characters to verify the signature
 * @msglen: number of characters to check
 * @sig: points to signature to be checked
 *
 * Return: 1 if signature is valid, otherwise 0
 */
int ec_verify(EC_KEY const *key, uint8_t const *msg, size_t msglen,
	sig_t const *sig)
{
	uint8_t digest[SHA256_DIGEST_LENGTH];

	if (key == NULL || msg == NULL || sig == NULL)
		return (0);

	if (!EC_KEY_check_key(key))
		return (0);

	if (!SHA256(msg, msglen, digest))
		return (0);

	if (ECDSA_verify(0, digest, SHA256_DIGEST_LENGTH, sig->sig,
		sig->len, (EC_KEY *)key) != 1)
		return (0);

	return (1);
}
