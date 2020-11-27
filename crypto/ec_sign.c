#include "hblk_crypto.h"

/**
 * ec_sign - signs a given set of bytes using a
 *           given EC_KEY private key
 *
 * @key: EC_KEY structure containing private key to be used
 * @msg: characters to be signed
 * @msglen: number of characters to be signed
 * @sig: address at which to store the signature
 * Return: pointer to signature buffer on success, NULL on failure
 */
uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg, size_t msglen,
				 sig_t *sig)
{
	unsigned char md[SHA256_DIGEST_LENGTH];

	if (key == NULL || msg == NULL || sig == NULL)
		return (NULL);
	if (!EC_KEY_check_key(key))
		return (NULL);
	if (!SHA256(msg, msglen, md))
		return (NULL);
	sig->len = ECDSA_size(key);
	if (!sig->len)
		return (NULL);
	if (!ECDSA_sign(EC_CURVE, md, SHA256_DIGEST_LENGTH, sig->sig,
					(unsigned int *)&(sig->len), (EC_KEY *)key))
		return (NULL);
	return (sig->sig);
}
