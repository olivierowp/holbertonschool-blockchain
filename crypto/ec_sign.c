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
	unsigned int len;

	if (!key || !msg || !sig)
		return (NULL);
	len = sig->len;
	if (ECDSA_sign(0, msg, msglen, sig->sig, &len,
				   (EC_KEY *)key) != 1)
		return (NULL);
	sig->len = len;
	return (sig->sig);
}
