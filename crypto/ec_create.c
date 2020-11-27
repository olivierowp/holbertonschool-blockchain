#include "hblk_crypto.h"

/**
 * ec_create - creates a new EC key pair
 *
 * Description: uses secp256k1 elliptic curve to create new pair
 * Return: pointer to EC_KEY struct with public and private keys, or NULL
 */
EC_KEY *ec_create(void)
{
	EC_KEY *key;

	key = EC_KEY_new_by_curve_name(EC_CURVE);
	if (key == NULL)
		return (NULL);

	if (!EC_KEY_generate_key(key))
	{
		EC_KEY_free(key);
		return (NULL);
	}
	return (key);
}
