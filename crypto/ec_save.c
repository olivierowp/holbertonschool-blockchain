#include "hblk_crypto.h"

/**
 * ec_save - saves an existing EC key pair on the disk
 *
 * @key: points to EC key pair to be saved on disk
 * @folder: path to the folder in which to save the keys
 *
 * Return: 1 on success, 0 on failure
 */
int ec_save(EC_KEY *key, char const *folder)
{
	char buffer[BUFSIZ];
	FILE *fp;

	if (key == NULL || folder == NULL)
		return (0);

	mkdir(folder, 0700);
	sprintf(buffer, "%s/%s", folder, PRI_FILENAME);
	fp = fopen(buffer, "w");
	if (fp == NULL)
		return (0);

	/* Write Private key to PEM */
	if (!PEM_write_ECPrivateKey(fp, key, NULL, NULL, 0, NULL, NULL))
	{
		fclose(fp);
		return (0);
	}
	fclose(fp);

	sprintf(buffer, "%s/%s", folder, PUB_FILENAME);
	fp = fopen(buffer, "w");
	if (fp == NULL)
		return (0);

	/* Write Public key to PEM */
	if (!PEM_write_EC_PUBKEY(fp, key))
	{
		fclose(fp);
		return (0);
	}
	fclose(fp);
	return (1);
}
