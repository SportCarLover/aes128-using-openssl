#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

unsigned char keyval[16];

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx) {
  int i, nrounds = 5;
  unsigned char iv[16];

  i = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), NULL, key_data, key_data_len, nrounds, keyval, iv);  if (i != 16) {
    printf("Key size is %d bits - should be 128 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_128_cbc(), NULL, keyval, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_128_cbc(), NULL, keyval, iv);

  return 0;
}

unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len, unsigned char *key) {
  int c_len = *len + AES_BLOCK_SIZE;
  int f_len = 0;
  unsigned char *ciphertext = malloc(c_len);

  EVP_EncryptInit_ex(e, EVP_aes_128_cbc(), NULL, key, NULL);
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len, unsigned char *key) {
  int p_len = *len;
  int f_len = 0;
  unsigned char *plaintext = malloc(p_len);

  EVP_DecryptInit_ex(e, EVP_aes_128_cbc(), NULL, key, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

int main(int argc, char **argv) {
  EVP_CIPHER_CTX *en, *de;
  unsigned char *key_data;
  int key_data_len;
  if (argc < 5) {
        printf("Usage: cryptoAES input-file key d/e output-file\n");
        return -1;
  }

  FILE *inp_file = fopen(argv[1], "rb");
  FILE *out_file = fopen(argv[4], "wb");

  fseek(inp_file, 0, SEEK_END);
  int file_len = ftell(inp_file);
  fseek(inp_file, 0, SEEK_SET);

  char *input = malloc(file_len);
  size_t result = fread(input, 1, file_len, inp_file);

  en = EVP_CIPHER_CTX_new();
  de = EVP_CIPHER_CTX_new();
  key_data = malloc(16);
  memcpy(key_data, argv[2], strlen(argv[2]));
  key_data_len = 16;

  if (aes_init(key_data, key_data_len, NULL, en, de)) {
    printf("Couldn't initialize AES cipher\n");
    return -1;
  }

  if (argv[3][0] == 'e') {
    unsigned char *ciphertext = aes_encrypt(en, (unsigned char *) input, &file_len, keyval);
    fwrite(ciphertext, 1, file_len, out_file);
    free(ciphertext);
  } else {
    char *plaintext = (char *) aes_decrypt(de, (unsigned char *) input, &file_len, keyval);
    fwrite(plaintext, 1, file_len, out_file);
    free(plaintext);
  }

  free(input);

  EVP_CIPHER_CTX_free(en);
  EVP_CIPHER_CTX_free(de);

  return 0;
}
