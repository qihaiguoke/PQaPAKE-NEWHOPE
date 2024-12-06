#include <pqpake/cake.h>
#include <stdio.h>
#include <stdlib.h>
#include <pqpake/omega_transform.h>
#include <pqpake/crypto_tools.h>

void print_buffer(const uint8_t *buffer, int size)
{
  for (int i = 0; i < size; i++)
  {
    printf("%02x", buffer[i]);
  }
  printf("\n");
}

void acake_test()
{
  char password[] = "password1234";

  // initial omega-transform
  omtransform_crs *crs = malloc(sizeof(omtransform_crs));
  omtransform_client *client = malloc(sizeof(omtransform_client));
  omtransform_server *server = malloc(sizeof(omtransform_server));
  omtransform_init(password, crs, client, server);

  // cake begin
  uint32_t ssid = 424242;

  char alice_name[] = "alice";
  cake_agent *alice =
      cake_create_alice(ssid, client->pwfile, KEY_LENGTH,
                        (uint8_t *)alice_name, strlen(alice_name));
  char bob_name[] = "bob";
  cake_agent *bob = cake_create_bob(ssid, server->pwfile, KEY_LENGTH,
                                    (uint8_t *)bob_name, strlen(bob_name));

  uint8_t *alice_message;
  size_t alice_message_size;
  cake_create_message_step1(alice, &alice_message, &alice_message_size);

  if (alice_message_size == 0)
  {
    printf("alice_message_size == 0\n");
    exit(1);
  }

  upadte_transcript(crs, alice_message, alice_message_size);

  uint8_t *bob_message;
  size_t bob_message_size;
  cake_create_message_step2(bob, alice_message, &bob_message,
                            &bob_message_size);

  if (bob_message_size == 0)
  {
    printf("bob_message_size == 0\n");
    exit(1);
  }

  upadte_transcript(crs, bob_message, bob_message_size);

  cake_create_message_step3(alice, bob_message);

  // printf("alice pk: ");
  // print_buffer(alice->pk, CRYPTO_CIPHERTEXTBYTES);
  // printf("  bob pk: ");
  // print_buffer(bob->pk, CRYPTO_CIPHERTEXTBYTES);

  const uint8_t *alice_ss = cake_get_shared_secret(alice);
  const uint8_t *bob_ss = cake_get_shared_secret(bob);

  printf("Alice: ");
  print_buffer(alice_ss, PQPAKE_SHARED_SECRET_SIZE);

  printf("  Bob: ");
  print_buffer(bob_ss, PQPAKE_SHARED_SECRET_SIZE);

  for (int i = 0; i < PQPAKE_SHARED_SECRET_SIZE; i++)
  {
    if (alice_ss[i] != bob_ss[i])
    {
      printf("alice_ss[%d] != bob_ss[%d]", i, i);
      exit(1);
    }
  }

  printf("Cake_test passed\n");

  // construct aPake from Pake by omega-transform
  omtransform_message_setp1(crs, server, bob_ss);
  omtransform_message_setp2(crs, client, alice_ss);

  if (omtransform_message_setp3(crs, server))
  {
    printf("Alice: ");
    print_buffer(client->sharedkey, KEY_LENGTH);

    printf("  Bob: ");
    print_buffer(server->sharedkey, KEY_LENGTH);

    int success = 1;
    for (int i = 0; i < KEY_LENGTH; i++)
    {
      if (client->sharedkey[i] != server->sharedkey[i])
      {
        printf("alice_sharedkey[%d] != bob_sharedkey[%d]\n", i, i);
        success = 0;
      }
    }
    if (success)
      printf("aCake_test passed!\n");
  }
  printf("salts of kdf:\n");
  print_buffer((const uint8_t *)crs->salt0,SALT_LENGTH);
  print_buffer((const uint8_t *)crs->salt1,SALT_LENGTH);
  print_buffer((const uint8_t *)crs->salt2,SALT_LENGTH);
  print_buffer((const uint8_t *)crs->salt3,SALT_LENGTH);


  for(int i=0;i<3;++i){
    printf("ciphertext of round:%d\n",i+1);
    print_buffer(crs->tr.message[i],crs->tr.bytes[i]);
  }

  printf("mac of transcript:\n");
  print_buffer(crs->tr_hmac,HMAC_LENGTH);

  cake_free_agent(alice);
  cake_free_agent(bob);
  omtransform_free_crs(crs);
  free(client);
  free(server);
}

int main(void)
{
  acake_test();

  return 0;
}
