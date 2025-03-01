#include <pqpake/cake.h>
#include <pqpake/omega_transform.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "benchmark.h"

void prepare_acake(char *password, omtransform_crs **crs, omtransform_client **client, omtransform_server **server)
{

  *crs = malloc(sizeof(omtransform_crs));
  *client = malloc(sizeof(omtransform_client));
  *server = malloc(sizeof(omtransform_server));
  omtransform_init(password, *crs, *client, *server);
}

int run_acake(omtransform_crs *crs, omtransform_client *client, omtransform_server *server,
              uint32_t ssid,
              char *password,
              char *alice_name,
              char *bob_name)
{
  int pwsize = strlen(password);
  derive_key((uint8_t *)password, pwsize, crs->salt0, client->pwfile);
  cake_agent *alice =
      cake_create_alice(ssid, client->pwfile, KEY_LENGTH,
                        (uint8_t *)alice_name, strlen(alice_name));
  cake_agent *bob = cake_create_bob(ssid, server->pwfile, KEY_LENGTH,
                                    (uint8_t *)bob_name, strlen(bob_name));

  uint8_t *alice_message;
  size_t alice_message_size;
  cake_create_message_step1(alice, &alice_message, &alice_message_size);

  if (alice_message_size == 0)
  {
    return -1;
  }

  upadte_transcript(crs, alice_message, alice_message_size);

  uint8_t *bob_message;
  size_t bob_message_size;
  cake_create_message_step2(bob, alice_message, &bob_message,
                            &bob_message_size);

  if (bob_message_size == 0)
  {
    return -2;
  }

  upadte_transcript(crs, bob_message, bob_message_size);

  cake_create_message_step3(alice, bob_message);

  const uint8_t *alice_ss = cake_get_shared_secret(alice);
  const uint8_t *bob_ss = cake_get_shared_secret(bob);

  for (int i = 0; i < PQPAKE_SHARED_SECRET_SIZE; i++)
  {
    if (alice_ss[i] != bob_ss[i])
    {
      return -3 - i;
    }
  }

  // construct aPake from Pake by omega-transform
  omtransform_message_setp1(crs, server, bob_ss);
  omtransform_message_setp2(crs, client, alice_ss);

  if (omtransform_message_setp3(crs, server))
  {
    for (int i = 0; i < KEY_LENGTH; i++)
    {
      if (client->sharedkey[i] != server->sharedkey[i])
      {
        printf("alice_sharedkey[%d] != bob_sharedkey[%d]\n", i, i);
        return -4 - i;
      }
    }
  }

  cake_free_agent(alice);
  cake_free_agent(bob);
  omtransform_free_crs(crs);
  free(client);
  free(server);

  return 0;
}

void benchmark_acake(int n)
{
  benchmark_result *result_pre = malloc(sizeof(benchmark_result));
  result_pre->mean = 0;
  result_pre->median = 0;
  result_pre->min = 0;
  result_pre->max = 0;
  result_pre->std_dev = 0;
  result_pre->fail_count = 0;

  benchmark_result *result_run = malloc(sizeof(benchmark_result));
  result_run->mean = 0;
  result_run->median = 0;
  result_run->min = 0;
  result_run->max = 0;
  result_run->std_dev = 0;
  result_run->fail_count = 0;

  char password[] = "password1234";
  char alice_name[] = "finch";
  char bob_name[] = "reese";

  double *pretimes = malloc(sizeof(double) * n);
  double *runtimes = malloc(sizeof(double) * n);

  for (int i = 0; i < n; i++)
  {
    omtransform_crs *crs;
    omtransform_client *client;
    omtransform_server *server;
    clock_t start = clock();
    prepare_acake(password, &crs, &client, &server);
    clock_t end = clock();
    pretimes[i] = (double)(end - start);// / CLOCKS_PER_SEC * 1000;
    uint32_t ssid = rand();

    start = clock();
    int ret = run_acake(crs, client, server, ssid, password, alice_name, bob_name);
    end = clock();
    if (ret < 0)
    {
      runtimes[i] = -1;
      fprintf(stderr, "run_acake failed with %d\n", ret);
      continue;
    }

    runtimes[i] = (double)(end - start);// / CLOCKS_PER_SEC * 1000;
  }

  compute_statistics(pretimes, n, result_pre);
  compute_statistics(runtimes, n, result_run);

  free(pretimes);
  free(runtimes);

  printf("Benchmark results for Registration: (n=%d):\n", n);
  printf("\tmean: %f cpu cycles\n", result_pre->mean);
  printf("\tmedian: %f cpu cycles\n", result_pre->median);
  printf("\tmin: %f cpu cycles\n", result_pre->min);
  printf("\tmax: %f cpu cycles\n", result_pre->max);
  printf("\tstd dev: %f cpu cycles\n", result_pre->std_dev);
  printf("\tfail count: %d\n", result_pre->fail_count);

  printf("Benchmark results for aCAKE: (n=%d):\n", n);
  printf("\tmean: %f cpu cycles\n", result_run->mean);
  printf("\tmedian: %f cpu cycles\n", result_run->median);
  printf("\tmin: %f cpu cycles\n", result_run->min);
  printf("\tmax: %f cpu cycles\n", result_run->max);
  printf("\tstd dev: %f cpu cycles\n", result_run->std_dev);
  printf("\tfail count: %d\n", result_run->fail_count);
}

int main(int argc, char **argv)
{
  srand(time(NULL));

  if (argc != 2)
  {
    fprintf(stderr, "usage: %s n\n", argv[0]);
    return 1;
  }

  int n = atoi(argv[1]);

  if (n == 0)
  {
    fprintf(stderr, "invalid argument n\n");
    return 1;
  }

  benchmark_acake(n);

  return 0;
}
