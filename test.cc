/*
 * client.c
 *
 * This file is the client program,
 * which prepares the arguments, calls "rpcCall", and checks the returns.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rpc.h"

#define CHAR_ARRAY_LENGTH 100

int main() {

  int argTypes[3];
  argTypes[0] = 51;
  argTypes[1] = 52;
  argTypes[2] = 0;

  void *args[1];
  args[0] = (void *)1;

  /* rpcCalls */
  int retval = rpcCall("f0", argTypes, args);
  /* test the return f0 */
  printf("\nEXPECTED return of f0 is: %d\n", -1);
  if (retval >= 0) {
    printf("ACTUAL return of f0 is: %d\n", args[0]);
  }
  else {
    printf("Error: %d\n", retval);
  }
  /* end of client.c */
  return 0;
}




