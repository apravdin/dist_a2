/*
* client.c
*
* This file is the client program,
* which prepares the arguments, calls "rpcCall", and checks the returns.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

#include "rpc.h"
#include "server_function_skels.h"

#define CHAR_ARRAY_LENGTH 100

int main() {

    int argTypes[3];
    argTypes[0] = (int) 'a';
    argTypes[1] = (int) 'b';
    argTypes[2] = 0;

    void *args[1];
    args[0] = (void *)1;

    int retval = rpcCall("f0", argTypes, args);
    printf("\nEXPECTED return of f0 is: %d\n", -1);
    if (retval >= 0) {
        printf("ACTUAL return of f0 is: %d\n", *((int *)args));
    }else {
        printf("Error: %d\n", retval);
    }
/* end of client.c */
    return 0;
}




