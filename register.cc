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
#include <rpc_errno.h>

#include "rpc.h"
#include "server_function_skels.h"

#define CHAR_ARRAY_LENGTH 100

int main() {

    int argTypes[3];
    argTypes[0] = (int) 'a';
    argTypes[1] = (int) 'b';
    argTypes[2] = 0;

    // void *args[1];
    // args[0] = (void *)1;


    int retval = rpcInit();
    std::cout << "Init:" << retval << std::endl;
    retval = rpcRegister("f0", argTypes, *f0_Skel);
    retval = rpcRegister("f0", argTypes, *f0_Skel);

    if (retval != RETVAL_SUCCESS) {
        std::cout << "Failed to register:" << retval << std::endl;
    } else {
        std::cout << "Registered" << std::endl;
    }

    // retval = rpcRegister("f0", argTypes, *f0_Skel);
/* end of client.c */
    return 0;
}




