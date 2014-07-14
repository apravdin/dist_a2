#include <iostream>
#include <string>
#include "tcpconnector.h"
#include "tcpstream.h"
#include <stdlib.h>
#include <unistd.h>
#include <rpc_errno.h>
#include <rpc.h>

int get_arg_num(int *argTypes) {
    int i = 0;
    while(argTypes[i] != 0) {
        i++;
    }
    return i;
}

// Client functions
int rpcCall(char *name, int *argTypes, void **args) {
    // Initialize tcp connector
    TCPConnector *c = new TCPConnector();
    TCPStream *stream;
    char *server_name = "127.0.0.1"; // getenv("BINDER_ADDRESS");
    char *port = "53737"; // getenv("BINDER_PORT");
#ifdef DEBUG
    std::cout << "Connection to: " << server_name << ":" << port << std::endl;
#endif
    if (server_name == NULL || port == NULL) {
        std::cerr << "Failed to find BINDER_ADDRESS or BINDER_PORT" << std::endl;
        return 0;
    }

    stream = c->connect(atoi(port), server_name);
    if (stream == NULL) {
        std::cerr << "Failed to connect" << std::endl;
        return 0;
    }



    // Send function lookup to binder
    int name_len = strlen(name);
    int arg_len = get_arg_num(argTypes);
    int msg_len = name_len + arg_len;

    stream->send(&msg_len);
    stream->send(name, name_len);
    stream->send(argTypes, arg_len);


    // Get binder lookup response
    char buf[BUFFER_SIZE];
    int bytes_read = 0;
    int len;
    std::string msg = "";
    read(stream->get_sd(), &msg_len, sizeof(msg_len));
    while (bytes_read < msg_len) {
        len = stream->receive(buf, BUFFER_SIZE-1);
        if (len <= 0) {
            return -1;
        }

        buf[len] = 0;
        bytes_read += len;
        msg.append(buf, len);
    }

    std::cout << "Server: " << msg << std::endl;

    // Send execute request to server

    // Get server response

    delete c;
    return 0;
    return RETVAL_SUCCESS;
}

int rpcCacheCall(char* name, int* argTypes, void** args) {
    return RETVAL_SUCCESS;
}

int rpcTerminate() {
    return RETVAL_SUCCESS;
}


// Server functions
int rpcInit() {
    return RETVAL_SUCCESS;
}

int rpcRegister(char* name, int* argTypes, skeleton f) {
    return RETVAL_SUCCESS;
}

int rpcExecute() {
    return RETVAL_SUCCESS;
}

