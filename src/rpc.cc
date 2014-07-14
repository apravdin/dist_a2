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
    return i * sizeof(int);
}

int connect_to_binder(TCPConnector *c, TCPStream **stream) {
    char *server_name = "127.0.0.1"; // getenv("BINDER_ADDRESS");
    char *port = "61111"; // getenv("BINDER_PORT");
    if (server_name == NULL || port == NULL) {
        std::cerr << "Failed to find BINDER_ADDRESS or BINDER_PORT" << std::endl;
        return ERRNO_ENV_VAR_NOT_SET;
    }

    *stream = c->connect(atoi(port), server_name);
    if (stream == NULL) {
        std::cerr << "Failed to connect" << std::endl;
        return ERRNO_FAILED_TO_CONNECT;
    }

    return RETVAL_SUCCESS;
}

// Client functions
int rpcCall(char *name, int *argTypes, void **args) {
    // Initialize tcp connector
    TCPConnector *c = new TCPConnector();
    TCPStream *stream;

    int retval = connect_to_binder(c, &stream);

    if (retval != RETVAL_SUCCESS) {
        return retval;
    }

    char sys_name[NAME_SIZE];
    int name_len = strlen(name);
    memcpy(sys_name, name, std::min(name_len + 1, NAME_SIZE));

    // Send function lookup to binder
    int arg_len = get_arg_num(argTypes);
    int msg_len = NAME_SIZE + arg_len;

    int type = LOOKUP;

    retval = stream->send(&msg_len);
    std::cout << "RET:" << retval << std::endl;
    retval = stream->send(&type);
    std::cout << "RET:" << retval << std::endl;
    retval = stream->send(sys_name, NAME_SIZE);
    std::cout << "RET:" << retval << std::endl;
    retval = stream->send(argTypes, arg_len);
    std::cout << "RET:" << retval << ":" << arg_len << std::endl;


    // Get binder lookup response
    char buf[BUFFER_SIZE];
    int bytes_read = 0;
    int len;
    std::string msg = "";
    read(stream->get_sd(), &msg_len, sizeof(msg_len));
    while (bytes_read < msg_len) {
        len = stream->receive(buf, BUFFER_SIZE-1);
        if (len <= 0) {
            return ERRNO_FAILED_READ;
        }

        buf[len] = 0;
        bytes_read += len;
        msg.append(buf, len);
    }

    std::cout << "Server: " << msg << std::endl;

    // Send execute request to server

    // Get server response

    delete c;
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

