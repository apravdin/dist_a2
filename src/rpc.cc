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

void copy_name(char *sys_name, char *name) {
    memset(sys_name, 0, NAME_SIZE);
    int name_len = strlen(name);
    memcpy(sys_name, name, std::min(name_len + 1, NAME_SIZE));
}

int get_int(TCPStream *stream) {
    int msg;
    return read(stream->get_sd(), &msg, sizeof(msg));
}

int get_str(TCPStream *stream, std::string &msg, int msg_len) {
    char buf[BUFFER_SIZE];
    int bytes_read = 0;
    int len;

    msg.clear();
    while (bytes_read < msg_len) {
        len = stream->receive(buf, BUFFER_SIZE-1);
        if (len <= 0) {
            return ERRNO_FAILED_READ;
        }

        buf[len] = 0;
        bytes_read += len;
        msg.append(buf, len);
    }

    return bytes_read;
}

int send_int(TCPStream *stream, int data) {
    return stream->send(&data);
}

int send_data(TCPStream *stream, int type, bool sig_only, char *name, int *argTypes, void **args) {
    char sys_name[NAME_SIZE];
    copy_name(sys_name, name);

    // Send function lookup to binder
    int arg_len = get_arg_num(argTypes);

    if (!sig_only) {
        // TODO calc param len
    }

    int msg_len = NAME_SIZE + arg_len;

    if (stream->send(&msg_len) != sizeof(msg_len)) {
        return ERRNO_FAILED_SEND;
    }
    // std::cout << "RET:" << 4 << std::endl;
    if (stream->send(&type) != sizeof(type)) {
        return ERRNO_FAILED_SEND;
    }
    // std::cout << "RET:" << 4 << std::endl;
    if (stream->send(sys_name, NAME_SIZE) != NAME_SIZE) {
        return ERRNO_FAILED_SEND;
    }
    // std::cout << "RET:" << NAME_SIZE << std::endl;
    if (stream->send(argTypes, arg_len) != arg_len * sizeof(int)) {
        return ERRNO_FAILED_SEND;
    }
    // std::cout << "RET:" << arg_len * sizeof(int) << std::endl;

    if (!sig_only) {
        // TODO send params
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

    // Send lookup request
    retval = send_data(stream, LOOKUP, true, name, argTypes, NULL);
    if (retval != RETVAL_SUCCESS) {
        return retval;
    }

    // Get binder lookup response
    std::string msg;
    int msg_len = get_int(stream);
    int type = get_int(stream);

    // If return value is an error code
    if (type != RETVAL_SUCCESS) {
        std::cout << "Server: Lookup failed" << std::endl;
        return ERRNO_FUNC_NOT_FOUND;
    } else {
        get_str(stream, msg, msg_len);
        std::cout << "Server: " << msg << std::endl;
    }

    // Send execute request to server

    // Get server response

    delete c;
    return RETVAL_SUCCESS;
}

int rpcCacheCall(char* name, int* argTypes, void** args) {
    return RETVAL_SUCCESS;
}

int rpcTerminate() {
    // Initialize tcp connector
    TCPConnector *c = new TCPConnector();
    TCPStream *stream;

    int retval = connect_to_binder(c, &stream);

    if (retval != RETVAL_SUCCESS) {
        return retval;
    }

    send_int(stream, 0);
    send_int(stream, TERMINATE);

    return RETVAL_SUCCESS;
}


static TCPStream *server_connection = NULL;
// Server functions
int rpcInit() {
    TCPConnector *c = new TCPConnector();
    TCPStream *stream;

    int retval = connect_to_binder(c, &stream);

    if (retval != RETVAL_SUCCESS) {
        return ERRNO_FAILED_TO_CONNECT;
    }

    server_connection = stream;

    send_int(stream, 0);
    send_int(stream, INIT);

    return RETVAL_SUCCESS;
}

int rpcRegister(char* name, int* argTypes, skeleton f) {
    if (server_connection == NULL) {
        return ERRNO_FAILED_TO_CONNECT;
    }

    return send_data(server_connection, REGISTER, true, name, argTypes, NULL);
}

int rpcExecute() {
    return RETVAL_SUCCESS;
}

