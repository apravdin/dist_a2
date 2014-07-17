#include <iostream>
#include <string>
#include "tcpconnector.h"
#include "tcpstream.h"
#include <stdlib.h>
#include <unistd.h>
#include <rpc_errno.h>
#include <rpc.h>
#include <cassert>

static TCPStream *server_connection = NULL;


unsigned int get_arg_num(int *argTypes) {
    unsigned int i = 0;
    while(argTypes[i] != 0) {
        i++;
    }
    return i;
}

int get_msg_data(int sd, void *result, int data_len) {
    char buffer[BUFFER_SIZE];
    int len;
    int bytes_read = 0;

    while (bytes_read < data_len) {
        // Read from the socket
        len = read(sd, buffer, data_len);
        if (len <= 0) {
            return ERRNO_FAILED_READ;
        }

        // Copy the read data into the result buffer
        memcpy(((char *) result) + bytes_read, buffer, len);

        // Increment the bytes read
        bytes_read += len;
    }
    return bytes_read;
}

void gen_sig(int *argTypes) {
    int total_args = get_arg_num(argTypes);
    for (int i = 0; i < total_args; i++) {
        argTypes[i] &= ARG_TYPE_MASK;
    }
}

int get_hash(std::string &hash, char *name, int *argTypes) {
    hash.clear();

    int arg_len = get_arg_num(argTypes);
    gen_sig(argTypes);

    hash.append(name);
    hash.append((char *) argTypes, arg_len * sizeof(int));

    return RETVAL_SUCCESS;
}

void rpcReset() {
    close(server_connection->get_sd());
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
    read(stream->get_sd(), &msg, sizeof(msg));
    return msg;
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

int send_hash(TCPStream *stream, int type, std::string &hash) {

    int hash_len = hash.length();
    std::cout << "Sending:" << hash_len << ":" << hash << std::endl;
    if (stream->send(&hash_len) != sizeof(int)) {
        return ERRNO_FAILED_SEND;
    }
    if (stream->send(&type) != sizeof(int)) {
        return ERRNO_FAILED_SEND;
    }

    if (stream->send(hash.c_str(), hash_len) != hash_len) {
        return ERRNO_FAILED_SEND;
    }

    return RETVAL_SUCCESS;
}

int send_data(TCPStream *stream, int type, bool sig_only, char *name, int *argTypes, void **args) {
    char sys_name[NAME_SIZE];
    copy_name(sys_name, name);

    // Send function lookup to binder
    unsigned int arg_len = get_arg_num(argTypes);

    if (!sig_only) {
        // TODO calc param len
    }

    int msg_len = NAME_SIZE + arg_len * sizeof(int);

    std::cout << "msg_len:" << msg_len << std::endl;
    if (stream->send(&msg_len) != sizeof(msg_len)) {
        return ERRNO_FAILED_SEND;
    }
    std::cout << "type:" << type << std::endl;
    if (stream->send(&type) != sizeof(type)) {
        return ERRNO_FAILED_SEND;
    }
    std::cout << "name:" << NAME_SIZE << std::endl;
    if (stream->send(sys_name, NAME_SIZE) != NAME_SIZE) {
        return ERRNO_FAILED_SEND;
    }
    std::cout << "args:" << arg_len  << std::endl;
    if (stream->send(argTypes, arg_len) != arg_len * sizeof(int)) {
        return ERRNO_FAILED_SEND;
    }

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

    // Generate the function hash
    std::string hash;
    get_hash(hash, name, argTypes);

    // Send lookup request
    retval = send_hash(stream, LOOKUP, hash);


    // Get binder lookup response
    std::string msg;
    int msg_len = get_int(stream);
    int type = get_int(stream);

    // If return value is an error code
    if (type != RETVAL_SUCCESS) {
        std::cout << "Server: Lookup failed:" << msg_len << " " << type << std::endl;
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

    retval = get_int(stream);
    if (retval != 0) {
        return ERRNO_INIT_FAILED;
    }
    retval = get_int(stream);
    if (retval != RETVAL_SUCCESS) {
        return ERRNO_INIT_FAILED;
    }

    return RETVAL_SUCCESS;
}

int rpcRegister(char* name, int* argTypes, skeleton f) {
    if (server_connection == NULL) {
        return ERRNO_FAILED_TO_CONNECT;
    }

    // Generate the function hash
    std::string hash;
    get_hash(hash, name, argTypes);

    // Send the register request
    int retval = send_hash(server_connection, REGISTER, hash);
    if (retval != RETVAL_SUCCESS) {
        return retval;
    }

    retval = get_int(server_connection);
    if (retval != 0) {
        return ERRNO_REGISTER_FAILED;
    }
    retval = get_int(server_connection);
    if (retval != RETVAL_SUCCESS) {
        return ERRNO_REGISTER_FAILED;
    }

    return retval;
}

int rpcExecute() {
    return RETVAL_SUCCESS;
}

