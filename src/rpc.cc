#include <iostream>
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include <map>
#include <unistd.h>
#include <csignal>
#include <rpc.h>
#include "my_rpc.h"
#include "rpc_errno.h"
#include "tcpconnector.h"
#include "tcpstream.h"
#include "tcpacceptor.h"

static TCPStream *server_connection = NULL;
static std::map<std::string, skeleton> server_functions;
static TCPAcceptor *server_acceptor = NULL;


void send_msg_header(int sd, int len, int type) {
    write(sd, &len, sizeof(int));
    write(sd, &type, sizeof(int));
}

unsigned int get_arg_num(int *argTypes) {
    unsigned int i = 0;
    while(argTypes[i] != 0) {
        i++;
    }
    return i;
}

bool is_not_output(int argType) {
    return (argType & (1 << ARG_OUTPUT)) == 0;
}

bool is_array(int argType) {
    return (argType & ARG_ARRAY_LEN_MASK) > 0;
}

unsigned int get_type_size(int argType) {
    int type = (argType & ARG_TYPE_MASK) >> 16;
    int num = is_array(argType) ? (argType & ARG_ARRAY_LEN_MASK) : 1;
    switch(type) {
            case ARG_CHAR:
                return sizeof(char) * num;
            case ARG_SHORT:
                return sizeof(short) * num;
            case ARG_INT:
                return sizeof(int) * num;
            case ARG_LONG:
                return sizeof(long) * num;
            case ARG_FLOAT:
                return sizeof(float) * num;
            case ARG_DOUBLE:
                return sizeof(double) * num;
            default:
                return 0;
        }
}

unsigned int get_arg_len(int *argTypes) {
    unsigned int total = 0;

    for (unsigned int i = 0; i < get_arg_num(argTypes); i++) {
        total += get_type_size(argTypes[i]);
    }

    return total;
}

void map_list(char *data, int *argTypes, void **result) {
    unsigned int offset = 0;
    for(unsigned int i = 0; i < get_arg_num(argTypes); i++) {
        result[i] = &(data[offset]);
        offset += get_type_size(argTypes[i]);
    }
}

void copy_results(char *data, int *argTypes, void **args) {
    unsigned int offset = 0;
    unsigned int size = 0;
    for(unsigned int i = 0; i < get_arg_num(argTypes); i++) {
        size = get_type_size(argTypes[i]);
        if (is_not_output(argTypes[i])) {
            offset += size;
            continue;
        }
        memcpy(args[i], &(data[offset]), size);
        offset += size;
    }
}

void parse_args(int *argTypes, void **args, char *result) {
    unsigned int size = 0;
    unsigned int offset = 0;

    for (unsigned int i = 0; i < get_arg_num(argTypes); i++) {
        size = get_type_size(argTypes[i]);
        if (size == 0) {
            continue;
        }

        memcpy(&(result[offset]), args[i], size);
        offset += size;
    }
}

int get_msg_data(int sd, void *result, int data_len) {
    return read(sd, result, data_len);
}

void gen_sig(int *argTypes) {
    int total_args = get_arg_num(argTypes);
    for (int i = 0; i < total_args; i++) {
        argTypes[i] &= ARG_HASH_MASK;
    }
}

int get_hash(std::string &hash, char *name, int *argTypes) {
    hash.clear();

    int arg_len = get_arg_num(argTypes);
    int *temp_args = new int[arg_len + 1];
    memcpy(temp_args, argTypes, (arg_len + 1) * sizeof(int));

    gen_sig(temp_args);

    hash.append(name);
    hash.append((char *) temp_args, arg_len * sizeof(int));

    delete[] temp_args;
    return RETVAL_SUCCESS;
}

void rpcReset() {
    close(server_connection->get_sd());
}


int connect_to_binder(TCPConnector *c, TCPStream **stream) {
    char *server_name = getenv("BINDER_ADDRESS");
    char *port = getenv("BINDER_PORT");
    if (server_name == NULL || port == NULL) {
        std::cerr << "Failed to find BINDER_ADDRESS or BINDER_PORT" << std::endl;
        return ERRNO_ENV_VAR_NOT_SET;
    }

    *stream = c->connect(atoi(port), server_name);
    if (*stream == NULL) {
        std::cerr << "Failed to connect to binder" << std::endl;
        return ERRNO_FAILED_TO_CONNECT;
    }

    return RETVAL_SUCCESS;
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

int send_data(TCPStream *stream, char *name, int *argTypes, char *args, int data_len) {
    int name_len = strlen(name) + 1;
    int arg_len = get_arg_num(argTypes) + 1;
    int total_len = name_len + arg_len + data_len;
    int type = EXECUTE;

    if (stream->send(&total_len) != sizeof(int)) {
        return ERRNO_FAILED_SEND;
    }
    if (stream->send(&type) != sizeof(int)) {
        return ERRNO_FAILED_SEND;
    }
    if (stream->send(&name_len) != sizeof(int)) {
        return ERRNO_FAILED_SEND;
    }
    if (stream->send(name, name_len) != name_len) {
        return ERRNO_FAILED_SEND;
    }
    if (stream->send(&arg_len) != sizeof(int)) {
        return ERRNO_FAILED_SEND;
    }

    for (int i = 0; i < arg_len; i++) {
    }

    if (stream->send(argTypes, arg_len) != (int) (arg_len * sizeof(int))) {
        return ERRNO_FAILED_SEND;
    }
    if (stream->send(&data_len) != sizeof(int)) {
        return ERRNO_FAILED_SEND;
    }

    if (stream->send(args, data_len) != data_len) {
        return ERRNO_FAILED_SEND;
    }

    return RETVAL_SUCCESS;
}

void *execute(void *sd) {
    int socket = *((int *)sd);

    int msg_len;
    int type;
    int name_len;
    int arg_len;
    int data_len;

    get_msg_data(socket, &msg_len, sizeof(int));
    get_msg_data(socket, &type, sizeof(int));

    if (type == TERMINATE) {
        exit(0);
    }else if (type != EXECUTE) {
        return NULL;
    }


    get_msg_data(socket, &name_len, sizeof(int));
    char *name = new char[name_len];
    get_msg_data(socket, name, name_len);

    get_msg_data(socket, &arg_len, sizeof(int));
    int *argTypes = new int[arg_len];
    get_msg_data(socket, argTypes, arg_len * sizeof(int));

    for (int i = 0; i < arg_len; i++) {
    }


    get_msg_data(socket, &data_len, sizeof(int));
    char *data = new char[data_len];
    get_msg_data(socket, data, data_len);

    void **args = new void*[arg_len - 1];
    map_list(data, argTypes, args);

    std::string hash;
    get_hash(hash, name, argTypes);

    map<std::string, skeleton>::iterator it;
    it = server_functions.find(hash);
    if (it == server_functions.end()) {
        send_msg_header(socket, sizeof(int), EXECUTE_FAILURE);
        int errno = ERRNO_FUNC_NOT_FOUND;
        write(socket, &errno, sizeof(int));
        delete[] name;
        delete[] argTypes;
        delete[] data;
        delete[] args;
        return NULL;
    }

    skeleton f = it->second;


    int retval = f(argTypes, args);
    if (retval != 0) {
        send_msg_header(socket, sizeof(int), EXECUTE_FAILURE);
        write(socket, &retval, sizeof(int));
        delete[] name;
        delete[] argTypes;
        delete[] data;
        delete[] args;
        return NULL;
    }

    parse_args(argTypes, args, data);


    send_msg_header(socket, data_len, EXECUTE_SUCCESS);
    write(socket, data, data_len);

    close(socket);
    delete[] name;
    delete[] argTypes;
    delete[] data;
    delete[] args;
    return NULL;
}

// Client functions
int rpcCall(char *name, int *argTypes, void **args) {
    // Initialize tcp connector
    TCPConnector *c = new TCPConnector();
    TCPStream *stream;


    int retval = connect_to_binder(c, &stream);
    if (retval != RETVAL_SUCCESS) {
        delete c;
        return ERRNO_FAILED_TO_CONNECT;
    }


    // Generate the function hash
    std::string hash;
    get_hash(hash, name, argTypes);

    // Send lookup request
    retval = send_hash(stream, LOOKUP, hash);


    // Get binder lookup response
    std::string server;
    int msg_len = get_int(stream);
    int type = get_int(stream);

    // If return value is an error code
    if (type != RETVAL_SUCCESS) {
        delete c;
        delete stream;
        return ERRNO_FUNC_NOT_FOUND;
    } else {
        server.clear();
        char server_buf[100];
        read(stream->get_sd(), server_buf, msg_len);
        server.append(server_buf, msg_len);
    }

    int port = get_int(stream);

    // delete stream;

    stream = c->connect(port, server.c_str());
    if (stream == NULL) {
        delete c;
        delete stream;
        return ERRNO_FAILED_TO_CONNECT;
    }
    // Parse arguments and send
    int data_len = get_arg_len(argTypes);

    char *data = new char[data_len];

    parse_args(argTypes, args, data);


    // Send execute request to server
    retval = send_data(stream, name, argTypes, data, data_len);
    if (retval != RETVAL_SUCCESS) {
        delete c;
        delete[] data;
        delete stream;
        return retval;
    }

    // Get server response
    msg_len = get_int(stream);
    type = get_int(stream);

    if (type == EXECUTE_FAILURE) {
        retval = get_int(stream);
    } else {
        stream->receive(data, msg_len);
        copy_results(data, argTypes, args);
        retval = RETVAL_SUCCESS;
    }




    delete c;
    delete[] data;
    delete stream;
    return retval;
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
        delete c;
        return retval;
    }

    send_int(stream, 0);
    send_int(stream, TERMINATE);


    delete c;
    delete stream;
    return RETVAL_SUCCESS;
}


// Server functions
int rpcInit() {
    TCPConnector *c = new TCPConnector();
    TCPStream *stream;

    int retval = connect_to_binder(c, &stream);
    if (retval != RETVAL_SUCCESS) {
        delete c;
        return ERRNO_FAILED_TO_CONNECT;
    }

    server_connection = stream;

    // Open socket to accept connections
    signal(SIGPIPE, SIG_IGN);
    server_acceptor = new TCPAcceptor(1337);
    if (server_acceptor->start() != 0) {
        delete c;
        delete server_acceptor;
        return ERRNO_FAILED_TO_START_SERVER;
    }

    int port = server_acceptor->get_port();
    send_int(stream, 0);
    send_int(stream, INIT);
    send_int(stream, port);

    retval = get_int(stream);
    if (retval != 0) {
        delete c;
        delete server_acceptor;
        return ERRNO_INIT_FAILED;
    }
    retval = get_int(stream);
    if (retval != RETVAL_SUCCESS) {
        delete c;
        delete server_acceptor;
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

    server_functions.insert(std::make_pair(hash, f));

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
    if (server_acceptor == NULL) {
        return ERRNO_FAILED_TO_START_SERVER;
    }

    pthread_t handler;
    int i = 0;
    while(1) {
        int retval = server_acceptor->accept();
        if (retval >= 0) {
            pthread_create (&handler, NULL, execute, &retval);
            i++;
        }
    }

    return RETVAL_SUCCESS;
}

