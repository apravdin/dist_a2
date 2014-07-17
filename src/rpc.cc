#include <iostream>
#include <string>
#include "tcpconnector.h"
#include "tcpstream.h"
#include "tcpacceptor.h"
#include <stdlib.h>
#include <unistd.h>
#include <rpc_errno.h>
#include <rpc.h>
#include <cassert>
#include <map>
#include <unistd.h>

static TCPStream *server_connection = NULL;
static std::map<std::string, skeleton> server_functions;


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

inline bool is_array(int argType) {
    return argType & ARG_ARRAY_MASK;
}

unsigned int get_type_size(int argType) {
    int type = argType & ARG_TYPE_MASK;
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
                std::cout << "Got invalid type" << std::endl;
                return 0;
        }
}

unsigned int get_arg_len(int *argTypes) {
    unsigned int total;

    for (unsigned int i = 0; i < get_arg_num(argTypes); i++) {
        total += get_type_size(argTypes[i]);
    }

    return total;
}

void parse_args(int *argTypes, void **args, char *result) {
    unsigned int offset = 0;
    unsigned int size = 0;
    for (unsigned int i = 0; i < get_arg_num(argTypes); i++) {
        size = get_type_size(argTypes[i]);
        if (is_array(argTypes[i])) {
            memcpy(&(result[offset]), args[i], size);
        } else {
            memcpy(&(result[offset]), &(args[i]), size);
        }
        offset += size;
    }
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
        argTypes[i] &= ARG_HASH_MASK;
    }
}

int get_hash(std::string &hash, char *name, int *argTypes) {
    hash.clear();

    int arg_len = get_arg_num(argTypes);
    int *temp_args = new int[arg_len + 1];
    memcpy(temp_args, argTypes, arg_len + 1);

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

int send_data(TCPStream *stream, char *name, int *argTypes, char *args, int data_len) {
    int name_len = strlen(name) + 1;
    int arg_len = get_arg_num(argTypes) + 1;
    int total_len = name_len + arg_len + data_len;
    int type = EXECUTE;

    stream->send(&total_len);
    stream->send(&type);

    stream->send(&name_len);
    stream->send(name, name_len);

    stream->send(&arg_len);
    stream->send(argTypes, arg_len);

    stream->send(&data_len);
    stream->send(args, data_len);

    int msg_len = get_int(stream);
    type = get_int(stream);

    if (type == EXECUTE_SUCCESS) {
        // TODO get result data
        (void) msg_len;

    } else if (type == EXECUTE_FAILURE) {
        // TODO place result in correct place
        get_int(stream);
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

    if (type != EXECUTE) {
        std::cout << "INVALID EXECUTE COMMAND" << std::endl;
        return NULL;
    }


    get_msg_data(socket, &name_len, sizeof(int));
    char *name = new char[name_len];
    get_msg_data(socket, &name, name_len);

    get_msg_data(socket, &arg_len, sizeof(int));
    int *argTypes = new int[arg_len];
    get_msg_data(socket, &argTypes, arg_len * sizeof(int));

    get_msg_data(socket, &data_len, sizeof(int));
    void **args = (void **) new char[data_len];
    get_msg_data(socket, &args, data_len);

    std::string hash;
    get_hash(hash, name, argTypes);

    map<std::string, skeleton>::iterator it;
    it = server_functions.find(hash);
    if (it == server_functions.end()) {
        send_msg_header(socket, sizeof(int), EXECUTE_FAILURE);
        int errno = ERRNO_FUNC_NOT_FOUND;
        write(socket, &errno, sizeof(int));
        return NULL;
    }

    skeleton f = it->second;

    f(argTypes, args);

    send_msg_header(socket, data_len, EXECUTE_SUCCESS);
    write(socket, args, data_len);

    close(socket);
    return NULL;
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
    std::string server;
    std::string port;
    int msg_len = get_int(stream);
    int type = get_int(stream);

    // If return value is an error code
    if (type != RETVAL_SUCCESS) {
        std::cout << "Server: Lookup failed:" << msg_len << " " << type << std::endl;
        return ERRNO_FUNC_NOT_FOUND;
    } else {
        get_str(stream, server, msg_len);
        std::cout << "Server: " << server << std::endl;
    }

    msg_len = get_int(stream);
    type = get_int(stream);
    if (type != RETVAL_SUCCESS) {
        std::cout << "Server: Lookup failed:" << msg_len << " " << type << std::endl;
        return ERRNO_FUNC_NOT_FOUND;
    } else {
        get_str(stream, port, msg_len);
        std::cout << "Port: " << port << std::endl;
    }


    delete stream;

    stream = c->connect(atoi(port.c_str()), server.c_str());

    // Parse arguments and send
    int data_len = get_arg_len(argTypes);

    char *data = new char[data_len];

    parse_args(argTypes, args, data);

    // Send execute request to server
    send_data(stream, name, argTypes, data, data_len);

    // Get server response
    msg_len = get_int(stream);
    type = get_int(stream);

    stream->receive((char *) args, msg_len);


    delete c;
    delete[] data;
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
    signal(SIGPIPE, SIG_IGN);
    int retval;
    TCPAcceptor *acceptor = new TCPAcceptor(12345);
    if (acceptor->start() == 0) {
        acceptor->display_name();
        acceptor->display_port();

        pthread_t handler;
        int i = 0;
        while(1) {
            retval = acceptor->accept();
            if (retval >= 0) {
                pthread_create (&handler, NULL, execute, &retval);
                i++;
            }
        }
    }
    std::cerr << "Failed to start server" << std::endl;

    return RETVAL_SUCCESS;
}

