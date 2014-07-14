#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include "tcpacceptor.h"
#include <rpc.h>
#include <rpc_errno.h>
#include <pthread.h>
#include <map>

#define BUFFER_SIZE 256

static map<std::string, std::vector<std::string> > registered_functions;


void send_header(int sd, int len, int type) {
    write(sd, &len, sizeof(int));
    write(sd, &type, sizeof(int));
}

void get_client_addr(int sd, std::string &result) {
    struct sockaddr_in address;
    socklen_t len = sizeof(address);
    bzero(&address, sizeof(address));

    getsockname(sd, (struct sockaddr*)&address, &len);

    result.append(inet_ntoa(address.sin_addr));
}

int get_data(int sd, void *result, int data_len) {
    char buffer[BUFFER_SIZE];
    int len;
    int bytes_read = 0;

    std::cout << "Start read:"<< data_len << std::endl;
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

        // Null terminate for debug purposes
        buffer[len] = 0;
        for (int i = 0; i < len; i++) {
            std::cout << (int) buffer[i] << ",";
        }
        std::cout << std::endl;
    }
    std::cout << "End read"<< std::endl;
    return bytes_read;
}

void get_hash(std::string &hash, char *name, int *arg_types, int arg_len) {
    hash.clear();
    hash.append(name, NAME_SIZE);
    hash.append((char *) arg_types, arg_len);
}

void get_server(std::vector<std::string> &servers, std::string &result) {
    result = servers.front();
}

int function_lookup(std::string &hash, std::string &result) {
    std::map<std::string, std::vector<std::string> >::iterator it;
    it = registered_functions.find(hash);

    if (it != registered_functions.end()) {
        get_server(it->second, result);
        return RETVAL_SUCCESS;
    } else {
        return ERRNO_FUNC_NOT_FOUND;
    }
}

int register_function(std::string &hash, std::string &server) {
    std::map<std::string, std::vector<std::string> >::iterator it;
    it = registered_functions.find(hash);

    if (it != registered_functions.end()) {
        it->second.push_back(hash);
    } else {
        std::vector<std::string> v;
        v.push_back(server);
        registered_functions.insert(std::pair<std::string, std::vector<std::string> >(hash, v));
    }
    return RETVAL_SUCCESS;
}

int handle_register(int sd, int len, std::string &server_addr) {
    // Get signature
    std::string hash;

    // Get server lock
    // Add function to server
    register_function(hash, server_addr);
    // Release server lock

    // Respond with status
    return RETVAL_SUCCESS;
}

int handle_init(int sd, int len) {
    // Get server addr
    std::string server_addr;
    get_client_addr(sd, server_addr);

    // Respond with status
    send_header(sd, 0, RETVAL_SUCCESS);

    // Keep connection alive
    int msg_len;
    int type;
    while (true) {
        len = read(sd, &msg_len, sizeof(int));
        if (len <= 0) {
            break;
        }
        len = read(sd, &type, sizeof(int));
        if (len <= 0) {
            break;
        }

        // Continuously register unless connection is closed
        if (type == REGISTER) {
            handle_register(sd, len, server_addr);
        }
    }

    std::cout << "Closing connection to server:" << server_addr << std::endl;


    // Get server lock
    // Remove server functions
    // Release server lock

    return RETVAL_SUCCESS;
}

int handle_lookup(int sd, int len) {
    std::cout << "Handling lookup"<< std::endl;
    int arg_len = len - NAME_SIZE;

    char name[NAME_SIZE + 1];
    int *args_types = new int[arg_len];

    int retval = get_data(sd, (void *)name, NAME_SIZE);
    name[NAME_SIZE] = 0;
    std::cout << "Got Name:"<< name << std::endl;

    retval = get_data(sd, (void *) args_types, arg_len);
    std::cout << "First arg:"<< args_types[0] << std::endl;

    // Mask out array lengths
    int total_args = arg_len / sizeof(int);
    for (int i = 0; i < total_args; i++) {
        args_types[i] &= ARG_TYPE_MASK;
    }

    // Generate a hash
    std::string hash;
    get_hash(hash, name, args_types, arg_len);

    std::cout << "HASH:" << hash.length() << std::endl;

    // Get server lock
    // Lookup the function
    std::string server;
    retval = function_lookup(hash, server);

    if (retval != RETVAL_SUCCESS) {
        len = sizeof(int);
        send_header(sd, 0, retval);
    } else {
        send_header(sd, server.length(), retval);
        write(sd, server.c_str(), server.length());
    }

    // Release server lock

    // Respond with status

    delete[] args_types;
    return RETVAL_SUCCESS;
}


void *handle_request(void *sd) {
    int socket = *((int *)sd);

    // Get the length of the message
    int len;
    int status = read(socket, &len, sizeof(len));
    if (status <= 0) {
        return NULL;
    }
    std::cout << "Got len:" << len << std::endl;

    // Get the message type
    int type;
    status = read(socket, &type, sizeof(type));
    if (status <= 0) {
        return NULL;
    }
    std::cout << "Got type:" << type << std::endl;

    switch(type) {
        case INIT:
            handle_init(socket, len);
            break;
        case LOOKUP:
            handle_lookup(socket, len);
            break;
        default:
            std::cout << "Got invalid request:" << type << std::endl;
            send_header(socket, 0, BINDER_INVALID_COMMAND);
            break;
    }

    close(*((int *)sd));
    return NULL;
}


int main() {
    int retval;
    TCPAcceptor *acceptor = new TCPAcceptor(12345);


    if (acceptor->start() == 0) {
        acceptor->display_name();
        acceptor->display_port();

        pthread_t handler;
        while(1) {
            retval = acceptor->accept();

            if (retval >= 0) {
                pthread_create (&handler, NULL, handle_request, &retval);
            }
        }
    }
    std::cerr << "Failed to start server" << std::endl;
    return 0;
}
