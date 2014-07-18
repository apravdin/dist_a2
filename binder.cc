#include <iostream>
#include <list>
#include <cstring>
#include <unistd.h>
#include "tcpacceptor.h"
#include "tcpconnector.h"
#include <csignal>
#include <rpc.h>
#include <rpc_errno.h>
#include <pthread.h>
#include <map>
#include <algorithm>
#include <my_rpc.h>

#define BUFFER_SIZE 256

static map<std::string, std::list<std::string> > registered_functions;
static map<std::string, int> server_ports;


int get_data(int sd, void *result, int data_len) {
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

int get_hash(int sd, std::string &hash, int msg_len) {
    hash.clear();

    char *msg = new char[msg_len];

    int retval = get_data(sd, msg, msg_len);
    if (retval == msg_len) {
        hash.append(msg, msg_len);
    }

    delete[] msg;
    return RETVAL_SUCCESS;
}

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

int get_server(std::list<std::string> &servers, std::string &result) {
    result.clear();
    if (servers.empty()) {
        return ERRNO_FUNC_NOT_FOUND;
    }

    result = servers.front();
    servers.pop_front();
    servers.push_back(result);

    return RETVAL_SUCCESS;
}

int function_lookup(std::string &hash, std::string &result) {
    std::map<std::string, std::list<std::string> >::iterator it;
    it = registered_functions.find(hash);

    if (it != registered_functions.end()) {
        return get_server(it->second, result);
    } else {
        return ERRNO_FUNC_NOT_FOUND;
    }
}

int register_function(std::string &hash, std::string &server) {
    std::map<std::string, std::list<std::string> >::iterator it;
    it = registered_functions.find(hash);

    if (it != registered_functions.end()) {
        std::list<std::string>::iterator lit;
        lit = std::find(it->second.begin(), it->second.end(), server);
        if (lit != it->second.end()) {
            std::cout << "Found dup" << std::endl;
            return RETVAL_SUCCESS;
        }

        std::cout << "Adding to list" << std::endl;
        it->second.push_back(server);
    } else {
        std::list<std::string> *v = new std::list<std::string>;
        if (v == NULL) {
            return ERRNO_NO_SPACE;
        }

        std::cout << "Completely new list" << std::endl;
        v->push_back(server);
        registered_functions.insert(std::pair<std::string, std::list<std::string> >(hash, *v));
    }
    return RETVAL_SUCCESS;
}

int handle_register(int sd, int len, std::string &server_addr, int port) {
    // Generate a hash
    std::string hash;
    int retval = get_hash(sd, hash, len);
    if (retval < 0) {
        return retval;
    }

    // Get server lock
    // Add function to server
    retval = register_function(hash, server_addr);
    // Release server lock

    return retval;
}

int handle_init(int sd, int len) {
    int port;
    len = read(sd, &port, sizeof(int));
    if (len <= 0) {
        send_header(sd, 0, len);
    }

    // Get server addr
    std::string server_addr;
    get_client_addr(sd, server_addr);

    // Respond with status
    send_header(sd, 0, RETVAL_SUCCESS);

    server_ports.insert(std::make_pair(server_addr, port));

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
            int retval = handle_register(sd, msg_len, server_addr, port);
            send_header(sd, 0, retval);
        }
    }

    std::cout << "Closing connection to server:" << server_addr << std::endl;


    // Get server lock
    // Remove server functions
    std::list<std::string>::iterator lit;
    std::map<std::string, std::list<std::string> >::iterator it;
    for (it = registered_functions.begin(); it != registered_functions.end(); ++it){
        lit = std::find(it->second.begin(), it->second.end(), server_addr);
        if (lit != it->second.end()) {
            std::cout << "Unregistered:" << it->first << "@" << *lit << std::endl;
            it->second.erase(lit);
        }
    }

    for (it = registered_functions.begin(); it != registered_functions.end(); ++it){
        for (lit = it->second.begin(); lit != it->second.end(); ++lit) {
            std::cout << "Remains:" << it->first << "@" << *lit << std::endl;

        }
    }

    std::map<std::string, int>::iterator pit;
    pit = server_ports.find(server_addr);
    if (pit != server_ports.end()) {
        server_ports.erase(pit);
    }
    // Release server lock

    return RETVAL_SUCCESS;
}

int handle_lookup(int sd, int len) {
    // Generate a hash
    std::string hash;
    int retval = get_hash(sd, hash, len);
    if (retval < 0) {
        send_header(sd, 0, retval);
        return retval;
    }

    // Lookup the function
    // Get server lock
    std::string server;
    retval = function_lookup(hash, server);
    // Release server lock

    // Respond with status
    if (retval != RETVAL_SUCCESS) {
        send_header(sd, 0, retval);
    } else {
        send_header(sd, server.length(), retval);
        retval = write(sd, server.c_str(), server.length());
        int port = server_ports[server];
        write(sd, &port, sizeof(int));
    }

    return RETVAL_SUCCESS;
}

int handle_terminate(int sd, int len) {
    TCPConnector *c = new TCPConnector();
    TCPStream *stream;

    int cmd = TERMINATE;

    std::map<std::string, int>::iterator pit;
    for (pit = server_ports.begin(); pit != server_ports.end(); ++pit) {
        stream = c->connect(pit->second, pit->first.c_str());
        stream->send(&len);
        stream->send(&cmd);
    }

    exit(0);
}


void *handle_request(void *sd) {
    int socket = *((int *)sd);

    // Get the length of the message
    int len;
    int status = read(socket, &len, sizeof(int));
    if (status <= 0) {
        return NULL;
    }

    // Get the message type
    int type;
    status = read(socket, &type, sizeof(int));
    if (status <= 0) {
        return NULL;
    }

    switch(type) {
        case INIT:
            std::cout << "SERVER INIT:" << socket << std::endl;
            handle_init(socket, len);
            break;
        case LOOKUP:
            std::cout << "CLIENT LOOKUP:" << socket << std::endl;
            handle_lookup(socket, len);
            break;
        case TERMINATE:
            std::cout << "CLIENT TERMINATE:" << socket << std::endl;
            handle_terminate(socket, len);
            break;
        default:
            std::cout << "Got invalid request:" << type << std::endl;
            send_header(socket, 0, BINDER_INVALID_COMMAND);
            break;
    }
    std::cout << "Closing sd:" << socket << std::endl;
    close(socket);
    return NULL;
}


int main() {
    signal(SIGPIPE, SIG_IGN);
    int retval;
    TCPAcceptor *acceptor = new TCPAcceptor(12345);
    try {
        if (acceptor->start() == 0) {
            acceptor->display_name();
            acceptor->display_port();

            pthread_t handler;
            int i = 0;
            while(1) {
                retval = acceptor->accept();
                if (retval >= 0) {
                    pthread_create (&handler, NULL, handle_request, &retval);
                    i++;
                }
            }
        }
        std::cerr << "Failed to start server" << std::endl;

    } catch (int e) {
        std::cout << "Exception Caught:" << e << std::endl;
    }

    return 0;
}
