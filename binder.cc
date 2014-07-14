#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include "tcpacceptor.h"
#include <rpc.h>
#include <rpc_errno.h>

#define BUFFER_SIZE 256



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

int handle_init(int sd, int len) {
    return RETVAL_SUCCESS;
}

int handle_lookup(int sd, int len) {
    std::cout << "Handling lookup"<< std::endl;
    int arg_len = (len - NAME_SIZE);

    char name[NAME_SIZE + 1];
    int *args_types = new int[arg_len];

    int retval = get_data(sd, (void *)name, NAME_SIZE);
    name[NAME_SIZE] = 0;
    std::cout << "Got Name:"<< name << std::endl;

    retval = get_data(sd, (void *) args_types, arg_len);
    std::cout << "First arg:"<< args_types[0] << std::endl;

    // TODO handle retval
    (void) retval;

    delete[] args_types;
    return RETVAL_SUCCESS;
}

int handle_register(int sd, int len) {
    return RETVAL_SUCCESS;
}


int handle_request(int sd) {
    int len;
    int status = read(sd, &len, sizeof(len));
    if (status <= 0) {
        return ERRNO_FAILED_READ;
    }
    std::cout << "Got len:" << len << std::endl;

    int type;
    status = read(sd, &type, sizeof(type));
    if (status <= 0) {
        return ERRNO_FAILED_READ;
    }
    std::cout << "Got type:" << type << std::endl;

    switch(type) {
        case INIT:
            return handle_init(sd, len);
        case LOOKUP:
            return handle_lookup(sd, len);
        case REGISTER:
            return handle_register(sd, len);
        default:
            std::cout << "Got invalid request:" << type << std::endl;
            return BINDER_INVALID_COMMAND;
    }
}


int main() {
    int retval;
    TCPAcceptor *acceptor = new TCPAcceptor(12345);
    vector<int> active_socks;

    int main_socket;
    int maxfd;
    int cursd;
    fd_set total_set, active_set;
    FD_ZERO(&total_set);
    FD_ZERO(&active_set);


    int result = 0;


    if (acceptor->start() == 0) {
        acceptor->display_name();
        acceptor->display_port();

        main_socket = acceptor->get_sd();
        maxfd = main_socket;
        FD_SET(main_socket, &total_set);

        while(1) {
            active_set = total_set;
            result = select(maxfd+1, &active_set, NULL, NULL, NULL);

            if (result > 0) {
                if (FD_ISSET(main_socket, &active_set)) {
#ifdef DEBUG
                    std::cout << "Accepting" << std::endl;
#endif
                    // Accept connection
                    cursd = acceptor->accept();
                    if (cursd > 0) {
                        active_socks.push_back(cursd);

                        // set fd data
                        FD_SET(cursd, &total_set);
                        maxfd = max(maxfd, cursd);
                    }
                }

                // Iterate through all active sockets
                for (std::vector<int>::iterator it = active_socks.begin() ; it != active_socks.end();) {
                    if (FD_ISSET(*it, &active_set)) {
                        retval = handle_request(*it);

                        // TODO handle retval
                        (void) retval;
                        close(*it);
                        active_socks.erase(it);
                        FD_CLR(*it, &total_set);
                        continue;
                    }
                    ++it;
                }
            }
        }
    }
    std::cerr << "Failed to start server" << std::endl;
    return 0;
}
