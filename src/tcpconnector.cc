#include "tcpconnector.h"
#include "tcpstream.h"
#include <iostream>
#include <netdb.h>
#include <arpa/inet.h>
#include <string>
#include <cstring>
#include <unistd.h>

#define DOMAIN      AF_INET
#define TYPE        SOCK_STREAM
#define PROTOCOL    0


int TCPConnector::resolveHostName(const char *server, struct in_addr *address) {
    struct addrinfo *res;

    int result = getaddrinfo(server, NULL, NULL, &res);
    if (result == 0) {
        memcpy(address, &((struct sockaddr_in *) res->ai_addr)->sin_addr, sizeof(struct in_addr));
        freeaddrinfo(res);
    }
    return result;
}

TCPStream *TCPConnector::connect(int port, const char *server) {
    struct sockaddr_in address;

    // Setup the host info variable
    bzero(&address, sizeof address);
    address.sin_family = AF_INET;
    address.sin_port = htons(port);


    // resolve the server name
    int ret = resolveHostName(server, &(address.sin_addr));

    if (ret != 0) {
        std::cerr << "Failed to resolve hostname" << std::endl;
        return NULL;
    }

    // Create a socket
    int sd = socket(DOMAIN, TYPE, PROTOCOL);
    if (sd == -1) {
        std::cerr << "Failed to create a socket" << std::endl;
    } else {

        // connect the socket
        if (::connect(sd, (struct sockaddr*)&address, sizeof(address)) != 0) {
            return NULL;
        }
    }

    // Create a new stream and return it to the client
    TCPStream *stream = new TCPStream(sd, &address);
    return stream;
};

