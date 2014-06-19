#include <iostream>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "tcpacceptor.h"
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

TCPAcceptor::TCPAcceptor(int port)
    : m_lsd(0), m_port(port) {}

TCPAcceptor::~TCPAcceptor() {
    if (this->m_lsd > 0) {
        close(this->m_lsd);
    }
}

int TCPAcceptor::start() {
    this->m_lsd = socket(PF_INET, SOCK_STREAM, 0);

    if (this->m_lsd <= 0) {
        std::cerr << "Failed to create server socket" << std::endl;
        return -1;
    }

    struct sockaddr_in address;
    socklen_t len = sizeof(address);
    bzero(&address, sizeof(address));
    address.sin_family = PF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(INADDR_ANY);

    int result = bind(this->m_lsd, (struct sockaddr*)&address, sizeof(address));

    if (result != 0) {
        std::cerr << "Failed to bind" << std::endl;
        return result;
    }

    getsockname(m_lsd, (struct sockaddr*)&address, &len);
    this->m_port = ntohs(address.sin_port);

    result = listen(this->m_lsd, MAX_CONNECTIONS);
    if (result != 0) {
        std::cerr << "Failed to listen" << std::endl;
    }

    return result;
}

int TCPAcceptor::accept() {
    int sd = ::accept(this->m_lsd, (struct sockaddr*)NULL, NULL);

    if (sd < 0) {
        std::cerr << "Failed to accept" << std::endl;
    }

    return sd;
}

void TCPAcceptor::display_name() {
    char server_name[1024];
    gethostname(server_name, 1024);
    std::cout << "SERVER_ADDRESS " << server_name << std::endl;
}

void TCPAcceptor::display_port() {
    std::cout << "SERVER_PORT " << this->m_port << std::endl;
}

int TCPAcceptor::get_sd() {
    return this->m_lsd;
}
