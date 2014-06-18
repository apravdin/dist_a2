#include "tcpstream.h"
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>



TCPStream::TCPStream(int sd, struct sockaddr_in *addr): m_sd(sd) {
    m_port = ntohs(addr->sin_port);
};

TCPStream::~TCPStream() {
    close(this->m_sd);
};

int TCPStream::send(const char *buffer, int len) {
    return ::write(this->m_sd, buffer, len);
}

int TCPStream::send(const int* val) {
    return ::write(this->m_sd, val, sizeof(int));
}

int TCPStream::receive(char *buffer, int len) {
    bzero(buffer, len);
    return ::read(this->m_sd, buffer, len);
}

int TCPStream::get_sd() {
    return this->m_sd;
}
