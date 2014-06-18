#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>

#ifndef TCPSTREAM_H__
#define TCPSTREAM_H__

class TCPStream {
    int m_sd;
    int m_port;

public:
    TCPStream(int sd, struct sockaddr_in *addr);
    ~TCPStream();

    int get_sd();

    int send(const int *val);
    int send(const char *buffer, int len);
    int receive(char *buffer, int len);
};

#endif /* end of include guard: TCPSTREAM_H__ */
