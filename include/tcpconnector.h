#include "tcpstream.h"
#include <iostream>
#include <netdb.h>
#include <arpa/inet.h>
#include <cstring>

#ifndef TCPCONNECTOR_H__
#define TCPCONNECTOR_H__

class TCPConnector {
private:
    int resolveHostName(const char *server, struct in_addr *address);
public:
    TCPStream* connect(int port, const char* server);
};

#endif /* end of include guard: TCPCONNECTOR_H__ */
