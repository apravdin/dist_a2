#include <iostream>
#include <string>
#include "tcpconnector.h"
#include <stdlib.h>
#include <unistd.h>

#define BUFFER_SIZE 256

int main() {
    TCPConnector *c = new TCPConnector();
    TCPStream *stream;
    char *server_name = getenv("SERVER_ADDRESS");
    char *port = getenv("SERVER_PORT");
#ifdef DEBUG
    std::cout << "Connection to: " << server_name << ":" << port << std::endl;
#endif

    if (server_name == NULL || port == NULL) {
        std::cerr << "Failed to find SERVER_ADDRESS or SERVER_PORT" << std::endl;
        return 0;
    }

    stream = c->connect(atoi(port), server_name);

    if (stream == NULL) {
        std::cerr << "Failed to connect" << std::endl;
        return 0;
    }

    std::string msg = "";
    int msg_len;
    int bytes_read;
    char buf[BUFFER_SIZE];


    while(std::getline(std::cin, msg)) {

        msg_len = msg.size();

        if (msg_len <= 0) {
            continue;
        }

        stream->send(&msg_len);
        stream->send(msg.c_str(), msg_len);
#ifdef DEBUG
        std::cout << "Sending: " << msg << std::endl;
#endif

        int msg_len;
        bytes_read = 0;
        int len;

        msg = "";

        // Get server response
        read(stream->get_sd(), &msg_len, sizeof(msg_len));
        while (bytes_read < msg_len) {
            len = stream->receive(buf, BUFFER_SIZE-1);
            if (len <= 0) {
                return -1;
            }

            buf[len] = 0;
            bytes_read += len;
            msg.append(buf, len);
        }

        std::cout << "Server: " << msg << std::endl;
        sleep(2);
    }

    delete c;
    return 0;
}
