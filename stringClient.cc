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

    if (server_name == NULL || port == NULL) {
        std::cerr << "Failed to find SERVER_ADDRESS or SERVER_PORT" << std::endl;
        return 0;
    }

    stream = c->connect(atoi(port), server_name);

    if (stream == NULL) {
        std::cerr << "Failed to connect" << std::endl;
        return 0;
    }

    std::string msg = "####";
    int msg_len;
    int total_bytes_read;
    int bytes_read;
    char buf[BUFFER_SIZE];


    while(1) {
        sleep(2);
        std::getline(std::cin, msg);

        msg_len = msg.size();

        stream->send(&msg_len);
        stream->send(msg.c_str(), msg_len);
        total_bytes_read = 0;
        msg = "";

        while(total_bytes_read < msg_len) {
            bytes_read = stream->receive(buf, BUFFER_SIZE);

            if (bytes_read > 0) {
                msg.append(buf, bytes_read);
                total_bytes_read += bytes_read;
            }
        }
        std::cout << "Server: " << msg << std::endl;
    }

    delete c;
    return 0;
}
