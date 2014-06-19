#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include "tcpacceptor.h"

#define BUFFER_SIZE 256

int process_data(int sd);
int is_divider(char c);
int totitle(char *buffer, int len, int status);

int main() {
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
                    std::cout << "Accepting" << std::endl;
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
                        if (process_data(*it) != 0) {
                            close(*it);
                            active_socks.erase(it);
                            FD_CLR(*it, &total_set);
                            continue;
                        }
                    }
                    ++it;
                }
            }
        }
    }
    std::cerr << "Failed to start server" << std::endl;
    return 0;
}

int process_data(int sd) {
    int msg_len;
    int bytes_read = 0;
    int len;
    int status = 1;

    string msg = "";
    char buffer[BUFFER_SIZE] = { 0 };

    // Get user input
    read(sd, &msg_len, sizeof(msg_len));
    write(sd, &msg_len, sizeof(msg_len));
    while (bytes_read < msg_len) {
        len = read(sd, buffer, BUFFER_SIZE-1);
        if (len <= 0) {
            return -1;
        }

        buffer[len] = 0;
        bytes_read += len;
        // msg.append(buffer, len);

        std::cout << buffer;
        status = totitle(buffer, len, status);

        write(sd, buffer, len);
    }
    std::cout << std::endl;

    // Send back to client
    // write(sd, &msg_len, sizeof(msg_len));
    // write(sd, msg.c_str(), msg.length());

    return 0;
}

// Set to title case
int totitle(char *buffer, int len, int status = 1) {
    for (int i = 0; i < len; i++) {
        if (status && !is_divider(buffer[i])) {
            buffer[i] = toupper(buffer[i]);
            status = 0;
        } else {
            buffer[i] = tolower(buffer[i]);
            status = is_divider(buffer[i]);
        }
    }
    return status;
}

int is_divider(char c) {
    switch(c) {
        case ' ':
            return 1;
        case '-':
            return 1;
        default:
            return 0;
    }
}
