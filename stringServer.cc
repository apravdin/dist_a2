#include <iostream>
#include <vector>
#include <unistd.h>
#include "tcpacceptor.h"

#define BUFFER_SIZE 256

int process_data(int sd);
int is_divider(char c);
void totitle(char *buffer, int len);

int main() {
    TCPAcceptor *acceptor = new TCPAcceptor(12377);
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

        std::cout << "Awaiting connections" << std::endl;
        while(1) {
            active_set = total_set;
            result = select(maxfd+1, &active_set, NULL, NULL, NULL);

            if (result > 0) {
                if (FD_ISSET(main_socket, &active_set)) {
                    std::cout << "Getting connection" << std::endl;

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
                        std::cout << "Processing data: " << *it << std::endl;

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
    string msg;
    char buffer[BUFFER_SIZE];

    // Get user input
    int len = read(sd, buffer, sizeof(buffer));
    if (len <= 0) {
        std::cerr << "No input" << endl;
        return -1;
    }
    buffer[len] = 0;
    std::cout << "received: " << (int)*buffer << endl;
    msg.append(buffer, len);

    totitle(buffer, len);

    // Send back to client
    write(sd, buffer, len);

    return 0;
}

// Set to title case
void totitle(char *buffer, int len) {
    int status = 1;
    for (int i = 0; i < len; i++) {
        if (status && !is_divider(buffer[i])) {
            buffer[i] = toupper(buffer[i]);
            status = 0;
        } else {
            buffer[i] = tolower(buffer[i]);
            status = is_divider(buffer[i]);
        }
    }
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
