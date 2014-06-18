#ifndef TCPACCEPTOR_H__
#define TCPACCEPTOR_H__

#include <string>
#include <netinet/in.h>
#include "tcpstream.h"

#define MAX_CONNECTIONS 5

using namespace std;

class TCPAcceptor {
  private:
    int    m_lsd;
    int    m_port;

  public:
    TCPAcceptor(int port);
    ~TCPAcceptor();

    int start();
    int accept();

    void display_name();
    void display_port();
    int get_sd();
};

#endif /* end of include guard: TCPACCEPTOR_H__ */
