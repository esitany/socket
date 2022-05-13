
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <time.h>
#include <signal.h>
#include <errno.h>

#include <sys/select.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>


#define SOCK_PACKET_SIZE     2048

#define TAG "UDP_CLIENT"

#ifndef lDbg
  #define lDbg(fmt, ...) { \
    fprintf(stdout, "%10s|%5d >> " fmt "\n", \
                    TAG, __LINE__,  ##__VA_ARGS__); \
    fflush(stdout); \
  }
#endif
#ifndef lWrn
  #define lWrn(fmt, ...) { \
    fprintf(stdout, "\x1b[33m%10s|%5d >> " fmt "\x1B[0m\n", \
                    TAG, __LINE__,  ##__VA_ARGS__); \
    fflush(stdout); \
  }
#endif
#ifndef lErr
  #define lErr(fmt, ...) { \
    fprintf(stdout, "\x1b[31m%10s|%5d >> " fmt "[E=%s(%d)]\x1B[0m\n", \
                    TAG, __LINE__,  ##__VA_ARGS__, strerror(errno), errno); \
    fflush(stdout); \
  }
#endif

#ifndef hexdump
  void sockHexdump(int line, const char *title, void *pack, int size);

  #define hexdump(T, P, S) sockHexdump(__LINE__, T, P, S)
#endif

void sockHexdump(int line, const char *title, void *pack, int size)
{
    int   idx = 0;

    char strTmp[4]    = {"\0"};
    char strAscii[32] = {"\0"};
    char strDump[64]  = {"\0"};
    char *dump        = NULL;

    dump = (char *)pack;
    if ((size > 0) && (pack != NULL)) {
        fprintf(stdout, "%10s|%5d >> ***** %s %d bytes *****\n",
                TAG, line, (title == NULL) ? "None" : title, size);
        fflush(stdout);

        memset(strDump, 0, 64);
        memset(strAscii, 0, 32);

        for(idx = 0; idx < size; idx++) {
            if    ((0x1F < dump[idx]) && (dump[idx] < 0x7F) ) { strAscii[idx & 0x0F] = dump[idx]; }
            else                                              { strAscii[idx & 0x0F] = 0x2E;
            }

            snprintf(strTmp, 4, "%02X ", (unsigned char)dump[idx]);
            strcat(strDump, strTmp);
            if( (idx != 0) && ((idx & 0x03) == 0x03)) { strcat(strDump, " "); }

            if((idx & 0x0F) == 0x0F) {
                fprintf(stdout, "%16s <0x%04X> %s%s\n", "", (idx & 0xFFF0), strDump, strAscii);
                fflush(stdout);
                memset(strDump, 0, 64);
                memset(strAscii, 0, 32);
            }
        }

        if (((size - 1) & 0x0F) != 0x0F) {
            for(idx = strlen(strDump) ; idx < 52; idx++) {
                strDump[idx] = 0x20;
            }
            fprintf(stdout, "%16s <0x%04X> %s%s\n", "", (size & 0xFFF0), strDump, strAscii);
            fflush(stdout);
        }

        fprintf(stdout, "\n");
        fflush(stdout);
    }
}

static char isRun = 0;

void sig_handler(int sig)
{
    sigset_t sigset;

    lDbg("Called %s()", __FUNCTION__);

    if (sigprocmask(SIG_BLOCK, &sigset, NULL) < 0) {
        lWrn("sigprocmask %s(%d) error \n", strsignal(sig), sig);
    }

    switch(sig) {
    case SIGHUP   :
    case SIGTSTP  :
    case SIGWINCH :
    case SIGSTOP  :
        lDbg("%s() Ignore signal = %s(%d)", __FUNCTION__, strsignal(sig), sig);
        break;
    default      :
        lWrn("%s() Quit...Received signal = %s(%d)", __FUNCTION__, strsignal(sig), sig);
        isRun = 0;
        break;
    }
}

void registerSignals(void)
{
    int idx = 0;
    struct sigaction sigact;

    /* Set up the structure to specify the new action. */
    memset(&sigact, 0, sizeof(struct sigaction));
    sigact.sa_handler = sig_handler;

    sigemptyset (&sigact.sa_mask);
    sigact.sa_flags = sigact.sa_flags | SA_RESETHAND;

    for (idx = SIGHUP; idx < SIGRTMAX; idx++) {
        switch(idx) {
        case SIGHUP   :
        case SIGTSTP  :
        case SIGWINCH :
        case SIGSTOP  :
            lDbg("Ignore signal = %s(%d)", strsignal(idx), idx);
            break;
        default      :
            sigaction(idx, &sigact, NULL);
            break;
        }
    }
}

int socketSetReuseaddr(int sock)
{
    int ret = 0,
        val = 0;

    if (sock == -1) {
        lWrn("socket file descriptor invalid!!!");
        ret = -EINVAL;
    }
    else {
        val = 1;
        ret = setsockopt(sock,
                         SOL_SOCKET,
                         SO_REUSEADDR,
                         (const void *)&val,
                         (socklen_t)sizeof(val));
        if (ret == -1) {
            lErr("setsockopt( , SOL_SOCKET, SO_REUSEADDR, ...) failed...");
            ret = -EFAULT;
        }
    }

    return ret;
}

int socketSetLinger(int sock)
{
    int ret = 0;

    struct linger sl = { .l_onoff = 0, .l_linger = 0, };

    if (sock == -1) {
        lWrn("socket file descriptor invalid!!!");
        ret = -EINVAL;
    }
    else {
        sl.l_onoff  = 1;
        sl.l_linger = 0;

        ret = setsockopt(sock,
                         SOL_SOCKET,
                         SO_LINGER,
                         (const void *)&sl,
                         (socklen_t)sizeof(struct linger));
        if (ret == -1) {
            lErr("setsockopt( , SOL_SOCKET, SO_LINGER, ...) failed...");
            ret = -EFAULT;
        }
    }

    return ret;
}
#if defined(SOCKET_IPV6)
int udpSocket(void)
{
    int sockFd = -1;

    sockFd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
    if (sockFd == -1) {
        lErr("socket() failed...");
    }
    else {
        socketSetReuseaddr(sockFd);
        socketSetLinger(sockFd);
    }

    return sockFd;
}

int udpSocketReceive(int sock)
{
    int ret  = 0,
        port = 0;

    socklen_t lSock = 0;

    struct sockaddr_in6 sa;

    char addr[64] = {"\0"};
    char msg[256]   = {"\0"};
    char packet[SOCK_PACKET_SIZE] = { 0, };

    struct timespec tsReal = { .tv_sec = 0, };
    struct tm tmLt;
    char strLt[128]   = {"\0"};

    if (sock == -1) {
        lWrn("Socket file descriptor invalid");
        ret = -EINVAL;
    }
    else {
        clock_gettime(CLOCK_REALTIME, &tsReal);

        localtime_r(&tsReal.tv_sec, &tmLt);
        strftime(strLt, 128, "%Y/%m/%d %H:%M:%S", &tmLt);

        memset(&sa, 0, sizeof(struct sockaddr_in6));
        lSock = (socklen_t)sizeof(struct sockaddr_in6);

        ret = recvfrom(sock,
                       packet,
                       SOCK_PACKET_SIZE,
                       MSG_DONTWAIT,
                       (struct sockaddr *)&sa,
                       &lSock);
        if (ret > 0) {
            port = ntohs(sa.sin6_port);
            inet_ntop(AF_INET6, &sa.sin6_addr, addr, (socklen_t)sizeof(struct sockaddr_in6));

            snprintf(msg, 256, "%s.%d Recvfrom Server%s(%d)", strLt, (int)(tsReal.tv_nsec / 1000), addr, port);
            hexdump(msg, packet, ret);
        }
        else {
            lWrn("%s.%d recvfrom()...%d", strLt, (int)(tsReal.tv_nsec / 1000), ret);
        }
    }

    return ret;
}
#else
int udpSocket(void)
{
    int sockFd = -1;

    sockFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sockFd == -1) {
        lErr("socket() failed...");
    }
    else {
        socketSetReuseaddr(sockFd);
        socketSetLinger(sockFd);
    }

    return sockFd;
}

int udpSocketReceive(int sock)
{
    int ret  = 0,
        port = 0;

    socklen_t lSock = 0;

    struct sockaddr_in sa;

    struct timespec tsReal = { .tv_sec = 0, };
    struct tm tmLt;
    char strLt[128]   = {"\0"};

    char addr[64] = {"\0"};
    char msg[256]   = {"\0"};
    char packet[SOCK_PACKET_SIZE] = { 0, };

    if (sock == -1) {
        lWrn("Socket file descriptor invalid");
        ret = -EINVAL;
    }
    else {
        clock_gettime(CLOCK_REALTIME, &tsReal);

        localtime_r(&tsReal.tv_sec, &tmLt);
        strftime(strLt, 128, "%Y/%m/%d %H:%M:%S", &tmLt);


        memset(&sa, 0, sizeof(struct sockaddr_in));
        lSock = (socklen_t)sizeof(struct sockaddr_in);

        ret = recvfrom(sock,
                       packet,
                       SOCK_PACKET_SIZE,
                       MSG_DONTWAIT,
                       (struct sockaddr *)&sa,
                       &lSock);
        if (ret > 0) {
            port = ntohs(sa.sin_port);
            inet_ntop(AF_INET, &sa.sin_addr, addr, (socklen_t)sizeof(struct sockaddr_in));

            snprintf(msg, 256, "%s.%d Recvfrom Server%s(%d)", strLt, (int)(tsReal.tv_nsec / 1000), addr, port);
            hexdump(msg, packet, ret);
        }
        else {
            lWrn("recvfrom()...%d", ret);
        }
    }

    return ret;
}
#endif /* defined(SOCKET_IPV6) */

#define HOUR2SEC   (60 * 60)
#define DAY2SEC    (HOUR2SEC * 24)
int makeMessage(char *msg, size_t szMax)
{
    int ret  = 0,
        days = 0;

    struct timespec tsReal = { .tv_sec = 0, };
    struct timespec tsMono = { .tv_sec = 0, };

    struct tm tmLt,
              tmUt;

    char strLt[128]   = {"\0"};
    char strUt[128]   = {"\0"};

    if (msg == NULL) {
        lWrn("Message buffer is null!!!");
        ret = -EINVAL;
    }
    else if (szMax < 8) {
        lWrn("Message buffer size not enough!!!");
        ret = -EINVAL;
    }
    else {
        clock_gettime(CLOCK_MONOTONIC_RAW, &tsMono);
        clock_gettime(CLOCK_REALTIME, &tsReal);

        localtime_r(&tsReal.tv_sec, &tmLt);
        strftime(strLt, 128, "%Y/%m/%d(WoY=%U, %a[%u, %A]) %H:%M:%S %z(%Z)", &tmLt);

        gmtime_r(&tsMono.tv_sec, &tmUt);
        days = (int)(tsMono.tv_sec / DAY2SEC);

        snprintf(strUt, 128, "%d Days %2d:%2d:%2d.%d",
                 days,
                 tmUt.tm_hour,
                 tmUt.tm_min,
                 tmUt.tm_sec,
                 (int)(tsMono.tv_nsec / 1000) );

        ret = snprintf(msg,
                      szMax,
                      "Hello Server, Client time is %s(%d us), Uptime=%s",
                      strLt,
                      (int)(tsReal.tv_nsec / 1000),
                      strUt);

    }

    return ret;
}

int udpClient(const char *server, int port)
{
    int sock = -1,
        idx  = 0,
        ret  = 0;

    int cntSnd  = 0,
        cntRcv  = 0,
        cntLoss = 0,
        cntFail = 0;

    size_t size = 0;

    double itv = 0.0;

    fd_set rfds,
           efds;

    struct timeval tv;
#if defined(SOCKET_IPV6)
    struct sockaddr_in6 sa;
#else
    struct sockaddr_in sa;
#endif /* defined(SOCKET_IPV6) */

    char msg[256]   = {"\0"};
    char packet[SOCK_PACKET_SIZE] = { 0, };

    struct timespec tsReal = { .tv_sec = 0, };
    struct timespec tsSnd = { .tv_sec = 0, };
    struct timespec tsRcv = { .tv_sec = 0, };
    struct tm  stTM;
    char strTime[128] = {"\0"};

    lDbg("%s() UDP Client Start!!!", __FUNCTION__);

#if defined(SOCKET_IPV6)
    memset(&sa, 0, sizeof(struct sockaddr_in6));
    sa.sin6_family = AF_INET6;
    sa.sin6_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET6, server, &sa.sin6_addr) != 1) {
        lErr("inet_pton(%s) failed...", server);
        isRun = 0;
        ret = -EFAULT;
    }
#else
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons((uint16_t)port);
    if (inet_pton(AF_INET, server, &sa.sin_addr) != 1) {
        lErr("inet_pton(%s) failed...", server);
        isRun = 0;
        ret = -EFAULT;
    }
#endif

    while(isRun) {
        sock = udpSocket();
        if (sock == -1) {
            lWrn("udpSocket() failed");
            isRun = 0;
            break;
        }

        size = (size_t)makeMessage(packet, SOCK_PACKET_SIZE);
        if (size > 0) {
            clock_gettime(CLOCK_MONOTONIC_RAW, &tsSnd);
            clock_gettime(CLOCK_REALTIME, &tsReal);

            localtime_r(&tsReal.tv_sec, &stTM);
            strftime(strTime, 128, "%Y/%m/%d %H:%M:%S", &stTM);

            idx = 0;
            do {
            #if defined(SOCKET_IPV6)
                ret = sendto(sock,
                             packet,
                             size,
                             MSG_NOSIGNAL,
                             (const struct sockaddr *)&sa,
                             (socklen_t)sizeof(struct sockaddr_in6));
            #else
                ret = sendto(sock,
                             packet,
                             size,
                             MSG_NOSIGNAL,
                             (const struct sockaddr *)&sa,
                             (socklen_t)sizeof(struct sockaddr_in));
            #endif
                usleep(5000);
            } while ((ret >= 0) && (++idx < 1));

            if (ret == -1) {
                cntFail = cntFail + 1;
                lErr("%s.%d sendto %s(%d) failed...", strTime, (int)(tsReal.tv_nsec / 1000), server, port);
            }
            else {
                cntSnd = cntSnd + 1;
                snprintf(msg, 256, "%s.%d sendto %s(%d)...%d", strTime, (int)(tsReal.tv_nsec / 1000), server, port, ret);
                hexdump(msg, packet, ret);

                FD_ZERO(&rfds);
                FD_ZERO(&efds);

                // Timeout 5 second
                tv.tv_sec  = 5;
                tv.tv_usec = 0;

                FD_SET(sock, &rfds);
                FD_SET(sock, &efds);

                ret = select(sock + 1, &rfds, NULL, &efds, &tv);
                if (ret == -1) {
                    lErr("select() failed...");
                    break;
                }
                else if (ret) {
                    if (FD_ISSET(sock, &efds)) {
                        lWrn("Exception...");
                    }

                    if (FD_ISSET(sock, &rfds)) {
                        clock_gettime(CLOCK_MONOTONIC_RAW, &tsRcv);

                        if (udpSocketReceive(sock) > 0) {
                            cntRcv = cntRcv + 1;

                            itv = (tsRcv.tv_nsec < tsSnd.tv_nsec)
                                    ?  (double)(tsRcv.tv_sec - (tsSnd.tv_sec + 1))
                                      + ((double)((1000000000 + tsRcv.tv_nsec) - tsSnd.tv_nsec) / 1000000000)
                                    : (double)(tsRcv.tv_sec - tsSnd.tv_sec)
                                      + ((double)(tsRcv.tv_nsec - tsSnd.tv_nsec) / 1000000000);

                            cntLoss = cntSnd - cntRcv;
                            lDbg("Respond Interval=%.6lf, snd=%d, rcv=%d, loss=%d", itv, cntSnd, cntRcv, cntLoss);

                        }
                    }
                }
                else {
                    clock_gettime(CLOCK_MONOTONIC_RAW, &tsRcv);

                    itv = (tsRcv.tv_nsec < tsSnd.tv_nsec)
                          ?  (double)(tsRcv.tv_sec - (tsSnd.tv_sec + 1))
                            + ((double)((1000000000 + tsRcv.tv_nsec) - tsSnd.tv_nsec) / 1000000000)
                          : (double)(tsRcv.tv_sec - tsSnd.tv_sec)
                            + ((double)(tsRcv.tv_nsec - tsSnd.tv_nsec) / 1000000000);

                    cntLoss = cntSnd - cntRcv;
                    lWrn("Respond Timeout(%.6lf) snd=%d, rcv=%d, loss=%d", itv, cntSnd, cntRcv, cntLoss);
                }
            }
        }

        close(sock);
        sock = -1;
    }

    if (sock != -1) {
        close(sock);
    }

    cntLoss = cntSnd - cntRcv;
    lDbg("%s() UDP Client finish Count(SND=%d, RCV=%d, Loss=%d, Fail=%d)!!!", __FUNCTION__, cntSnd, cntRcv, cntLoss, cntFail);

    return ret;
}

void usage(const char *app)
{
    lWrn("Usage : %s [Server IP Address] [Server Listen port]", app);
}

int main(int argc, char **argv)
{
    int port = 0;

    isRun = 1;

    if (argc < 3) {
        usage(argv[0]);
    }
    else {
        port = strtol(argv[2], NULL, 10);

        registerSignals();

        udpClient(argv[1], port);
    }

    return 0;
}

