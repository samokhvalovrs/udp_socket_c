#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define UDP_PORT 9999 // predefined port numbers
#define MAXSIZE 8192

// actual use of the port number
int g_udp_port = UDP_PORT;

// function for echoing
void echo_fn(int sockfd);

void set_socket_option(int socket, uint8_t ip_ttl)
{
    /* Set socket options : timeout, IPTTL, IP_RECVTTL, IP_RECVTOS */
    uint8_t One = 1;
    int result;

    /* Set IPTTL value to twamp standard: 255 */
#ifdef IP_TTL
    result = setsockopt(socket, IPPROTO_IP, IP_TTL, &ip_ttl, sizeof(ip_ttl));
    if (result != 0)
    {
        fprintf(stderr, "[PROBLEM] Cannot set the TTL value for emission.\n");
    }
#else
    fprintf(stderr,
            "No way to set the TTL value for leaving packets on that platform.\n");
#endif

    /* Set receive IP_TTL option */
#ifdef IP_RECVTTL
    result = setsockopt(socket, IPPROTO_IP, IP_RECVTTL, &One, sizeof(One));
    if (result != 0)
    {
        fprintf(stderr,
                "[PROBLEM] Cannot set the socket option for TTL reception.\n");
    }
#else
    fprintf(stderr,
            "No way to ask for the TTL of incoming packets on that platform.\n");
#endif

    /* Set receive IP_TOS option */
#ifdef IP_RECVTOS
    result = setsockopt(socket, IPPROTO_IP, IP_RECVTOS, &One, sizeof(One));
    if (result != 0)
    {
        fprintf(stderr,
                "[PROBLEM] Cannot set the socket option for TOS reception.\n");
    }
#else
    fprintf(stderr,
            "No way to ask for the TOS of incoming packets on that platform.\n");
#endif

    int yes = 1;
    result = setsockopt(socket, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &yes, sizeof(yes));
    if (result != 0)
    {
        printf("error IPV6_RECVHOPLIMIT: %s\n", strerror(errno));
        fprintf(stderr,
                "[PROBLEM] Cannot set the socket option for TTL reception.\n");
    }
    result = setsockopt(socket, IPPROTO_IPV6, IPV6_RECVTCLASS, &yes, sizeof(yes));
    if (result != 0)
    {
        printf("error IPV6_RECVTCLASS: %s\n", strerror(errno));
        fprintf(stderr,
                "[PROBLEM] Cannot set the socket option for TTL reception.\n");
    }
}

int main(int argc, char *argv[])
{
    int sockfd;               // socket descriptor
    struct sockaddr_in6 addr; // address configuration for IPv6 over UDP

    if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
    {
        printf("Error in socket\n");
        return -1;
    }

    bzero(&addr, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(UDP_PORT);
    addr.sin6_addr = in6addr_any;

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) == -1)
    {
        printf("Error in binding\n");
        return -1;
    }

    set_socket_option(sockfd, 255);

    echo_fn(sockfd); // call the function echo

    close(sockfd); // Close the socket

    return -1;
}

// function for echoing
void echo_fn(int sockfd)
{
    char data[MAXSIZE];
    int n = 0;
    socklen_t len = sizeof(struct sockaddr_in6);
    struct sockaddr_in6 addr;

    while (1)
    {
        printf("Waiting for data...\n");

        struct msghdr *message = malloc(sizeof(struct msghdr));
        struct cmsghdr *c_msg;
        char *control_buffer = malloc(MAXSIZE);
        uint16_t control_length = MAXSIZE;
        struct sockaddr_in6 addr6;
        socklen_t len = sizeof(addr6);

        memset(message, 0, sizeof(*message));
        message->msg_name = (void *)&addr6;
        message->msg_namelen = len;
        message->msg_iov = malloc(sizeof(struct iovec));
        message->msg_iov->iov_base = data;
        message->msg_iov->iov_len = MAXSIZE;
        message->msg_iovlen = 1;
        /* Message control does not exist on every system. For instance, HP Tru64
         * does not have it */
        message->msg_control = control_buffer;
        message->msg_controllen = control_length;

        int rv = recvmsg(sockfd, message, 0);

        char str_server[INET6_ADDRSTRLEN]; /* String for Client IP address */

        inet_ntop(AF_INET6, (void *)&(addr6.sin6_addr), str_server, sizeof(str_server));

        printf("recved: %d from %s\n", rv, str_server);

        if (rv <= 0)
        {
            fprintf(stderr, "[%s] ", str_server);
            perror("Failed to receive TWAMP-Test packet");
            return;
        }

        uint8_t fw_ttl = 0;
        uint8_t fw_tos = 0;

        for (c_msg = CMSG_FIRSTHDR(message); c_msg;
             c_msg = (CMSG_NXTHDR(message, c_msg)))
        {
            printf("msg level %i and type %i\n", c_msg->cmsg_level, c_msg->cmsg_type);
            if ((c_msg->cmsg_level == IPPROTO_IP && c_msg->cmsg_type == IP_TTL) || (c_msg->cmsg_level == IPPROTO_IPV6 && c_msg->cmsg_type == IPV6_HOPLIMIT))
            {
                fw_ttl = *(int *)CMSG_DATA(c_msg);
            }
            else if (c_msg->cmsg_level == IPPROTO_IP && c_msg->cmsg_type == IP_TOS)
            {
                fw_tos = *(int *)CMSG_DATA(c_msg);
            }
            else if (c_msg->cmsg_level == IPPROTO_IPV6 && c_msg->cmsg_type == IPV6_TCLASS )
            {
                fw_tos = *(int *)CMSG_DATA(c_msg);
            }
            else
                {
                    fprintf(stderr,
                            "\tWarning, unexpected data of level %i and type %i\n",
                            c_msg->cmsg_level, c_msg->cmsg_type);
                }
        }

        printf("hoplimit = %d, tc = %d\n", fw_ttl, fw_tos);
        /*// accepted from the client to the data
        if ((n = recvfrom(sockfd, data, MAXSIZE, 0, (struct sockaddr *)&addr, &len)) == -1)
        {
            printf("Error in receiving\n");
            exit(-1);
        }
        //data[n] = '\0';
        printf("Received data: %d\n", n);
        // IPv6 address is stored with "colon hexadecimal notation" representation
        char buf_addr[40];
        // IPv6 address to "colon hexadecimal notation" (colon hexadecimal notation) represent
        inet_ntop(AF_INET6, &addr.sin6_addr, buf_addr, 64);

        printf("Client ip: %s\n", buf_addr);
        printf("Client port: %d\n", ntohs(addr.sin6_port));
        printf("\n");
        // data is received and then sent back
        //sendto(sockfd, data, n, 0, (struct sockaddr *)&addr, len);
*/
    }
}
