// Decode the public libproc layout with the SDK's native C declarations.
#include <arpa/inet.h>
#include <libproc.h>
#include <stdint.h>
#include <string.h>
#include <sys/proc_info.h>

struct tcptui_socket {
    uint64_t generation;
    uint8_t local[16];
    uint8_t remote[16];
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t family;
    uint8_t protocol;
    uint8_t state;
    uint8_t reserved;
};

int tcptui_socket_info(int pid, int fd, struct tcptui_socket *out)
{
    struct socket_fdinfo socket;
    const int size = (int)sizeof(socket);
    if (proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &socket, size) != size)
        return 0;

    const struct socket_info *info = &socket.psi;
    const struct in_sockinfo *addresses;
    if (info->soi_kind == SOCKINFO_TCP && info->soi_protocol == IPPROTO_TCP) {
        addresses = &info->soi_proto.pri_tcp.tcpsi_ini;
        out->protocol = IPPROTO_TCP;
        out->state = info->soi_proto.pri_tcp.tcpsi_state;
    } else if (info->soi_kind == SOCKINFO_IN && info->soi_protocol == IPPROTO_UDP) {
        addresses = &info->soi_proto.pri_in;
        out->protocol = IPPROTO_UDP;
    } else {
        return 0;
    }

    if (info->soi_family == AF_INET) {
        out->family = 4;
        memcpy(out->local, &addresses->insi_laddr.ina_46.i46a_addr4, 4);
        memcpy(out->remote, &addresses->insi_faddr.ina_46.i46a_addr4, 4);
    } else if (info->soi_family == AF_INET6) {
        out->family = 6;
        memcpy(out->local, &addresses->insi_laddr.ina_6, 16);
        memcpy(out->remote, &addresses->insi_faddr.ina_6, 16);
    } else {
        return 0;
    }
    out->generation = addresses->insi_gencnt;
    out->local_port = ntohs((uint16_t)addresses->insi_lport);
    out->remote_port = ntohs((uint16_t)addresses->insi_fport);
    return 1;
}
