/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "context.h"

#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#if HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#if HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#if HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif

#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

#include "arp-nd.h"
#include "event.h"
#include "gtp-path.h"
#include "pfcp-path.h"
#include "rule-match.h"

#define UPF_GTP_HANDLED     1

#define ENB_GTP_IP "127.0.1.1"
#define ENB_GTP_IP_2 "127.0.1.2"
static int gtp_fd;
static int tun_fd;

const uint8_t proxy_mac_addr[] = { 0x0e, 0x00, 0x00, 0x00, 0x00, 0x01 };

static ogs_pkbuf_pool_t *packet_pool = NULL;

static void upf_gtp_handle_multicast(ogs_pkbuf_t *recvbuf);

static int check_framed_routes(upf_sess_t *sess, int family, uint32_t *addr)
{
    int i = 0;
    ogs_ipsubnet_t *routes = family == AF_INET ?
        sess->ipv4_framed_routes : sess->ipv6_framed_routes;

    if (!routes)
        return false;

    for (i = 0; i < OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI; i++) {
        uint32_t *sub = routes[i].sub;
        uint32_t *mask = routes[i].mask;

        if (!routes[i].family)
            break;

        if (family == AF_INET) {
            if (sub[0] == (addr[0] & mask[0]))
                return true;
        } else {
            if (sub[0] == (addr[0] & mask[0]) &&
                sub[1] == (addr[1] & mask[1]) &&
                sub[2] == (addr[2] & mask[2]) &&
                sub[3] == (addr[3] & mask[3]))
                return true;
        }
    }
    return false;
}

static uint16_t _get_eth_type(uint8_t *data, uint len) {
    if (len > ETHER_HDR_LEN) {
        struct ether_header *hdr = (struct ether_header*)data;
        return htobe16(hdr->ether_type);
    }
    return 0;
}

static void _gtpv1_tun_recv_common_cb(
        short when, ogs_socket_t fd, bool has_eth, void *data)
{
    ogs_pkbuf_t *recvbuf = NULL;

    upf_sess_t *sess = NULL;
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_pdr_t *fallback_pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_user_plane_report_t report;
    int i;

    recvbuf = ogs_tun_read(fd, packet_pool);
    if (!recvbuf) {
        ogs_warn("ogs_tun_read() failed");
        return;
    }

    if (has_eth) {
        ogs_pkbuf_t *replybuf = NULL;
        uint16_t eth_type = _get_eth_type(recvbuf->data, recvbuf->len);
        uint8_t size;

        if (eth_type == ETHERTYPE_ARP) {
            if (is_arp_req(recvbuf->data, recvbuf->len) &&
                    upf_sess_find_by_ipv4(
                        arp_parse_target_addr(recvbuf->data, recvbuf->len))) {
                replybuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
                ogs_assert(replybuf);
                ogs_pkbuf_reserve(replybuf, OGS_TUN_MAX_HEADROOM);
                ogs_pkbuf_put(replybuf, OGS_MAX_PKT_LEN-OGS_TUN_MAX_HEADROOM);
                size = arp_reply(replybuf->data, recvbuf->data, recvbuf->len,
                    proxy_mac_addr);
                ogs_pkbuf_trim(replybuf, size);
                ogs_info("[SEND] reply to ARP request: %u", size);
            } else {
                goto cleanup;
            }
        } else if (eth_type == ETHERTYPE_IPV6 &&
                    is_nd_req(recvbuf->data, recvbuf->len)) {
            replybuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
            ogs_assert(replybuf);
            ogs_pkbuf_reserve(replybuf, OGS_TUN_MAX_HEADROOM);
            ogs_pkbuf_put(replybuf, OGS_MAX_PKT_LEN-OGS_TUN_MAX_HEADROOM);
            size = nd_reply(replybuf->data, recvbuf->data, recvbuf->len,
                proxy_mac_addr);
            ogs_pkbuf_trim(replybuf, size);
            ogs_info("[SEND] reply to ND solicit: %u", size);
        }
        if (replybuf) {
            if (ogs_tun_write(fd, replybuf) != OGS_OK)
                ogs_warn("ogs_tun_write() for reply failed");
            
            ogs_pkbuf_free(replybuf);
            goto cleanup;
        }
        if (eth_type != ETHERTYPE_IP && eth_type != ETHERTYPE_IPV6) {
            ogs_error("[DROP] Invalid eth_type [%x]]", eth_type);
            ogs_log_hexdump(OGS_LOG_ERROR, recvbuf->data, recvbuf->len);
            goto cleanup;
        }
        ogs_pkbuf_pull(recvbuf, ETHER_HDR_LEN);
    }

    ogs_gtp2_header_t mod_gtp_hdesc;
    ogs_gtp2_extension_header_t mod_ext_hdesc;

    memset(&mod_gtp_hdesc, 0, sizeof(mod_gtp_hdesc));
    memset(&mod_ext_hdesc, 0, sizeof(mod_ext_hdesc));

    mod_gtp_hdesc.flags = 0; // should just be zero
    mod_gtp_hdesc.type = 255; // G-PDU -- 255
    mod_gtp_hdesc.teid = 1; // TODO - how to pick TEID? for now, just implement and see how srsenb responds... It looks like 1 is used pretty often for SGWU?

    ogs_gtp2_fill_header(&mod_gtp_hdesc, &mod_ext_hdesc, recvbuf);

    // ogs_info("----------> [DL] PKBUF after ogs_gtp2_fill_header in bypass branch");
    // ogs_log_hexdump(OGS_LOG_ERROR, recvbuf->data, recvbuf->len);

    // Then, need to send it to the right sock addr
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(2152);
    ogs_info("-----------> OK, i'm hitting the right branch.");
    if (inet_pton(AF_INET, ENB_GTP_IP_2, &dst_addr.sin_addr) <= 0) {
        ogs_error("----------> [DL] Couldn't build sockaddr for sendto() in bypass branch");
        goto cleanup;
    }

    // I'm not sure what FD to use -- I assume the GTP Server is appropriate, but I see both 14 and 15 used often
    ssize_t sent = sendto(gtp_fd, recvbuf->data, recvbuf->len, 0, (const struct sockaddr *)&dst_addr, sizeof(dst_addr));

    if (sent < 0 || sent != recvbuf->len) {
        if (ogs_socket_errno != OGS_EAGAIN) {
            int err = ogs_socket_errno;
            ogs_log_message(OGS_LOG_ERROR, err,
                    "sendto(%u, %p, %u, 0, ...) failed",
                    gtp_fd, recvbuf->data, recvbuf->len);
        }
    }
    
    ogs_pkbuf_free(recvbuf);
    return;
}

static void _gtpv1_tun_recv_cb(short when, ogs_socket_t fd, void *data)
{
    _gtpv1_tun_recv_common_cb(when, fd, false, data);
}

static void _gtpv1_tun_recv_eth_cb(short when, ogs_socket_t fd, void *data)
{
    _gtpv1_tun_recv_common_cb(when, fd, true, data);
}

static void _gtpv1_u_recv_cb(short when, ogs_socket_t fd, void *data)
{
    int len;
    ssize_t size;
    char buf1[OGS_ADDRSTRLEN];
    char buf2[OGS_ADDRSTRLEN];

    upf_sess_t *sess = NULL;

    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sock_t *sock = NULL;
    ogs_sockaddr_t from;

    ogs_gtp2_header_t *gtp_h = NULL;
    ogs_gtp2_header_desc_t header_desc;
    ogs_pfcp_user_plane_report_t report;

    ogs_assert(fd != INVALID_SOCKET);
    sock = data;
    ogs_assert(sock);

    pkbuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_TUN_MAX_HEADROOM);
    ogs_pkbuf_put(pkbuf, OGS_MAX_PKT_LEN-OGS_TUN_MAX_HEADROOM);

    size = ogs_recvfrom(fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "ogs_recv() failed");
        goto cleanup;
    }

    ogs_pkbuf_trim(pkbuf, size);

    ogs_assert(pkbuf);
    ogs_assert(pkbuf->len);

    gtp_h = (ogs_gtp2_header_t *)pkbuf->data;
    if (gtp_h->version != OGS_GTP2_VERSION_1) {
        ogs_error("[DROP] Invalid GTPU version [%d]", gtp_h->version);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }

    len = ogs_gtpu_parse_header(&header_desc, pkbuf);
    if (len < 0) {
        ogs_error("[DROP] Cannot decode GTPU packet");
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }
    if (header_desc.type == OGS_GTPU_MSGTYPE_ECHO_REQ) {
        ogs_pkbuf_t *echo_rsp;

        ogs_debug("[RECV] Echo Request from [%s]", OGS_ADDR(&from, buf1));
        echo_rsp = ogs_gtp2_handle_echo_req(pkbuf);
        ogs_expect(echo_rsp);
        if (echo_rsp) {
            ssize_t sent;

            /* Echo reply */
            ogs_debug("[SEND] Echo Response to [%s]", OGS_ADDR(&from, buf1));

            sent = ogs_sendto(fd, echo_rsp->data, echo_rsp->len, 0, &from);
            if (sent < 0 || sent != echo_rsp->len) {
                ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                        "ogs_sendto() failed");
            }
            ogs_pkbuf_free(echo_rsp);
        }
        goto cleanup;
    }
    if (header_desc.type != OGS_GTPU_MSGTYPE_END_MARKER &&
        pkbuf->len <= len) {
        ogs_error("[DROP] Small GTPU packet(type:%d len:%d)",
                header_desc.type, len);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }

    ogs_trace("[RECV] GPU-U Type [%d] from [%s] : TEID[0x%x]",
            header_desc.type, OGS_ADDR(&from, buf1), header_desc.teid);

    /* Remove GTP header and send packets to TUN interface */
    ogs_assert(ogs_pkbuf_pull(pkbuf, len));

    if (header_desc.type == OGS_GTPU_MSGTYPE_END_MARKER) {
        /* Nothing */

    } else if (header_desc.type == OGS_GTPU_MSGTYPE_ERR_IND) {
        ogs_pfcp_far_t *far = NULL;

        far = ogs_pfcp_far_find_by_gtpu_error_indication(pkbuf);
        if (far) {
            ogs_assert(true ==
                ogs_pfcp_up_handle_error_indication(far, &report));

            if (report.type.error_indication_report) {
                ogs_assert(far->sess);
                sess = UPF_SESS(far->sess);
                ogs_assert(sess);

                ogs_assert(OGS_OK ==
                    upf_pfcp_send_session_report_request(sess, &report));
            }

        } else {
            ogs_error("[DROP] Cannot find FAR by Error-Indication");
            ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        }
    } else if (header_desc.type == OGS_GTPU_MSGTYPE_GPDU) {
        uint16_t eth_type = 0;
        struct ip *ip_h = NULL;
        uint32_t *src_addr = NULL;
        ogs_pfcp_object_t *pfcp_object = NULL;
        ogs_pfcp_sess_t *pfcp_sess = NULL;
        ogs_pfcp_pdr_t *pdr = NULL;
        ogs_pfcp_far_t *far = NULL;

        ogs_pfcp_subnet_t *subnet = NULL;
        ogs_pfcp_dev_t *dev = NULL;
        int i;

        ip_h = (struct ip *)pkbuf->data;
        ogs_assert(ip_h);

        /*
         * Issue #2210, Discussion #2208, #2209
         *
         * Metrics reduce data plane performance.
         * It should not be used on the UPF/SGW-U data plane
         * until this issue is resolved.
         */
#if 0
        upf_metrics_inst_global_inc(UPF_METR_GLOB_CTR_GTP_INDATAPKTN3UPF);
        upf_metrics_inst_by_qfi_add(header_desc.qos_flow_identifier,
                UPF_METR_CTR_GTP_INDATAVOLUMEQOSLEVELN3UPF, pkbuf->len);
#endif

        // ogs_info("Packet received direct from eNB [IP version:%d, Packet Length:%d]",
        //     ip_h->ip_v, pkbuf->len);
        // ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        
        int tun_success = ogs_tun_write(tun_fd, pkbuf);
    
        ogs_info("---------> tun write success? %u", tun_success == OGS_OK);

        goto cleanup;

    } else {
        ogs_error("[DROP] Invalid GTPU Type [%d]", header_desc.type);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
    }

cleanup:
    ogs_pkbuf_free(pkbuf);
}

int upf_gtp_init(void)
{
    ogs_pkbuf_config_t config;
    memset(&config, 0, sizeof config);

    config.cluster_2048_pool = ogs_app()->pool.packet;

#if OGS_USE_TALLOC == 1
    /* allocate a talloc pool for GTP to ensure it doesn't have to go back
     * to the libc malloc all the time */
    packet_pool = talloc_pool(__ogs_talloc_core, 1000*1024);
    ogs_assert(packet_pool);
#else
    packet_pool = ogs_pkbuf_pool_create(&config);
#endif

    return OGS_OK;
}

void upf_gtp_final(void)
{
    ogs_pkbuf_pool_destroy(packet_pool);
}

static void _get_dev_mac_addr(char *ifname, uint8_t *mac_addr)
{
#ifdef SIOCGIFHWADDR
    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    ogs_assert(fd);
    struct ifreq req;
    memset(&req, 0, sizeof(req));
    ogs_cpystrn(req.ifr_name, ifname, IF_NAMESIZE-1);
    ogs_assert(ioctl(fd, SIOCGIFHWADDR, &req) == 0);
    memcpy(mac_addr, req.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
#else
    struct ifaddrs *ifap;
    ogs_assert(getifaddrs(&ifap) == 0);
    struct ifaddrs *p;
    for (p = ifap; p; p = p->ifa_next) {
        if (strncmp(ifname, p->ifa_name, IF_NAMESIZE-1) == 0) {
            struct sockaddr_dl* sdp = (struct sockaddr_dl*) p->ifa_addr;
            memcpy(mac_addr, sdp->sdl_data + sdp->sdl_nlen, ETHER_ADDR_LEN);
            freeifaddrs(ifap);
            return;
        }
    }
    ogs_assert(0); /* interface not found. */
#endif
}

int upf_gtp_open(void)
{
    ogs_pfcp_dev_t *dev = NULL;
    ogs_pfcp_subnet_t *subnet = NULL;
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;
    int rc;

    ogs_info("--------> gtp open called");
    ogs_list_for_each(&ogs_gtp_self()->gtpu_list, node) {
	sock = ogs_gtp_server(node);
        if (!sock) return OGS_ERROR;

        if (sock->family == AF_INET)
            ogs_gtp_self()->gtpu_sock = sock;
        else if (sock->family == AF_INET6)
            ogs_gtp_self()->gtpu_sock6 = sock;

        node->poll = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, _gtpv1_u_recv_cb, sock);
        ogs_info("----------> sock->fd after ogs_tun_open: %u", sock->fd);
        gtp_fd = sock->fd;
        ogs_info("----------> gtp_fd is now: %u", gtp_fd);
        ogs_assert(node->poll);
    }


    OGS_SETUP_GTPU_SERVER;

    /* NOTE : tun device can be created via following command.
     *
     * $ sudo ip tuntap add name ogstun mode tun
     *
     * Also, before running upf, assign the one IP from IP pool of UE
     * to ogstun. The IP should not be assigned to UE
     *
     * $ sudo ifconfig ogstun 45.45.0.1/16 up
     *
     */

    /* Open Tun interface */
    ogs_list_for_each(&ogs_pfcp_self()->dev_list, dev) {
        ogs_info("----------> testing testing");
	    
	dev->is_tap = strstr(dev->ifname, "tap");
        dev->fd = ogs_tun_open(dev->ifname, OGS_MAX_IFNAME_LEN, dev->is_tap);
        if (dev->fd == INVALID_SOCKET) {
            ogs_error("tun_open(dev:%s) failed", dev->ifname);
            return OGS_ERROR;
        }
	ogs_info("----------> dev->fd after ogs_tun_open: %u", dev->fd);
	tun_fd = dev->fd;
	ogs_info("----------> tun_fd is now: %u", tun_fd);

        if (dev->is_tap) {
            _get_dev_mac_addr(dev->ifname, dev->mac_addr);
            dev->poll = ogs_pollset_add(ogs_app()->pollset,
                    OGS_POLLIN, dev->fd, _gtpv1_tun_recv_eth_cb, NULL);
            ogs_assert(dev->poll);
        } else {
            dev->poll = ogs_pollset_add(ogs_app()->pollset,
                    OGS_POLLIN, dev->fd, _gtpv1_tun_recv_cb, NULL);
            ogs_assert(dev->poll);
        }

        ogs_assert(dev->poll);
    }

    /*
     * On Linux, it is possible to create a persistent tun/tap
     * interface which will continue to exist even if open5gs quit,
     * although this is normally not required.
     * It can be useful to set up a tun/tap interface owned
     * by a non-root user, so open5gs can be started without
     * needing any root privileges at all.
     */

    /* Set P-to-P IP address with Netmask
     * Note that Linux will skip this configuration */
    ogs_list_for_each(&ogs_pfcp_self()->subnet_list, subnet) {
        ogs_assert(subnet->dev);
        rc = ogs_tun_set_ip(subnet->dev->ifname, &subnet->gw, &subnet->sub);
        if (rc != OGS_OK) {
            ogs_error("ogs_tun_set_ip(dev:%s) failed", subnet->dev->ifname);
            return OGS_ERROR;
        }
    }

    return OGS_OK;
}

void upf_gtp_close(void)
{
    ogs_pfcp_dev_t *dev = NULL;

    ogs_socknode_remove_all(&ogs_gtp_self()->gtpu_list);

    ogs_list_for_each(&ogs_pfcp_self()->dev_list, dev) {
        if (dev->poll)
            ogs_pollset_remove(dev->poll);
        ogs_closesocket(dev->fd);
    }
}

static void upf_gtp_handle_multicast(ogs_pkbuf_t *recvbuf)
{
    struct ip *ip_h =  NULL;
    struct ip6_hdr *ip6_h = NULL;
    ogs_pfcp_user_plane_report_t report;

    ip_h = (struct ip *)recvbuf->data;
    if (ip_h->ip_v == 6) {
#if COMPILE_ERROR_IN_MAC_OS_X  /* Compiler error in Mac OS X platform */
        ip6_h = (struct ip6_hdr *)recvbuf->data;
        if (IN6_IS_ADDR_MULTICAST(&ip6_h->ip6_dst))
#else
        struct in6_addr ip6_dst;
        ip6_h = (struct ip6_hdr *)recvbuf->data;
        memcpy(&ip6_dst, &ip6_h->ip6_dst, sizeof(struct in6_addr));
        if (IN6_IS_ADDR_MULTICAST(&ip6_dst))
#endif
        {
            upf_sess_t *sess = NULL;

            /* IPv6 Multicast */
            ogs_list_for_each(&upf_self()->sess_list, sess) {
                if (sess->ipv6) {
                    /* PDN IPv6 is available */
                    ogs_pfcp_pdr_t *pdr = NULL;

                    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
                        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) {
                            ogs_pkbuf_t *sendbuf = ogs_pkbuf_copy(recvbuf);
                            ogs_assert(sendbuf);
                            ogs_assert(true ==
                                ogs_pfcp_up_handle_pdr(
                                    pdr, OGS_GTPU_MSGTYPE_GPDU,
                                    NULL, sendbuf, &report));
                            break;
                        }
                    }

                    return;
                }
            }
        }
    }
}
