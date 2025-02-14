#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "consts.h"

// Main function of transport layer; never quits
void listen_loop(int sockfd, struct sockaddr_in *addr, int type,
                 ssize_t (*input_p)(uint8_t *, size_t),
                 void (*output_p)(uint8_t *, size_t))
{

    // Set-Up Variables
    packet p_data; // Packet struct holding the sent/recieved data
    packet p_ack;  // Packet struct for acknowledgements

    struct sockaddr_in remote_addr;           // Remote c/s address
    socklen_t addr_len = sizeof(remote_addr); // Length of the address
    char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
    packet *pkt = (packet *)buffer;

    uint16_t seq_num = rand() % 1000; // Initial Range of 0-999, (CHANGE?)
    uint16_t expect_seq = 0;
    uint16_t server_seq = 0;
    uint16_t ack_num = 0;
    uint16_t window_size = MAX_WINDOW;

    // Perform handshake before entering infinite main loop
    perform_handshake(sockfd, &remote_addr, type, &seq_num, &server_seq, &expect_seq, input_p, output_p);

    while (true)
    {
        // Recieve packet
        int bytes_recvd = recvfrom(sockfd, pkt, sizeof(packet) + MAX_PAYLOAD, 0, (struct sockaddr *)&remote_addr, &addr_len);
        if (bytes_recvd < sizeof(packet))
        {
            continue; // Ignore incomplete packets
        }

        uint16_t seq = ntohs(pkt->seq);
        uint16_t ack = ntohs(pkt->ack);
        uint16_t length = ntohs(pkt->length);
        uint16_t win = ntohs(pkt->win);
        uint16_t flags = pkt->flags;

        bool syn = flags & 1;
        bool ack_flag = (flags >> 1) & 1;
        bool parity = (flags >> 2) & 1;

        // Process payload
        if (length > 0)
            output_p(pkt->payload, length);
    }
}

void perform_handshake(int sockfd, struct sockaddr_in *remote_addr, int type,
                       uint16_t *seq_num, uint16_t *server_seq, uint16_t *expect_seq,
                       ssize_t (*input_p)(uint8_t *, size_t),
                       void (*output_p)(uint8_t *, size_t))
{

    socklen_t addr_len = sizeof(*remote_addr);
    uint8_t buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
    packet *pkt = (packet *)buffer;

    if (type == CLIENT)
    {
        // Send SYN
        uint8_t payload[MAX_PAYLOAD] = {0};
        ssize_t payload_len = input_p(payload, MAX_PAYLOAD);

        packet syn_pkt = {};
        syn_pkt.seq = htons(*seq_num);
        syn_pkt.ack = 0;
        syn_pkt.flags = SYN;
        syn_pkt.length = htons(payload_len);
        memcpy(syn_pkt.payload, payload, payload_len);

        sendto(sockfd, &syn_pkt, sizeof(packet) + payload_len, 0, (struct sockaddr *)remote_addr, &addr_len);

        // Wait for server's SYN-ACK packet
        while (true)
        {
            int bytes_recvd = recvfrom(sockfd, pkt, sizeof(packet) + MAX_PAYLOAD, 0,
                                       (struct sockaddr *)remote_addr, &addr_len);
            if (bytes_recvd < sizeof(packet))
                continue;
            if (pkt->flags == (SYN | ACK) && ntohs(pkt->ack) == *seq_num + 1)
            {
                *server_seq = ntohs(pkt->seq);
                break;
            }
        }

        // Send Final ACK
        payload_len = input_p(payload, MAX_PAYLOAD);

        packet ack_pkt = {0};
        ack_pkt.seq = htons(0);
        ack_pkt.ack = htons(*server_seq + 1);
        ack_pkt.flags = ACK;
        ack_pkt.length = htons(payload_len);
        memcpy(ack_pkt.payload, payload, payload_len);

        sendto(sockfd, &ack_pkt, sizeof(packet) + payload_len, 0, (struct sockaddr *)remote_addr, addr_len);
    }
    else if (type == SERVER)
    {
        // Wait for client SYN
        while (true)
        {
            int bytes_recvd = recvfrom(sockfd, pkt, sizeof(packet) + MAX_PAYLOAD, 0,
                                       (struct sockaddr *)remote_addr, &addr_len);
            if (bytes_recvd < sizeof(packet))
                continue;
            if (pkt->flags == SYN)
            {
                *expect_seq = ntohs(pkt->seq) + 1;
                uint16_t len = ntohs(pkt->length);
                if (len > 0)
                    output_p(pkt->payload, len);
                break;
            }
        }

        // Send SYN-ACK
        *server_seq = rand() % 1000;
        uint8_t payload[MAX_PAYLOAD] = {0};
        ssize_t payload_len = input_p(payload, MAX_PAYLOAD);

        packet syn_ack = {0};
        syn_ack.seq = htons(*server_seq);
        syn_ack.ack = htons(*expect_seq);
        syn_ack.flags = SYN | ACK;
        syn_ack.length = htons(payload_len);
        memcpy(syn_ack.payload, payload, payload_len);

        sendto(sockfd, &syn_ack, sizeof(packet) + payload_len, 0, (struct sockaddr *)remote_addr, addr_len);

        // Wait for final ACK
        while (true)
        {
            int bytes_recvd = recvfrom(sockfd, pkt, sizeof(packet) + MAX_PAYLOAD, 0,
                                       (struct sockaddr *)remote_addr, &addr_len);
            if (bytes_recvd < sizeof(packet))
                continue;
            if (pkt->flags == ACK && ntohs(pkt->ack) == *server_seq + 1)
            {
                uint16_t len = ntohs(pkt->length);
                if (len > 0)
                    output_p(pkt->payload, len);
                break;
            }
        }
    }
}
