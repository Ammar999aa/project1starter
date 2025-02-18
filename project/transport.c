#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "consts.h"

// Packet Construction
static void packet_create(packet *pkt, uint16_t seq, uint16_t ack, uint16_t len, uint16_t win, uint16_t flags, uint8_t *payload)
{
    pkt->seq = htons(seq);
    pkt->ack = htons(ack);
    pkt->length = htons(len);
    pkt->win = htons(win);
    pkt->flags = flags;
    pkt->unused = 0;
    if (payload && len > 0)
    {
        memcpy(pkt->payload, payload, len);
    }
}

// Packet Sender
static ssize_t packet_send(int sockfd, struct sockaddr_in *addr, packet *pkt)
{
    return sendto(sockfd, pkt, sizeof(packet) + ntohs(pkt->length), 0, (struct sockaddr *)addr, sizeof(*addr));
}

// Packer Receiver
static ssize_t packet_receive(int sockfd, struct sockaddr_in *addr, packet *pkt)
{
    socklen_t addr_len = sizeof(*addr);
    return recvfrom(sockfd, pkt, sizeof(packet) + MAX_PAYLOAD, 0, (struct sockaddr *)addr, &addr_len);
}

// Handshake Function
static int handshake(int sockfd, struct sockaddr_in *addr, int type)
{
    packet pkt;
    uint16_t server_seq = 0;
    uint16_t client_seq = rand() % 1000;

    if (type == CLIENT)
    {
        // Send SYN
        packet_create(&pkt, client_seq, 0, 0, MAX_PAYLOAD, SYN, NULL);
        packet_send(sockfd, addr, &pkt);

        // Receive ACK
        packet_receive(sockfd, addr, &pkt);
        if (!(pkt.flags & SYN) || !(pkt.flags & ACK))
            return -1;

        // Send ACK
        server_seq = ntohs(pkt.seq);
        if (ntohs(pkt.length) > 0)
        {
            packet_create(&pkt, client_seq + 1, server_seq + 1, 0, MAX_PAYLOAD, ACK, NULL);
        }
        else
        {
            packet_create(&pkt, 0, server_seq + 1, 0, MAX_PAYLOAD, ACK, NULL);
        }
        packet_send(sockfd, addr, &pkt);
    }
    else
    { // SERVER
        packet_receive(sockfd, addr, &pkt);
        if (!(pkt.flags & SYN))
            return -1;

        client_seq = ntohs(pkt.seq);
        server_seq = rand() % 1000;
        packet_create(&pkt, server_seq, client_seq + 1, 0, MAX_PAYLOAD, (SYN | ACK), NULL);
        packet_send(sockfd, addr, &pkt);

        packet_receive(sockfd, addr, &pkt);
        if (!ntohs(pkt.flags & ACK))
            return -1;
    }
    return 0;
}

// Main function of transport layer; never quits
void listen_loop(int sockfd, struct sockaddr_in *addr, int type,
                 ssize_t (*input_p)(uint8_t *, size_t),
                 void (*output_p)(uint8_t *, size_t))
{
    if (handshake(sockfd, addr, type) != 0)
    {
        fprintf(stderr, "Handshake failed\n");
        return;
    }

    packet pkt;
    uint8_t buffer[MAX_PAYLOAD];

    while (true)
    {
    }
}
