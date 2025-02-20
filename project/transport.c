#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "consts.h"

#define MAX_BUFFER_ENTRIES 70

typedef struct
{
    packet pkt;         // Full packet header + payload
    size_t payload_len; // Actual number of payload bytes in this packet
    bool acked;
} buffer_entry_t;

typedef struct
{
    buffer_entry_t entries[MAX_BUFFER_ENTRIES];
    int head;          // Index of the oldest (first unacknowledged) packet
    int tail;          // Next free slot for a new packet
    int count;         // # of packets currently in the buffer
    int total_payload; // Total payload bytes currently unacknowledged
} sending_buffer_t;

// Initialize the buffer
void init_sending_buffer(sending_buffer_t *buf)
{
    buf->head = 0;
    buf->tail = 0;
    buf->count = 0;
    buf->total_payload = 0;
}

// Check if adding a new packet with payload size 'payload_size' would exceed the window
bool can_send_packet(sending_buffer_t *buf, size_t payload_size)
{
    return (buf->total_payload + payload_size) <= MAX_WINDOW;
}

// Add a new packet to the sending buffer.
// Returns true on success, false if there's no room (either by payload or by number of entries).
bool add_packet(sending_buffer_t *buf, packet *pkt, size_t payload_size)
{ // <-- payload_size is not necessary since it's always pkt->len + 12 bytes
    if (!can_send_packet(buf, payload_size))
    {
        return false;
    }
    if (buf->count >= MAX_BUFFER_ENTRIES)
    {
        return false; // buffer full
    }

    // Copy the complete packet (header + payload) into the next available slot.
    buffer_entry_t *entry = &buf->entries[buf->tail];
    memcpy(&entry->pkt, pkt, sizeof(packet) + payload_size);
    entry->payload_len = payload_size;
    entry->acked = false;

    buf->total_payload += payload_size;
    buf->count++;
    buf->tail = (buf->tail + 1) % MAX_BUFFER_ENTRIES;

    return true;
}

// Remove acknowledged packets from the front of the buffer to free up space.
void remove_acked_packets(sending_buffer_t *buf)
{
    while (buf->count > 0 && buf->entries[buf->head].acked)
    {
        buf->total_payload -= buf->entries[buf->head].payload_len;
        buf->head = (buf->head + 1) % MAX_BUFFER_ENTRIES;
        buf->count--;
    }
}

// Example function: mark packets as acknowledged based on an ACK number.
// This is a simplified check assuming sequence numbers increase monotonically.
void acknowledge_packets(sending_buffer_t *buf, uint16_t ack_number)
{
    // Loop over the current entries and mark those with seq < ack_number as acknowledged.
    for (int i = 0; i < buf->count; i++)
    {
        int index = (buf->head + i) % MAX_BUFFER_ENTRIES;
        uint16_t seq = ntohs(buf->entries[index].pkt.seq);
        if (seq < ack_number)
        { // You might need a more robust check for wrap-around.
            buf->entries[index].acked = true;
        }
    }
    // Remove entries from the head that have been acknowledged.
    remove_acked_packets(buf);
}

uint8_t compute_parity(const void *data, size_t total_bytes)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint8_t parity = 0;
    for (size_t i = 0; i < total_bytes; i++)
    {
        parity ^= bytes[i];
    }
    return parity;
}

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
static int handshake(int sockfd, struct sockaddr_in *addr, int type, uint16_t client_seq, uint16_t server_seq)
{
    packet pkt;

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
        // server_seq = rand() % 1000;
        packet_create(&pkt, server_seq, client_seq + 1, 0, MAX_PAYLOAD, (SYN | ACK), NULL);
        packet_send(sockfd, addr, &pkt);

        packet_receive(sockfd, addr, &pkt);
        if (!pkt.flags & ACK)
            return -1;
    }
    return 0;
}

// Main function of transport layer; never quits
void listen_loop(int sockfd, struct sockaddr_in *addr, int type,
                 ssize_t (*input_p)(uint8_t *, size_t),
                 void (*output_p)(uint8_t *, size_t))
{
    uint16_t client_seq = rand() % 1000;
    uint16_t server_seq = rand() % 1000;
    if (handshake(sockfd, addr, type, client_seq, server_seq) != 0)
    {
        fprintf(stderr, "Handshake failed\n");
        return;
    }

    client_seq += 1; // Increment client SEQ because handshake was successful and this is the third packet sent.
    uint16_t client_ack = server_seq + 1;

    sending_buffer_t send_buf;
    init_sending_buffer(&send_buf);

    while (true)
    {
        uint8_t data_buffer[MAX_PAYLOAD] = {0};
        ssize_t bytes_read = input_p(data_buffer, MAX_PAYLOAD);
        if (bytes_read > 0)
        {
            while (!can_send_packet(&send_buf, (size_t)bytes_read))
            {
                // Receive ACK packets.
                break;
            }

            packet data_pkt;

            packet_create(&data_pkt, client_seq, client_ack, (uint16_t)bytes_read, MAX_PAYLOAD, ACK, data_buffer);

            if (packet_send(sockfd, addr, &data_pkt) < 0)
            {
                perror("packet_send fail");
            }
            else
            {
                if (!add_packet(&send_buf, &data_pkt, (size_t)bytes_read))
                {
                    fprintf(stderr, "Failed to add packet to sending buffer\n");
                }
                client_seq += (uint16_t)bytes_read; // Update client_seq by the number of payload bytes sent
            }
        }

        // Ccheck for ACK packets from the receiver.
        packet ack_pkt;
        ssize_t ack_bytes = packet_receive(sockfd, addr, &ack_pkt);
        if (ack_bytes >= sizeof(packet))
        {
            uint16_t ack_num = ntohs(ack_pkt.ack);
            acknowledge_packets(&send_buf, ack_num);
        }
    }
}
