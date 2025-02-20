#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "consts.h"

// buffer as linked list
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

int state = 0;         // Curr state
int window = 0;        // Total num bytes in sending window
int dup_acks = 0;      // Counting duplicate ACKs
uint16_t ack = 0;      // ACK
uint16_t seq = 0;      // Seq
uint16_t last_ack = 0; // Last ack, keeps track of dupe ACKs
bool force_ack = false;
packet *base_pkt = NULL;

ssize_t (*input)(uint8_t *, size_t); // Get data from layer
void (*output)(uint8_t *, size_t);   // Output data from layer

#define CLIENT_WAIT 2 // Client is waiting for SYN ACK
#define BEGIN 3       // Handshake finished, begin normal operations

// Main function of transport layer; never quits
void listen_loop(int sockfd, struct sockaddr_in *addr, int type,
                 ssize_t (*input_p)(uint8_t *, size_t),
                 void (*output_p)(uint8_t *, size_t))
{

    int phase = type;

    char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
    packet *pkt = (packet *)&buffer;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    uint16_t server_seq = rand() % 1000;
    uint16_t client_seq = rand() % 1000;

    sending_buffer_t send_buf;
    init_sending_buffer(&send_buf);

    while (true)
    {
        if (phase == CLIENT)
        {
            int index = 0;
            while (true)
            {
                char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
                packet *pkt = (packet *)&buffer;
                pkt->seq = htons(client_seq + index);
                pkt->ack = htons(0);
                pkt->flags = SYN;
                pkt->win = htons(MAX_PAYLOAD);
                ssize_t input_len = input_p(pkt->payload, MAX_PAYLOAD);
                pkt->length = htons(input_len); // Store actual data length
                // Send SYN (with potential payload)

                if (!add_packet(&send_buf, pkt, (size_t)input_len))
                {
                    // Wait for ack packets.
                    char ack_buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
                    packet *ack_pkt = (packet *)&ack_buffer;

                    recvfrom(sockfd, ack_pkt, sizeof(packet) + MAX_PAYLOAD, 0,
                             (struct sockaddr *)addr, &addr_size);
                    acknowledge_packets(&send_buf, ntohs(ack_pkt->ack));
                }

                sendto(sockfd, pkt, sizeof(packet) + input_len, 0,
                       (struct sockaddr *)addr, sizeof(struct sockaddr_in));

                index++;
            }
        }
        else if (phase == SERVER)
        {
            uint16_t seq = 0;
            recvfrom(sockfd, pkt, sizeof(packet) + MAX_PAYLOAD, 0, (struct sockaddr *)addr, &addr_size);
            if (pkt->flags == SYN)
            {
                seq = ntohs(pkt->seq);
            }
            // If payload
            if (pkt->length > 0)
            {
                output_p(pkt->payload, ntohs(pkt->length));
            }
            // Send SYN-ACK with possible payload
            pkt->seq = htons(server_seq);
            pkt->ack = htons(seq + 1);
            pkt->flags = SYN | ACK;
            pkt->win = htons(MAX_PAYLOAD);
            ssize_t input_len = input_p(pkt->payload, MAX_PAYLOAD);
            pkt->length = htons(input_len);

            sendto(sockfd, pkt, sizeof(packet) + input_len, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in));
            phase = BEGIN;
        }
        else if (phase == CLIENT_WAIT)
        {
            // receive packet from server
            uint16_t seq = 0;
            recvfrom(sockfd, pkt, sizeof(packet) + MAX_PAYLOAD, 0, (struct sockaddr *)addr, &addr_size);
            if (pkt->length > 0)
            {
                seq = ntohs(pkt->seq);
                output_p(pkt->payload, ntohs(pkt->length));
            }
            // Send SYN-ACK with possible payload
            pkt->seq = htons(server_seq);
            pkt->ack = htons(seq + 1);
            pkt->flags = ACK;

            ssize_t input_len = input_p(pkt->payload, MAX_PAYLOAD);
            if (input_len > 0)
            {
                client_seq += 1;
                pkt->seq = client_seq;
            }
            else
            {
                pkt->seq = 0;
            }
            pkt->length = htons(input_len);
            sendto(sockfd, pkt, sizeof(packet) + input_len, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in));
            phase = BEGIN;
        }
        // Normal Operations
        else
        {
            recvfrom(sockfd, pkt, sizeof(packet) + MAX_PAYLOAD, 0, (struct sockaddr *)addr, &addr_size);
        }
    }
}