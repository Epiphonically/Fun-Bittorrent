#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>
#include "../bencodeLib/bencode.h"
#include "../bencodeLib/list.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "hashLib/hash.h"
#include <inttypes.h>
#include <fcntl.h>
#include <signal.h>

#define MIN_GET_INTERVAL 20
#define MAX_LINE 100000
#define MAX_COMMAND 30
#define MAX_COMMAND_ARG 10000
#define NUM_HEADERS 3
#define MAXPPLQUEUE 10
#define NUM_HEADERS 3
#define MAX_ACCEPTED_LEN 100000
#define HANDSHAKE_TIMEOUT 2
#define MAX_HANDSHAKE_RETRYS 5
#define MAX_REQ_SIZE 16384
#define MAX_PEERS 50
#define MAX_OUTGOING_REQ 100
#define OPTIMISTIC_UNCHOKE_PERIOD 5
#define OUTGOING_PIECE_TIMEOUT 3
#define BURST_TOLERANCE 0.5
#define ALPHA 0.2

#define REQ_TIMEOUT 1
#define BURST_REQ_NUM 6

#define RETRY_CONNECT_TIMER 5
#define HEADER_LEN 4

// External variables defined in bt.c
extern struct bittorrent_info *trackers;
extern uint8_t peer_id[21];
extern int serv_sock_tcp;
extern int port;
extern struct bittorrent_info *trackers;
extern struct timespec curr_time;

typedef enum {
    CHOKE = 0,
    UNCHOKE = 1,
    INTERESTED = 2,
    NOT_INTERESTED = 3,
    HAVE = 4,
    BITFIELD = 5,
    REQUEST = 6,
    PIECE = 7,
    CANCEL = 8,
    PORT = 9
} IDS;

typedef enum {
    NOT_CONNECTED,
    CONNECTED_NOT_HANDSHAKED,
    CONNECTED_HANDSHAKE_SENT,
    CONNECTED_HANDSHAKE_RECVD,
    SCREW_U
} PeerState;

typedef struct {
    char ip[16];
    unsigned short port;
    struct sockaddr_in inconsistent_addr;
    int peer_sock;
    char peer_id[20];
    char info_hash[20];
    struct timespec last_handshake_time;
    int handshakes_tried;
    PeerState my_state;

    struct timespec last_connect_time;

    struct timespec last_command_sent_in_general;
    struct timespec last_time_i_got_piece;

    ssize_t recv_len;
    ssize_t gotten;
    void *recv_buf;

    struct timespec last_set_of_req;
    uint32_t curr_piece;
    uint32_t offset_into_piece;

    int burst_num;
    double average_io_time;
    /* MALLOCED CAREFUL */
    uint8_t *my_bit_field;

    int sent_bit_field;

    int is_interested_in_me;
    int is_choking_me;

    int im_interested_in_him;
    int im_choking_him;

    int num_outgoing_piece_req;
} PeerInfo;

struct LimboPeer {
    struct LimboPeer *next;
    struct LimboPeer *prev;
    PeerInfo the_peer;
};


struct request {
    PeerInfo *him;
    uint32_t idx;
    uint32_t offset;

    struct timespec timeout;

    struct request *next;
    struct request *prev;
};


/* Sees whats up with peers inside the peer list of "the_tracker" */

struct bittorrent_info {
    int we_are_seeding;
    
    int trackers_tcp_sock;
    int has_pending_req;
    struct bittorrent_info *next;
    struct bittorrent_info *prev;
    struct timespec last_opt_unchoke;
    char *curr_event;

    size_t file_size;
    size_t owned_pieces;
    size_t num_pieces;
    size_t piece_len;
    size_t uploaded;
    size_t downloaded;
    size_t left;

    uint32_t piece_to_req;

    /* MALLOCED CAREFUL */
    uint8_t *outgoing_map;
    struct timespec *last_outgoing_map_update;
    struct request *request_list;

    /* MALLOCED CAREFUL */
    uint8_t *piece_density;

    /* MALLOCED CAREFUL */
    char *torrent_file_name;

    /* MALLOCED CAREFUL */
    char *file_name;

    /* MALLOCED CAREFUL */
    uint8_t *info_hash;

    uint32_t get_interval;
    struct timespec last_get_req;

    /* MALLOCED CAREFUL */
    PeerInfo *peer_list;
    size_t num_peers;

    /* MALLOCED CAREFUL */
    be_node_t *decoded_torrent_file;

    /* MALLOCED CAREFUL! */
    uint8_t *bit_field;
    size_t bit_field_len;

    /* MALLOCED CAREFUL! */
    uint8_t **piece_hashes;

    struct sockaddr_in the_addr;

    int started_as_done;
    int sent_end_message;
};

int he_has_piece(PeerInfo *him, uint32_t idx);

ssize_t safely_recv(int fd, void *buf, ssize_t size);

ssize_t safely_send(int fd, void *buf, ssize_t size);

void peer_init(PeerInfo *him);

size_t ceiling(double a);

uint32_t min(uint32_t a, uint32_t b);

uint64_t max(uint64_t a, uint64_t b);

double doub_abs(double a);

double time_delta(struct timespec t1, struct timespec t2);

int see_whats_up_with_peers(struct bittorrent_info *the_tracker);

int find_header_end(const unsigned char *data, size_t len);

int need_piece(struct bittorrent_info *the_tracker, int idx);

int parse_tracker_response(const unsigned char *response, size_t response_len,
                           PeerInfo **peers_out, size_t *num_peers_out, struct bittorrent_info *the_tracker);

void process_peer_message(void* buf, ssize_t size, PeerInfo *the_peer, struct bittorrent_info *the_tracker);

void request_pieces(PeerInfo *him, struct bittorrent_info *the_tracker);

void send_bit_field(PeerInfo *him, struct bittorrent_info *the_tracker);

void print_hex(const unsigned char *data, size_t len);

int char_is_safe(char a);

char *url_encode(uint8_t *url, int len);

void send_get_request_to_trackers();

int recv_response_from_tracker(unsigned char *buffer, struct bittorrent_info *curr_tracker);

struct bittorrent_info *url_to_address(char *url, uint64_t len);

int init_tracker_struct(char *file_name);
