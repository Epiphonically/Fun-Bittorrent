#include "scripts/headers.h"

int serv_sock_tcp;
int port;
struct bittorrent_info *trackers;
uint8_t peer_id[21];
struct LimboPeer *peers_in_limbo;

struct server_arguments {
    uint16_t port;
};

error_t server_parser(int key, char *arg, struct argp_state *state) {
    struct server_arguments *args = state->input;
    error_t ret = 0;
    switch (key) {
    case 'p':
        args->port = atoi(arg);
        if (args->port <= 1024) {
            argp_error(state, "Invalid option for a port");
        }
        break;
    default:
        ret = ARGP_ERR_UNKNOWN;
        break;
    }
    return ret;
}

struct server_arguments *server_parseopt(int argc, char *argv[]) {
    struct server_arguments *args;

    /* We're gonna be returning server_arguments and we dont
    want a memory leak for the salt so we allocate to HEAP */
    args = malloc(sizeof(*args));

    /* bzero ensures that "default" parameters are all zeroed out */
    bzero(args, sizeof(*args));

    struct argp_option options[] = {
        {"port", 'p', "port", 0, "The port to be used for the server", 0}, {0}};

    struct argp argp_settings = {options, server_parser, 0, 0, 0, 0, 0};

    if (argp_parse(&argp_settings, argc, argv, 0, NULL, args) != 0) {
        printf("Got an error condition when parsing\n");
    }

    return args;
}

int main(int argc, char *argv[]) {

    struct server_arguments *server_args = server_parseopt(argc, argv);
    if (server_args->port < 1024) {
        perror("Port Not Found\n");
        exit(1);
    }
    port = server_args->port;
    free(server_args);

    peers_in_limbo = malloc(sizeof(struct LimboPeer));
    peers_in_limbo->next = peers_in_limbo;
    peers_in_limbo->prev = peers_in_limbo;

    /* Do the peer ID of silly randomness :) */
    for (int i = 0; i < 20; i++) {
        peer_id[i] = 48 + (random() % 10);
    }
    peer_id[0] = '-';
    peer_id[1] = 'j';
    peer_id[2] = 'y';
    peer_id[3] = '0';
    peer_id[4] = '0';
    peer_id[5] = '0';
    peer_id[6] = '1';

    peer_id[20] = '\0';

    trackers = malloc(sizeof(struct bittorrent_info));
    trackers->next = trackers;
    trackers->prev = trackers;

    struct sockaddr_in my_addr;
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    serv_sock_tcp = socket(AF_INET, SOCK_STREAM, 0);

    bind(serv_sock_tcp, (struct sockaddr *)&my_addr, sizeof(my_addr));
    listen(serv_sock_tcp, MAXPPLQUEUE);

    char command[MAX_COMMAND];
    bzero(command, MAX_COMMAND);

    char command_arg[MAX_COMMAND_ARG];
    bzero(command_arg, MAX_COMMAND_ARG);

    char line[MAX_LINE];
    bzero(line, MAX_LINE);

    size_t sweep = 0;
    size_t idx = 0;

    printf("Do the command 'help' for commands\n");
    fflush(stdout);

    struct pollfd the_pfd;
    signal(SIGPIPE, SIG_IGN);

    while (1) {
    
        /* Accept Connections */
        the_pfd.fd = serv_sock_tcp;
        the_pfd.events = POLLIN;

        if (poll(&the_pfd, 1, 0) > 0) {
            /* Someone wants to connect! */
            printf("NEW PHONE WHO DIS\n");
            fflush(stdout);
            struct sockaddr_in temp_addr;
            socklen_t size = sizeof(temp_addr);
            int new_sock =
                accept(serv_sock_tcp, (struct sockaddr *)&temp_addr, &size);

            struct LimboPeer *new_limbo = malloc(sizeof(struct LimboPeer));
            peer_init(&new_limbo->the_peer);
            new_limbo->the_peer.peer_sock = new_sock;
            new_limbo->the_peer.inconsistent_addr = temp_addr;

            new_limbo->next = peers_in_limbo->next;
            new_limbo->prev = peers_in_limbo;
            peers_in_limbo->next = new_limbo;
            new_limbo->next->prev = new_limbo;
        }

        struct LimboPeer *curr_limbo = peers_in_limbo;
        struct LimboPeer *direction = malloc(sizeof(struct LimboPeer));
        for (curr_limbo = peers_in_limbo->next; curr_limbo != peers_in_limbo;
             curr_limbo = curr_limbo->next) {
            the_pfd.fd = curr_limbo->the_peer.peer_sock;
            the_pfd.events = POLLIN;
            if (poll(&the_pfd, 1, 0) >
                0) { /* ring ring this better be a handshake */
                uint8_t *recv_buf = malloc(1);
                if (recv(curr_limbo->the_peer.peer_sock, recv_buf, 1, 0) <= 0) {
                    /* wtf is this? */
                    free(recv_buf);
                    continue;
                }
                int pstrlen = recv_buf[0];
                uint8_t *swapsies = realloc(recv_buf, 49 + pstrlen);
                recv_buf = swapsies;

                int got = 0;
                int incr = 0;
                int failed_to_recv = 0;
                while (got < 48 + pstrlen) {
                    incr = recv(curr_limbo->the_peer.peer_sock,
                                recv_buf + 1 + got, 48 + pstrlen - got, 0);
                    if (incr <= 0) {
                        printf("BAD HANDSHAKERS");
                        fflush(stdout);
                        failed_to_recv = 1;

                        break;
                    }
                    got += incr;
                }

                if (!failed_to_recv) {

                    /* Verify that yess indeeeeed we are serving the umm thing
                     */
                    int verified = 0;
                    struct bittorrent_info *curr_track = trackers;
                    for (curr_track = trackers->next; curr_track != trackers;
                         curr_track = curr_track->next) {
                        verified = 1;
                        for (int j = 0; j < 20; j++) {
                            if (curr_track->info_hash[j] !=
                                recv_buf[1 + pstrlen + 8 + j]) {
                                verified = 0;
                                break;
                            }
                        }
                        if (verified) {
                            /* OHHH SO HES DOWNLOADING THIS FILLEEE */
                            /* Find some room for him and shake his hand back!
                             */

                            for (int j = 0; j < MAX_PEERS; j++) {
                                if (curr_track->peer_list[j].port == 0 ||
                                    curr_track->peer_list[j].my_state ==
                                        SCREW_U) {

                                    curr_track->peer_list[j] =
                                        curr_limbo->the_peer;
                                    char *pstr = "BitTorrent protocol";
                                    size_t len = 49 + strlen(pstr);
                                    char *buf = malloc(len);
                                    buf[0] = strlen(pstr);

                                    int curr_idx = 1;
                                    curr_idx +=
                                        sprintf(buf + curr_idx, "%s", pstr);
                                    for (int j = 0; j < 8; j++) {
                                        buf[curr_idx++] = 0;
                                    }

                                    /* append info hash of file */
                                    for (int j = 0; j < 20; j++) {
                                        buf[curr_idx++] =
                                            curr_track->info_hash[j];
                                    }

                                    /* append my peer id */
                                    for (int j = 0; j < 20; j++) {
                                        buf[curr_idx++] = peer_id[j];
                                    }

                                    size_t sent = 0;

                                    while (sent < len) {
                                        size_t incr =
                                            send(curr_limbo->the_peer.peer_sock,
                                                 buf + sent, len - sent, 0);

                                        if (incr <= 0) {
                                            /* ugh bruh wat */
                                            printf("HANDSHAKE FAILED\n");
                                            fflush(stdout);
                                            break;
                                        }
                                        sent += incr;
                                    }
                                    free(buf);

                                    curr_limbo->the_peer.my_state =
                                        CONNECTED_HANDSHAKE_RECVD;
                                    curr_limbo->the_peer.handshakes_tried = 0;

                                    curr_limbo->next->prev = curr_limbo->prev;
                                    curr_limbo->prev->next = curr_limbo->next;

                                    direction->next = curr_limbo->next;
                                    free(curr_limbo);
                                    curr_limbo = direction;
                                    break;
                                }
                            }

                            break;
                        }
                    }
                }
            }
        }
        free(direction);

        /* Bit Torrent Stuff */
        command[0] = '\0';
        command_arg[0] = '\0';
        line[0] = '\0';
        the_pfd.fd = 1;
        the_pfd.events = POLLIN;
        if (poll(&the_pfd, 1, 0) > 0) {
            if (!fgets(line, MAX_LINE, stdin)) {
                // End of input or error
                continue;
            }

            sweep = 0;
            idx = 0;
            for (; sweep < MAX_LINE; sweep++) {
                if (line[sweep] != ' ' && line[sweep] != '\n' &&
                    idx != MAX_COMMAND - 1) {
                    command[idx++] = tolower((unsigned char)line[sweep]);
                } else {
                    sweep++;
                    command[idx] = '\0';
                    break;
                }
            }
            idx = 0;
            for (; sweep < MAX_LINE; sweep++) {
                if (line[sweep] != ' ' && line[sweep] != '\n' &&
                    idx != MAX_COMMAND_ARG - 1) {
                    command_arg[idx++] = line[sweep];
                } else {
                    command_arg[idx] = '\0';
                    break;
                }
            }
            if (strcmp(command, "help") == 0) {
                printf("Commands:\n---------------------------\n| download "
                       "<filename>\n| stop <filename>\n| progress "
                       "<filename>\n| listall\n---------------------------\n");
                fflush(stdout);
            } else if (strcmp(command, "download") == 0) {
                printf("Starting Download!\n");
                fflush(stdout);
                if (!init_tracker_struct(command_arg)) {

                    printf("Something went wrong :(.\n");
                }
            } else if (strcmp(command, "stop") == 0) {
                /* Simple Just Remove The tracker from linked list */
                struct bittorrent_info *curr;
                int found = 0;
                for (curr = trackers->next; curr != trackers;
                     curr = curr->next) {
                    if (strcmp(command_arg, curr->torrent_file_name) == 0) {
                        free(curr->torrent_file_name);
                        free(curr->file_name);
                        free(curr->info_hash);
                        free(curr->piece_density);
                        free(curr->outgoing_map);
                        free(curr->last_outgoing_map_update);
                        for (size_t i = 0; i < MAX_PEERS; i++) {
                            if (curr->peer_list[i].my_bit_field) {
                                free(curr->peer_list[i].my_bit_field);
                            }
                            if (curr->peer_list[i].peer_sock > 0) {
                                close(curr->peer_list[i].peer_sock);
                            }
                        }
                        free(curr->peer_list);
                        be_free(curr->decoded_torrent_file);
                        free(curr->bit_field);

                        for (size_t i = 0; i < curr->num_pieces; i++) {
                            free(curr->piece_hashes[i]);
                        }
                        free(curr->piece_hashes);

                        close(curr->trackers_tcp_sock);

                        curr->next->prev = curr->prev;
                        curr->prev->next = curr->next;
                        free(curr);
                        found = 1;
                        printf("Stopped download of: %s\n", command_arg);
                        fflush(stdout);
                        break;
                    }
                }
                if (!found) {
                    printf("File not found\n");
                    fflush(stdout);
                }
            } else if (strcmp(command, "progress") == 0) {
                struct bittorrent_info *curr;
                int found = 0;
                for (curr = trackers->next; curr != trackers;
                     curr = curr->next) {
                    if (strcmp(command_arg, curr->torrent_file_name) == 0) {
                        if (curr->owned_pieces == curr->num_pieces) {
                            printf("Download completed, we are seeding now\n");
                            fflush(stdout);
                        } else {
                            printf(
                                "Downloaded Pieces: %ld, Total Pieces: %ld -> ",
                                curr->owned_pieces, curr->num_pieces);
                            printf("Download %f%% completed\n",
                                   ((double)curr->owned_pieces) /
                                       ((double)curr->num_pieces) * 100.0);
                            fflush(stdout);
                        }
                        found = 1;

                        break;
                    }
                }
                if (!found) {
                    printf("File not found\n");
                    fflush(stdout);
                }
            } else if (strcmp(command, "listall") == 0) {
                int count = 0;
                struct bittorrent_info *curr_tr;
                for (curr_tr = trackers->next; curr_tr != trackers;
                     curr_tr = curr_tr->next) {
                    printf("%s: ", curr_tr->file_name);
                    if (curr_tr->owned_pieces == curr_tr->num_pieces) {
                        printf("Download complete, seeding...\n");
                        fflush(stdout);
                    } else {
                        printf("Downloaded Pieces: %ld, Total Pieces: %ld -> ",
                               curr_tr->owned_pieces, curr_tr->num_pieces);
                        printf("Download %f%% completed\n",
                               ((double)curr_tr->owned_pieces) /
                                   ((double)curr_tr->num_pieces) * 100.0);
                        fflush(stdout);
                    }
                    count++;
                }
                if (count == 0) {
                    printf("No downloads right now.\n");
                }
                fflush(stdout);
            } else {
                printf("INVALID COMMAND\n");
                fflush(stdout);
            }
        }
        send_get_request_to_trackers();
        command[0] = '\0';
        command_arg[0] = '\0';
        // Attempt to receive a response from each of the trackers
        struct bittorrent_info *curr_tracker = trackers;
        for (curr_tracker = trackers->next; curr_tracker != trackers;
             curr_tracker = curr_tracker->next) {

            /* NEED DYNAMIC BUFFER SIZEPLSPLS WITH REALLOC */
            unsigned char buffer[250000];

            int response_size =
                recv_response_from_tracker(buffer, curr_tracker);

            // printf("Received %d bytes from tracker\n", response_size);

            // Find the start of the HTTP body
            int body_offset = find_header_end(buffer, response_size);
            if (response_size > 0 && body_offset >= 0) {

                size_t body_len = response_size - body_offset;
                const unsigned char *body_start = buffer + body_offset;

                PeerInfo *peers_temp = NULL;
                size_t num_peers = 0;

                if (parse_tracker_response(body_start, body_len, &peers_temp,
                                           &num_peers, curr_tracker) == 0) {

                    printf("Got %zu peers from tracker:\n", num_peers);

                    for (size_t i = 0; i < num_peers; i++) {
                        printf("Peer %zu: %s:%d\n", i, peers_temp[i].ip,
                               peers_temp[i].port);

                        for (size_t j = 0; j < MAX_PEERS; j++) {
                            if (curr_tracker->peer_list[j].port == 0) {
                                curr_tracker->peer_list[j] = peers_temp[i];
                                break;
                            }
                        }
                    }
                    free(peers_temp);

                } else {
                    fprintf(stderr, "Failed to parse tracker response from "
                                    "actual HTTP body.\n");
                }
            }
        }

        /* connect to peers? Then maybe send bit map? */

        for (curr_tracker = trackers->next; curr_tracker != trackers;
             curr_tracker = curr_tracker->next) {

            if (curr_tracker->peer_list) {

                see_whats_up_with_peers(curr_tracker);
            }
        }
    }

    return 0;
}
