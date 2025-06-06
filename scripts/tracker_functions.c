#include "headers.h"

size_t ceiling(double a) {
    if (a > (((size_t)a) / 1)) {
        return (((size_t)a) / 1) + 1;
    } else {
        return (((size_t)a) / 1);
    }
}

void peer_init(PeerInfo *him) {
    bzero(him, sizeof(PeerInfo));
    him->recv_buf = NULL;
    him->curr_piece = 0;
    him->offset_into_piece = 0;

    him->my_state = NOT_CONNECTED;
    him->is_interested_in_me = 0;
    him->is_choking_me = 1;

    him->im_interested_in_him = 0;
    him->im_choking_him = 1;

    him->sent_bit_field = 0;
    him->my_bit_field = NULL;

    him->num_outgoing_piece_req = 0;
    him->peer_sock = -1;

    him->burst_num = 1;
    him->average_io_time = 0;

}

uint64_t max(uint64_t a, uint64_t b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}

double doub_abs(double a) {
    if (a < 0) {
        return -1 * a;
    } else {
        return a;
    }
}

double time_delta(struct timespec t1, struct timespec t2) {
    double t1secs = (double)t1.tv_sec + (((double)t1.tv_nsec) / 1000000000);
    double t2secs = (double)t2.tv_sec + (((double)t2.tv_nsec) / 1000000000);
    return doub_abs(t2secs - t1secs);
}

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

int find_header_end(const unsigned char *data, size_t len) {
    for (size_t i = 0; i + 3 < len; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' &&
            data[i + 3] == '\n') {
            return i + 4; // Return the index after "\r\n\r\n"
        }
    }
    return -1;
}

int parse_tracker_response(const unsigned char *response, size_t response_len,
                           PeerInfo **peers_out, size_t *num_peers_out,
                           struct bittorrent_info *the_tracker) {
    *peers_out = NULL;
    *num_peers_out = 0;

    // printf("Tracker response (raw):\n");
    // print_hex(response, response_len);

    size_t readAmount = 0;
    be_node_t *root =
        be_decode((const char *)response, response_len, &readAmount);
    if (!root) {
        fprintf(stderr, "Failed to bencode-decode the tracker response.\n");
        return -1;
    }

    if (root->type != DICT) {
        fprintf(stderr, "Top-level tracker response is not a dictionary.\n");
        be_free(root);
        return -1;
    }

    // Lookup the "interval" key
    be_node_t *interval_node = be_dict_lookup(root, "interval", NULL);
    if (interval_node && interval_node->type == NUM) {
        the_tracker->get_interval = max(MIN_GET_INTERVAL, interval_node->x.num);
    }

    // Lookup the "peers" key
    be_node_t *peers_node = be_dict_lookup(root, "peers", NULL);
    if (!peers_node) {
        fprintf(stderr, "No 'peers' entry in the tracker response.\n");
        be_free(root);
        return -1;
    }

    if (peers_node->type == STR) {
        // Compact peers format
        // Each peer: 4 bytes for IP, 2 bytes for port
        long long plen = peers_node->x.str.len;
        if (plen % 6 != 0) {
            fprintf(stderr, "Invalid length for compact peers string.\n");
            be_free(root);
            return -1;
        }

        size_t count = (size_t)(plen / 6);
        PeerInfo *peer_array = malloc(count * sizeof(PeerInfo));
        if (!peer_array) {
            fprintf(stderr, "Memory allocation failed.\n");
            be_free(root);
            return -1;
        }

        const unsigned char *p = (const unsigned char *)peers_node->x.str.buf;
        for (size_t i = 0; i < count; i++) {
            peer_init(&peer_array[i]);
            unsigned char ip_bytes[4];
            memcpy(ip_bytes, p + i * 6, 4);
            unsigned short port_net;
            memcpy(&port_net, p + i * 6 + 4, 2);

            snprintf(peer_array[i].ip, sizeof(peer_array[i].ip), "%u.%u.%u.%u",
                     ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            peer_array[i].port = ntohs(port_net);
        }

        *peers_out = peer_array;
        *num_peers_out = count;

    } else if (peers_node->type == LIST) {
        // Non-compact peers format
        // It's a list of dictionaries, each with "ip" (str) and "port" (num)

        // Count the number of peers
        size_t count = 0;
        {
            list_t *pos;
            list_for_each(pos, &peers_node->x.list_head) { count++; }
        }

        PeerInfo *peer_array = malloc(count * sizeof(PeerInfo));
        if (!peer_array) {
            fprintf(stderr, "Memory allocation failed.\n");
            be_free(root);
            return -1;
        }

        size_t idx = 0;
        list_t *pos;
        list_for_each(pos, &peers_node->x.list_head) {
            be_node_t *peer_entry = list_entry(pos, be_node_t, link);
            if (peer_entry->type != DICT) {
                fprintf(stderr, "Peer entry not a dictionary.\n");
                free(peer_array);
                be_free(root);
                return -1;
            }

            char *ip = be_dict_lookup_cstr(peer_entry, "ip");
            long long port = be_dict_lookup_num(peer_entry, "port");

            if (!ip || port <= 0 || port > 65535) {
                fprintf(stderr,
                        "Peer dictionary missing valid 'ip' or 'port'.\n");
                free(peer_array);
                be_free(root);
                return -1;
            }

            // Copy IP
            peer_init(&peer_array[idx]);

            strncpy(peer_array[idx].ip, ip, sizeof(peer_array[idx].ip) - 1);
            peer_array[idx].ip[sizeof(peer_array[idx].ip) - 1] = '\0';
            peer_array[idx].port = (unsigned short)port;

            idx++;
        }

        *peers_out = peer_array;
        *num_peers_out = count;

    } else {
        fprintf(stderr, "'peers' entry is neither STR nor LIST.\n");
        be_free(root);
        return -1;
    }
    be_free(root);
    return 0;
}

int char_is_safe(char a) {
    return (a == '.' || a == '-' || a == '_' || a == '~' ||
            (a >= 48 && a <= 57) || (a >= 65 && a <= 90) ||
            (a >= 97 && a <= 122));
}

char *url_encode(uint8_t *url, int len) {
    char *out = malloc(len * 5);
    int index = 0;
    for (int i = 0; i < len; i++) {
        if (char_is_safe(url[i])) {
            out[index++] = url[i];
            out[index] = '\0';
        } else {
            out[index++] = 37; /* this is % */
            sprintf(out + index, "%02x", url[i]);
            index = strlen(out);
        }
    }

    return out;
}

void send_get_request_to_trackers() {
    char get_req[10000];

    struct bittorrent_info *curr = trackers;

    for (curr = trackers->next; curr != trackers; curr = curr->next) {
        clock_gettime(CLOCK_REALTIME, &curr_time);
        if ((curr->left == 0 && !curr->started_as_done && !curr->sent_end_message) || (!curr->has_pending_req &&
            time_delta(curr_time, curr->last_get_req) >= curr->get_interval)) {
            curr->trackers_tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(curr->trackers_tcp_sock,
                        (struct sockaddr *)&curr->the_addr,
                        sizeof(curr->the_addr)) < 0) {
                printf("Cant establish connection.\n");
                fflush(stdout);
                close(curr->trackers_tcp_sock);
                return;
            }

            clock_gettime(CLOCK_REALTIME, &curr->last_get_req);
            // be_node_t *the_tor_file = curr->decoded_torrent_file;
            // be_dump(the_tor_file);

            // U\%c1\%83\%16\%94\%20\%f7\%cbEjEx\%b1\%12\%5d\%25\%fcj\%97T
            int sweep = 0;
            sweep += sprintf(get_req, "GET /announce?info_hash=");

            /* url_encode may encode a null byte into the return bruh */
            char *the_encoding = url_encode(curr->info_hash, 20);

            sweep += sprintf(get_req + sweep, "%s", the_encoding);

            sweep += sprintf(get_req + sweep, "&peer_id=");
            free(the_encoding);
            // the_encoding = url_encode(peer_id, 20);
            for (int i = 0; i < 20; i++) {

                get_req[sweep++] = peer_id[i];
            }
            // free(the_encoding);
            sweep +=
                sprintf(get_req + sweep,
                        "&port=%d&uploaded=%ld&downloaded=%ld&left=%ld", port,
                        curr->uploaded, curr->downloaded, curr->left);
            if (strcmp(curr->curr_event, "started") == 0) {
                sweep += sprintf(get_req + sweep, "&event=started");
                curr->curr_event = "";
            } else if (curr->left == 0 && !curr->started_as_done && !curr->sent_end_message) {
                curr->sent_end_message = 1;
                sweep += sprintf(get_req + sweep, "&event=completed");
            }   
            sweep += sprintf(get_req + sweep,
                             "&compact=1&no_peer_id=1 "
                             "HTTP/1.1\r\nHost:%s:%d\r\nAccept-Encoding: "
                             "gzip\r\nConnection: close\r\n\r\n",
                             inet_ntoa(curr->the_addr.sin_addr),
                             ntohs(curr->the_addr.sin_port));

            int sent = 0;

            while (sent < sweep) {
                int incr = send(curr->trackers_tcp_sock, get_req + sent,
                                sweep - sent, 0);
                if (incr < 0) {
                    /* huh? */
                    break;
                }
                sent += incr;
            }
            curr->has_pending_req = 1;
            fflush(stdout);
        }
    }
}

int recv_response_from_tracker(unsigned char *buffer,
                               struct bittorrent_info *curr_tracker) {
    int recv_len = 0;
    if (curr_tracker->has_pending_req) {
        struct pollfd pfd;
        pfd.fd = curr_tracker->trackers_tcp_sock;
        pfd.events = POLLIN;

        if (poll(&pfd, 1, 0) > 0) {
            int incr = 0;
            while ((incr = recv(curr_tracker->trackers_tcp_sock,
                                buffer + recv_len, 100000, 0)) > 0) {

                recv_len += incr;
            }
            curr_tracker->has_pending_req = 0;
            shutdown(curr_tracker->trackers_tcp_sock, SHUT_RDWR);
            close(curr_tracker->trackers_tcp_sock);
        }
    }
    return recv_len;
}

struct bittorrent_info *url_to_address(char *url, uint64_t len) {

    char *headers[NUM_HEADERS];
    char *services[NUM_HEADERS];
    char *service = "0";
    headers[0] = "http://";
    headers[1] = "https://";
    headers[2] = "udp://";
    services[0] = "http";
    services[1] = "0";
    services[2] = "0";

    uint64_t start = 0;
    /* snip snip the header XD */
    for (int i = 0; i < NUM_HEADERS; i++) {
        if (strncmp(headers[i], url, strlen(headers[i])) == 0) {
            if (i == 1 || i == 2) {
                printf("Bruh we dont got no https or udp yet were broke bruh "
                       "aint no way\n");
                return NULL;
            }
            
            service = services[i];
            start += strlen(headers[i]);
            break;
        }
    }

    uint64_t end = len;
    int is_ip_port = 0;
    for (uint64_t i = start; i < len; i++) {
        if (url[i] == ':') { /* Oh its in the form of IP:PORT */
            is_ip_port = 1;
        }
        if (url[i] == '/') { /* cut off everything to the right of slash */
            end = i;
            break;
        }
    }
    // printf("start: %ld, end: %ld\n", start, end);
    // fflush(stdout);
    char port[6];

    char *host_name = malloc(end - start + 1);

    struct bittorrent_info *out = malloc(sizeof(struct bittorrent_info));
    if (is_ip_port) { /* port is provided! */
        int copy_index = 0;
        int ip = 1;
        for (uint64_t i = start; i < end; i++) {
            if (ip) { /* These characters go to the ip */
                if (url[i] == ':') {
                    ip = 0;
                    host_name[copy_index] = '\0';
                    copy_index = 0;

                } else {
                    host_name[copy_index++] = url[i];
                }
            } else { /* These characters go to the port */
                port[copy_index++] = url[i];
            }
        }
        port[copy_index] = '\0';

        struct addrinfo *him = NULL;
        int fail = getaddrinfo(host_name, service, 0, &him);

        if (!fail) {
            struct sockaddr_in *his_addr = (struct sockaddr_in *)him->ai_addr;

            /* According to the documentation the ports reserved for bit torrent
               range from: 6881 - 6889 */
            // if (ntohs(his_addr->sin_port) < 1024) {
            his_addr->sin_port = htons(atoi(port));

            // printf("IP: %s, Port: %d\n", inet_ntoa(his_addr->sin_addr),
            // ntohs(his_addr->sin_port));
            out->the_addr = *his_addr;

            fflush(stdout);
            freeaddrinfo(him);

            free(host_name);
            return out;
        } else {

            printf("Invalid URL\n");
            fflush(stdout);
        }
    } else { /* we gotta feed this through gethostname which does the DNS thingy
              */
        uint64_t i = start;
        for (; i < end; i++) {
            host_name[i - start] = url[i];
        }
        host_name[i - start] = '\0';

        // printf("Host: %s\n", host_name);
        // fflush(stdout);
        struct addrinfo *him = NULL;

        int fail = getaddrinfo(host_name, service, 0, &him);

        if (!fail) {
            struct sockaddr_in *his_addr = (struct sockaddr_in *)him->ai_addr;

            /* According to the documentation the ports reserved for bit torrent
               range from: 6881 - 6889 */
            // if (ntohs(his_addr->sin_port) < 1024) {
            //     his_addr->sin_port = htons(6881 + (rand() % 9));
            // }

            // printf("IP: %s, Port: %d\n", inet_ntoa(his_addr->sin_addr),
            // ntohs(his_addr->sin_port));
            out->the_addr = *his_addr;

            fflush(stdout);
            freeaddrinfo(him);

            free(host_name);
            return out;
        } else {

            printf("Invalid URL\n");
            fflush(stdout);
        }
    }
    free(host_name);
    free(out);
    return NULL;
}

int init_tracker_struct(char *file_name) {
    /* Uhh make sure we dont have an entry for that file already :) */

    FILE *file = fopen(file_name, "r");

    if (file != NULL) {
        fseek(file, 0, SEEK_END);
        size_t torrent_file_size = ftell(file);
        rewind(file);

        char *buffer = malloc(torrent_file_size);
        // printf("Torrent File Size: %ld\n", torrent_file_size);
        if (fread(buffer, sizeof(char), torrent_file_size, file) <
            torrent_file_size) {
            /* What the sigma */
            printf("Error reading file\n");
            fflush(stdout);
            free(buffer);
            fclose(file);
        } else {
            fclose(file);
            /* Decode the file using allowed bencode library */
            be_node_t *storage_node =
                be_decode(buffer, torrent_file_size, &torrent_file_size);
            free(buffer);
            if (storage_node == NULL) {

                printf("Invalid torrent file\n");
                fflush(stdout);
                return 0;
            }
            /* Loop through outer dictionary important crap we gotta find:
               Announce, Info */

            list_t *curr;
            struct bittorrent_info *tracker_addr;
            if (storage_node->type == DICT) {

                uint8_t *info_encoded = NULL;
                uint8_t *info_hash = NULL;

                /* GET THE HASHES OF THE PIECES IN AN ARRAY PLEASE */
                uint8_t *temp_bit_field;
                uint8_t **temp_piece_hashes;
                char *file_name_temp;
                uint8_t temp_hash[20];

                size_t file_size = 0;
                size_t piece_len = 0;
                size_t num_pieces;
                size_t left = 0;
                size_t owned_pieces = 0;

                list_for_each(curr, &storage_node->x.dict_head) {
                    be_dict_t *entry = list_entry(curr, be_dict_t, link);

                    be_str_t *becodestr = &entry->key;

                    if (entry->val->type == DICT &&
                        strcmp(becodestr->buf, "info") == 0) {

                        be_node_t *file_size_node =
                            be_dict_lookup(entry->val, "length", NULL);
                        if (file_size_node && file_size_node->type == NUM) {
                            file_size = file_size_node->x.num;
                            left = file_size;
                        }

                        be_node_t *piece_length_node =
                            be_dict_lookup(entry->val, "piece length", NULL);
                        if (piece_length_node &&
                            piece_length_node->type == NUM) {
                            piece_len = piece_length_node->x.num;
                        }

                        num_pieces =
                            ceiling(((double)file_size) / ((double)piece_len));

                        temp_bit_field =
                            malloc(ceiling(((double)num_pieces) / ((double)8)));

                        bzero(temp_bit_field,
                              ceiling(((double)num_pieces) / ((double)8)));
                        temp_piece_hashes =
                            malloc(num_pieces * sizeof(*temp_piece_hashes));
                        /* lets get the good pieces hashes woop woop */

                        be_node_t *long_hash_string =
                            be_dict_lookup(entry->val, "pieces", NULL);
                        // printf("File Size: %ld, Size per piece: %ld, Num
                        // Pieces: %ld\n", file_size, piece_len, num_pieces);
                        if (long_hash_string && long_hash_string->type == STR) {
                            for (size_t i = 0; i < num_pieces; i++) {
                                temp_piece_hashes[i] = malloc(20);
                                if (!memcpy(temp_piece_hashes[i],
                                            ((long_hash_string->x.str.buf) +
                                             20 * i),
                                            20)) {
                                    printf("THERE ARE NOT ENOUGH HASHES AS "
                                           "ADVERTISED \n");
                                    fflush(stdout);
                                }
                            }
                        }

                        /* uhhh create files if not already there */
                        be_node_t *name_node = be_dict_lookup(entry->val, "name", NULL);

                        if (name_node && name_node->type == STR) {
                            // printf("FILENAME: %s\n", name_node->x.str.buf);
                            file_name_temp = malloc(name_node->x.str.len + 1);
                            for (int m = 0; m < name_node->x.str.len; m++) {
                                file_name_temp[m] = name_node->x.str.buf[m];
                            }
                            file_name_temp[name_node->x.str.len] = '\0';
                            FILE *fp = fopen(name_node->x.str.buf, "r+");
                            if (!fp) {
                                fp = fopen(name_node->x.str.buf, "w");
                            }
                            if (fp != NULL) {
                                // printf("FOUND FILE\n");
                                /* fill out our bit map woop woop with whats in
                                 * the file woop woop */
                                fseek(fp, 0, SEEK_END);
                                size_t num_pieces_we_potentially_wrote = min(file_size, ceiling(((double)ftell(fp)) / ((double)piece_len)));
                                rewind(fp);

                                uint8_t *temp_read = malloc(piece_len);
                                int shift = 7;
                                size_t bit_field_index = 0;
                                for (size_t i = 0; i < num_pieces_we_potentially_wrote; i++) {
                                    /* Get the ith hash of the thing in the
                                     * crippy crappy */
                                    int read = fread(temp_read, 1, piece_len, fp);
                                    if (read > 0) { /* hash the thing and check it
                                                against the metadata */

                                        struct sha1sum_ctx *ctx = sha1sum_create(NULL, 0);
                                        sha1sum_finish(ctx, temp_read, read, temp_hash);
                                        sha1sum_destroy(ctx);
                                        int same = 1;
                                      

                                        for (int j = 0; j < 20; j++) {
                                            if (temp_hash[j] != temp_piece_hashes[i][j]) {
                                                
                                                same = 0;
                                            }
                                        }

                                        if (same) {
                                            if (piece_len > left) {
                                                left = 0;
                                            } else {
                                                left -= piece_len;
                                            }

                                            temp_bit_field[bit_field_index] = (temp_bit_field[bit_field_index] | (1 << (shift)));
                                            owned_pieces++;
                                           
                                        } 
                                    }
                                    
                                    shift--;
                                    if (shift < 0) {
                                        bit_field_index++;
                                        shift = 7;
                                    }
                                }
                                free(temp_read);

                                fclose(fp);
                            }
                            printf("Initial Bit Field:\n");
                            for (size_t i = 0; i < ceiling(((double)
                            num_pieces)/((double) 8)); i++) {
                                printf("%d ", temp_bit_field[i]);
                            }
                            printf("\n");
                            fflush(stdout);
                        }

                        /* hash the info */

                        /* bencode the info as a string then hash that stwing
                         * uwu :3 */

                        // be_dump(entry->val);
                        ssize_t end_len = be_encode(entry->val, NULL, 0);
                        info_encoded = malloc(end_len);
                        info_hash = malloc(20);
                        be_encode(entry->val, (char *)info_encoded, end_len);

                        struct sha1sum_ctx *ctx = sha1sum_create(NULL, 0);

                        sha1sum_finish(ctx, info_encoded, end_len, info_hash);
                        free(info_encoded);
                        // printf("Hash of the Info Field:\n");
                        // for (int i = 0; i < 20; i++) {
                        //     printf("%02x", info_hash[i]);
                        // }
                        // printf("\n");
                        // fflush(stdout);
                        // be_dump(entry->val); /* print the info first */

                        sha1sum_destroy(ctx);
                        break;
                    }
                }
                if (info_hash == NULL) {
                    printf("The torrent file has no info????\n");
                    fflush(stdout);
                    be_free(storage_node);
                    free(temp_bit_field);
                    for (size_t i = 0; i < num_pieces; i++) {
                        free(temp_piece_hashes[i]);
                    }
                    free(temp_piece_hashes);
                    return 0;
                }

                struct bittorrent_info *tester = trackers;
                for (tester = trackers->next; tester != trackers;
                     tester = tester->next) {
                    if (strncmp((char *)tester->info_hash, (char *)info_hash,
                                20) == 0) { /* already exists bruh */
                        printf("The torrent is already being downloaded\n");
                        fflush(stdout);
                        free(info_hash);
                        be_free(storage_node);
                        free(temp_bit_field);
                        for (size_t i = 0; i < num_pieces; i++) {
                            free(temp_piece_hashes[i]);
                        }
                        free(temp_piece_hashes);
                        return 0;
                    }
                }

                list_for_each(curr, &storage_node->x.dict_head) {
                    be_dict_t *entry = list_entry(curr, be_dict_t, link);

                    be_str_t *becodestr = &entry->key;

                    // printf("%s\n", becodestr->buf);
                    if (entry->val->type == STR &&
                        strcmp(becodestr->buf, "announce") == 0) {

                        // printf("URL: %s\n", entry->val->x.str.buf);
                        /* We need to cut the URL to get just the hostname */
                        if ((tracker_addr = url_to_address(
                                 entry->val->x.str.buf,
                                 entry->val->x.str.len)) != NULL) {
                            /* Add this guy to linked list of trackers */

                            tracker_addr->next = trackers->next;
                            trackers->next->prev = tracker_addr;
                            trackers->next = tracker_addr;
                            tracker_addr->prev = trackers;
                            tracker_addr->info_hash = info_hash;
                            tracker_addr->get_interval = MIN_GET_INTERVAL;
                            tracker_addr->uploaded = 0;
                            tracker_addr->downloaded = 0;
                            tracker_addr->left = left;
                           
                            tracker_addr->started_as_done = !left;
                            
                            tracker_addr->file_size = file_size;
                            tracker_addr->owned_pieces = owned_pieces;
                            tracker_addr->we_are_seeding = 0;
                            clock_gettime(CLOCK_REALTIME,
                                          &tracker_addr->last_get_req);
                            tracker_addr->file_name = file_name_temp;
                            tracker_addr->last_get_req.tv_sec -=
                                MIN_GET_INTERVAL;
                            tracker_addr->has_pending_req = 0;
                            tracker_addr->curr_event = "started";
                            tracker_addr->peer_list = malloc(MAX_PEERS * sizeof(PeerInfo));
                            for (size_t cop = 0; cop < MAX_PEERS; cop++) {
                                peer_init(&(tracker_addr->peer_list[cop]));
                            }
                            tracker_addr->torrent_file_name =
                                malloc(strlen(file_name) + 1);
                            for (size_t cop = 0; cop < strlen(file_name);
                                 cop++) {
                                tracker_addr->torrent_file_name[cop] =
                                    file_name[cop];
                            }
                            tracker_addr->torrent_file_name[strlen(file_name)] =
                                '\0';
                            tracker_addr->decoded_torrent_file = storage_node;
                            tracker_addr->bit_field = temp_bit_field;
                            tracker_addr->bit_field_len = ceiling(((double)num_pieces) / ((double)8));
                            tracker_addr->piece_hashes = temp_piece_hashes;
                            tracker_addr->num_pieces = num_pieces;
                            tracker_addr->piece_len = piece_len;
                            clock_gettime(CLOCK_REALTIME,
                                          &tracker_addr->last_opt_unchoke);
                            tracker_addr->piece_density =
                                malloc(sizeof(*tracker_addr->piece_density) *
                                       num_pieces);
                            tracker_addr->outgoing_map = malloc(sizeof(*tracker_addr->outgoing_map) * num_pieces);
                            memset(tracker_addr->outgoing_map, 0, sizeof(*tracker_addr->outgoing_map) * num_pieces);
                            
                            tracker_addr->request_list = malloc(sizeof(*tracker_addr->request_list));
                            tracker_addr->request_list->him = NULL;
                            tracker_addr->request_list->next = tracker_addr->request_list;
                            tracker_addr->request_list->prev = tracker_addr->request_list;
                            

                            tracker_addr->sent_end_message = 0;

                            tracker_addr->last_outgoing_map_update = malloc(sizeof(struct timespec) * num_pieces);
                            memset(tracker_addr->last_outgoing_map_update, 0, sizeof(struct timespec) * num_pieces);
                            return 1;
                        }
                    }      
                }
            }
            be_free(storage_node);
        }
    } else {
        printf("File not found\n");
        fflush(stdout);
    }
    return 0;
}
