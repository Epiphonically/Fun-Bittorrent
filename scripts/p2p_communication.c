#include "headers.h"

struct timespec curr_time;
struct timespec init_time;

ssize_t safely_recv(int fd, void *buf, ssize_t size) {
    ssize_t got = 0;
    ssize_t incr = 0;
    while (got < size) {
        incr = recv(fd, buf + got, size - got, 0);
        if (incr == 0) {
            
            return got;
        } else if (incr < 0) {
            return incr;
        }
        got += incr;
    }
    return got;
}

ssize_t safely_send(int fd, void *buf, ssize_t size) {
    ssize_t sent = 0;
    ssize_t incr = 0;
    while (sent < size) {
        incr = send(fd, buf + sent, size - sent, 0);
        if (incr <= 0) {
            return incr;
        }
        sent += incr;
    }
    return sent;
}

uint32_t min(uint32_t a, uint32_t b) {
    if (a < b) {
        return a;
    } else {
        return b;
    }
}

// Nonblocking socket
int make_socket_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
    return 0;
}

int make_socket_blocking_again(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0)
        return -1;
    return 0;
}


ssize_t recv_message_from_peer(PeerInfo *him, void **recv_buf) {
    struct pollfd pfd;
    pfd.fd = him->peer_sock;
    pfd.events = POLLIN;
    
    ssize_t got;
    if (poll(&pfd, 1, 0) > 0) { /* thanks */
        if (him->recv_buf) {
            got = recv(him->peer_sock, him->recv_buf + him->gotten, him->recv_len - him->gotten, 0);
            him->gotten += got;
            if (got < 0) {
                free(him->recv_buf);
                him->recv_buf = NULL;
            
                return -1;
            } else if (him->gotten == him->recv_len) {
                *recv_buf = him->recv_buf;
                return him->recv_len;
            }
        } else {
            him->recv_buf = malloc(HEADER_LEN);
            /* Get first 4 bytes which is the len */    
            if (safely_recv(him->peer_sock, him->recv_buf, HEADER_LEN) != HEADER_LEN) {
                free(him->recv_buf);
                him->recv_buf = NULL;
                him->my_state = BAD_PEER;
                return -1;
            }
            him->gotten = 0;
            him->recv_len = *((int *) him->recv_buf);
            him->recv_len = ntohl(him->recv_len);
            free(him->recv_buf);
            him->recv_buf = malloc(him->recv_len);
            
            if (poll(&pfd, 1, 0) > 0) { 
                got = recv(him->peer_sock, him->recv_buf, him->recv_len, 0);
            
                if (got == him->recv_len) {
                    *recv_buf = him->recv_buf;
                    return got;
                } else if (got < 0) {
                    free(him->recv_buf);
                    him->recv_buf = NULL;
                    return -1;
                } else {
                    him->gotten += got;
                    return -1;
                }
            } 
            

        }
        
    }

    return -1;
}

void process_peer_message(void* buf, ssize_t size, PeerInfo *the_peer, struct bittorrent_info *the_tracker) {
    /* size is 1 + length of data */
    /* buf should contain the action in the first byte then the rest of the data */
    uint8_t action = ((uint8_t *) buf)[0];

    switch (action) {
        case CHOKE:
   
            the_peer->is_choking_me = 1;
            break;

        case UNCHOKE:

            the_peer->is_choking_me = 0;
            break;

        case INTERESTED:

            the_peer->is_interested_in_me = 1;

            break;

        case NOT_INTERESTED:
       
            the_peer->is_interested_in_me = 0;
            break;

        case HAVE:
            /* If im not yet interested I need to tell him that
             * I am :) */
            /* Then request the pieces */
          
            if (the_peer->my_bit_field == NULL) {
                the_peer->my_bit_field = malloc(the_tracker->bit_field_len);
            }
            uint32_t special_idx = ntohl(((uint32_t *) (buf + 1))[0]);
            the_peer->my_bit_field[special_idx / 8] |= (1 << (7 - (special_idx % 8)));

            break;

        case BITFIELD:
            /* Update the bitfield */
            // uint8_t mask = 0;
            // for (size_t j = 0; j < 8 - (the_tracker->num_pieces % 8); j++) {
            //     mask = (mask | (1 << j));
            // }

            if (/* ((((uint8_t *) buf)[1 + size] & mask) > 0) || */ size - 1 != the_tracker->bit_field_len) {
                printf("INVALID BITFIELD\n");

                fflush(stdout);
                the_peer->my_state = BAD_PEER;
            } else {
                if (the_peer->my_bit_field == NULL) {
                    the_peer->my_bit_field = malloc(the_tracker->bit_field_len);
                }
                //printf("His bitfield:\n");
                for (uint32_t j = 0; j < size - 1; j++) {
                    //printf("%02x ", ((uint8_t *) buf)[j + 1]);
                    the_peer->my_bit_field[j] = ((uint8_t *) buf)[j + 1];
                }
                //printf("\n");
                fflush(stdout);
            }

            break;
        
        case REQUEST:
             // printf("HES REQUESTING FROM ME\n");
             // fflush(stdout);

            // if (!(the_tracker->peer_list[i].im_choking_him)) { /* Lets see if hes unchoked first */
            //     /* Wow taake my pieces */
            //     uint32_t req_idx = ntohl(((uint32_t *)(recv_buf + 5))[0]);
            //     uint32_t req_begin = ntohl(((uint32_t *)(recv_buf + 5))[1]);
            //     uint32_t req_len = ntohl(((uint32_t *)(recv_buf + 5))[2]);

            //     FILE *fp = fopen(the_tracker->file_name, "r");

            //     if (req_len <= MAX_REQ_SIZE && fp != NULL) {
            //         /* Verify I have the piece he wants */
            //         uint8_t temp_hash[20];
            //         fseek(fp, (req_idx * the_tracker->piece_len), 0);
            //         uint8_t *send_buf = malloc(the_tracker->piece_len);
            //         size_t read = fread(send_buf, 1, the_tracker->piece_len, fp);
            //     }
            //     struct sha1sum_ctx *ctx = sha1sum_create(NULL, 0);
            //     sha1sum_finish(ctx, send_buf, read, temp_hash);
            //     sha1sum_destroy(ctx);
            //     free(send_buf);
            //     int we_have = 1;
            //     for (int h = 0; h < 20; h++) {
            //         if (the_tracker->piece_hashes[req_idx][h] != temp_hash[h]) {
            //             we_have = 0;
            //         }
            //     }

            //     if (we_have) {
            //         send_buf = malloc(13 + req_len);
            //         ((uint32_t *)send_buf)[0] = htonl(9 + req_len);
            //         send_buf[4] = PIECE;
            //         ((uint32_t *)(send_buf + 5))[0] = htonl(req_idx);
            //         ((uint32_t *)(send_buf + 5))[1] = htonl(req_begin);

            //         rewind(fp);
            //         fseek(fp, (req_idx * (the_tracker->piece_len)) + req_begin, 0);
            //         read = fread(send_buf + 13, 1, req_len, fp);
            //         if (read == req_len) {
            //             int need = 13 + req_len;
        //                                     int sent = 0;
        //                                     while (sent < need) {
        //                                         int incr = send(
        //                                             the_tracker->peer_list[i]
        //                                                 .peer_sock,
        //                                             send_buf + sent,
        //                                             need - sent, 0);
        //                                         if (incr <= 0) {
        //                                             /* uhhh */
        //                                             break;
        //                                         }
        //                                         sent += incr;
        //                                     }
        //                                 }

        //                                 free(send_buf);
        //                             }
        //                         }
        //                         fclose(fp);
        //                     }

            break;

        case PIECE:
            
            clock_gettime(CLOCK_REALTIME, &the_peer->last_time_i_got_piece);

            uint32_t piece_index = ntohl(((uint32_t *)(buf + 1))[0]);
            uint32_t piece_begin = ntohl(((uint32_t *)(buf + 1))[1]);

            //printf("THIS IS A PIECE: IDX: %d, BEGIN: %d\n", piece_index, piece_begin);
            // fflush(stdout);
            //printf("%d, %d\n", the_tracker->piece_len, the_tracker->num_pieces);
            uint32_t the_len = size - 9;
            if (the_len <= MAX_REQ_SIZE && need_piece(the_tracker, piece_index)) {
                FILE *fp = fopen(the_tracker->file_name, "r+");
                if (fp != NULL) {
                    fseek(fp, (piece_index * the_tracker->piece_len) + piece_begin, SEEK_SET);
                    // printf("%d\n", the_len);
                    fwrite(buf + 9, 1, the_len, fp);

                    /* The piece may have been completed if so I
                    * update my bit map */
            
                    uint8_t temp_hash[20];
                    fseek(fp, (piece_index * the_tracker->piece_len), SEEK_SET);
                    uint8_t *temp_read = malloc(the_tracker->piece_len);
                    size_t read = fread(temp_read, 1, the_tracker->piece_len, fp);
                    //printf("%ld, %ld\n", read, the_tracker->piece_len);
                    struct sha1sum_ctx *ctx = sha1sum_create(NULL, 0);
                    sha1sum_finish(ctx, temp_read, read, temp_hash);
                    sha1sum_destroy(ctx);
                    free(temp_read);
                    int turn_on = 1;
                    int check = 0;
                   
                    for (check = 0; check < 20; check++) {
                        if (temp_hash[check] != the_tracker->piece_hashes[piece_index][check]) {
                
                            turn_on = 0;
                        } 
                    }
                    
                    if (turn_on) {

                        the_tracker->owned_pieces++;
                        
                        the_tracker->bit_field[piece_index / 8] |= (1 << (7 - (piece_index % 8)));
                        // printf("Turn on : %d\n", piece_index);
                        // fflush(stdout);
                    }
                    the_tracker->outgoing_map[piece_index]--;
                    clock_gettime(CLOCK_REALTIME, &(the_tracker->last_outgoing_map_update[piece_index]));
                    the_tracker->left -= the_len;
                    the_peer->num_outgoing_piece_req--;


                    fclose(fp);
                }
            }

        //                     if (the_tracker->peer_list[i].im_choking_him) {
        //                         /* unchoke him  */
        //                         uint8_t *send_buf = malloc(5);
        //                         ((uint32_t *)send_buf)[0] = htonl(1);
        //                         send_buf[4] = 1;
        //                         int sent = 0;
        //                         while (sent < 5) {
        //                             int incr = send(
        //                                 the_tracker->peer_list[i].peer_sock,
        //                                 send_buf + sent, 5 - sent, 0);
        //                             if (incr <= 0) {
        //                                 /* SUS */
        //                                 break;
        //                             }
        //                             sent += incr;
        //                         }
        //                         free(send_buf);
        //                         the_tracker->peer_list[i].im_choking_him = 0;
        //                     }

            break;

        //                 case CANCEL:
        //                     // printf("THIS GUY IS CANCELING ON ME\n");
        //                     // fflush(stdout);
        //                     break;

        //                 case PORT:
        //                     // printf("uh the port??? for DHT\n");
        //                     // fflush(stdout);
        //                     break;
                        
        

    }
}

int he_has_piece(PeerInfo *him, uint32_t idx) {
    if (him->my_bit_field) {
        uint8_t mask = ((1 << 7) >> (idx % 8));

        if (him->my_bit_field[idx / 8] & mask) {
            return 1;
        } else {
            return 0;
        }
    }
    return 0;
}

int need_piece(struct bittorrent_info *the_tracker, int idx) {
    uint8_t mask = ((1 << 7) >> (idx % 8));
    if (the_tracker->bit_field[idx / 8] & mask) {
        return 0;
    } else {
        return 1;
    }
}

void remove_request(struct request *remove_me) {
    struct request *temp = remove_me->prev;
    temp->next = remove_me->next;
    remove_me->next->prev = temp;
    free(remove_me);
}

int request_exists(struct bittorrent_info *the_tracker, uint32_t idx, uint32_t offset) {
    struct request *curr = the_tracker->request_list->next;
    struct request *temp;
    struct timespec curr_time;
    clock_gettime(CLOCK_REALTIME, &curr_time);
    while (curr != the_tracker->request_list) {
        if (time_delta(curr_time, curr->timeout) > REQ_TIMEOUT) {
            temp = curr;
            curr = curr->prev;
            remove_request(temp);
        } else if (curr->idx == idx && curr->offset == offset) {
          
            return 1;
        }
        curr = curr->next;
    }
    return 0;
}

void add_request(struct bittorrent_info *the_tracker, PeerInfo *him, uint32_t idx, uint32_t offset) {
    struct request *new = malloc(sizeof(struct request));
    new->him = him;
    new->idx = idx;
    new->offset = offset;
    clock_gettime(CLOCK_REALTIME, &new->timeout);

    new->next = the_tracker->request_list->next;
    the_tracker->request_list->next->prev = new;

    new->prev = the_tracker->request_list;
    the_tracker->request_list->next = new;
}

int request_subpiece(PeerInfo *him, struct bittorrent_info *the_tracker) {
   
    void *send_buf = malloc(4 + 13);
  
    /* construct the request packet */
    ((uint32_t *) send_buf)[0] = htonl(13);
    ((uint8_t *) send_buf)[4] = REQUEST;
    ((uint32_t *) (send_buf + 5))[0] = htonl(him->curr_piece);
    ((uint32_t *) (send_buf + 5))[1] = htonl(him->offset_into_piece);
    ((uint32_t *) (send_buf + 5))[2] = htonl(min(MAX_REQ_SIZE, (the_tracker->piece_len - him->offset_into_piece)));
    if (safely_send(him->peer_sock, send_buf, 4 + 13) == 17) {
        add_request(the_tracker, him, him->curr_piece, him->offset_into_piece);
        him->offset_into_piece += min(MAX_REQ_SIZE, (the_tracker->piece_len - him->offset_into_piece));

        if (him->offset_into_piece == the_tracker->piece_len) {
             
            him->curr_piece++;
            him->curr_piece %= the_tracker->num_pieces;
            him->offset_into_piece = 0;
        }   
        
    } else {
        free(send_buf);
        return 0;
    }
       
    
    free(send_buf);
   
    return 1;
   
}   

void request_pieces(PeerInfo *him, struct bittorrent_info *the_tracker) {
    
    int requested_pieces = 0;
    int requested = 0;
    int total = 0;
    struct timespec curr_time;
    clock_gettime(CLOCK_REALTIME, &curr_time);
   
    for (; total < the_tracker->num_pieces && (time_delta(him->last_set_of_req, curr_time) > 0.05f) && !him->is_choking_me && requested_pieces < BURST_REQ_NUM; total++) {
         
        if (!need_piece(the_tracker, him->curr_piece)) {
            
            him->curr_piece++;
            him->curr_piece %= the_tracker->num_pieces;
            him->offset_into_piece = 0;
        } else {
           
            if (request_exists(the_tracker, him->curr_piece, him->offset_into_piece)) {
                him->offset_into_piece += MAX_REQ_SIZE;
                him->offset_into_piece = min(him->offset_into_piece, the_tracker->piece_len);
                if (him->offset_into_piece == the_tracker->piece_len) {
                    him->curr_piece++;
                    him->curr_piece %= the_tracker->num_pieces;
                    him->offset_into_piece = 0;
                }
            } else if (he_has_piece(him, him->curr_piece)) {
                
                if (!request_subpiece(him, the_tracker)) {
                    return;
                }
                requested = 1;
                
                requested_pieces++;
            }
        }
    }

    if (requested) {
        
        clock_gettime(CLOCK_REALTIME, &him->last_set_of_req);
    }
    
}

void send_bit_field(PeerInfo *him, struct bittorrent_info *the_tracker) {
   
    uint8_t *send_buf = malloc(5 + the_tracker->bit_field_len);
    bzero(send_buf, 5 + the_tracker->bit_field_len);
    ((uint32_t *)send_buf)[0] = htonl(1 + the_tracker->bit_field_len);
    send_buf[4] = BITFIELD;

    for (size_t j = 0; j < the_tracker->bit_field_len; j++) {
        send_buf[5 + j] = the_tracker->bit_field[j];
    }

    if (safely_send(him->peer_sock, send_buf, 5 + the_tracker->bit_field_len) == 5 + the_tracker->bit_field_len) {
        him->sent_bit_field = 1;
    }
    free(send_buf);
}

int connected_hand_peers = 0;
int see_whats_up_with_peers(struct bittorrent_info *the_tracker) {
    if (the_tracker->owned_pieces == the_tracker->num_pieces) {
        the_tracker->we_are_seeding = 1;
    }
    memset(the_tracker->piece_density, 0, sizeof(*the_tracker->piece_density) * the_tracker->num_pieces);
    for (size_t i = 0; i < MAX_PEERS; i++) {
        if (the_tracker->peer_list[i].my_bit_field != NULL) {
            for (size_t k = 0; k < the_tracker->num_pieces; k++) {
                if ((((the_tracker->peer_list[i]).my_bit_field[k / 8]) &
                     (1 << (7 - (k % 8)))) > 0) {
                    the_tracker->piece_density[k]++;
                }
            }
        }
    }

    clock_gettime(CLOCK_REALTIME, &curr_time);
    for (size_t i = 0; i < the_tracker->num_pieces; i++) {
        if (time_delta(curr_time, the_tracker->last_outgoing_map_update[i]) > OUTGOING_PIECE_TIMEOUT && the_tracker->outgoing_map[i]) {
            the_tracker->outgoing_map[i] = 0;
        
        }
    }
   

    struct pollfd pfd;

    fd_set fdset;
    struct timeval tv;

    for (size_t i = 0; i < MAX_PEERS; i++) {
        PeerInfo *curr_peer = &(the_tracker->peer_list[i]);
        if (curr_peer->port != 0) {
            
            switch (curr_peer->my_state) {
            case NOT_CONNECTED:

                clock_gettime(CLOCK_REALTIME, &curr_time);

                if (curr_peer->peer_sock <= 0) {
                    clock_gettime(CLOCK_REALTIME, &(curr_peer->last_connect_time));

                    struct sockaddr_in temp_addr;
                    temp_addr.sin_family = AF_INET;
                    temp_addr.sin_port = htons(curr_peer->port);
                    if (!inet_aton(curr_peer->ip, &temp_addr.sin_addr)) {
                        printf("INVALID ADDRESS\n");
                        fflush(stdout);
                    }
                    curr_peer->peer_sock = socket(AF_INET, SOCK_STREAM, 0);

                    if (curr_peer->peer_sock <= 0) {
                        printf("Socket fail\n");
                        fflush(stdout);
                    }
                    make_socket_nonblocking(curr_peer->peer_sock);
                    if (connect(curr_peer->peer_sock, (struct sockaddr *) &temp_addr, sizeof(temp_addr)) == 0) {
                        
                        curr_peer->my_state = CONNECTED_NOT_HANDSHAKED;
                    } else {
                        
                        
                        FD_ZERO(&fdset);
                        FD_SET(curr_peer->peer_sock, &fdset);
                        tv.tv_sec = 0;          
                        tv.tv_usec = 0;

                        if (select(curr_peer->peer_sock + 1, NULL, &fdset, NULL, &tv) == 1) { /* Successfully connected! */
                            
                            curr_peer->my_state = CONNECTED_NOT_HANDSHAKED;
                        }
                    }
                } else {
                    
                    FD_ZERO(&fdset);
                    FD_SET(curr_peer->peer_sock, &fdset);
                    tv.tv_sec = 0;          
                    tv.tv_usec = 0;

                    if (select(curr_peer->peer_sock + 1, NULL, &fdset, NULL, &tv) == 1) { /* Successfully connected! */
                        
                        curr_peer->my_state = CONNECTED_NOT_HANDSHAKED;
                    } else if (time_delta(curr_peer->last_connect_time, curr_time) >= RETRY_CONNECT_TIMER) {
                       
                        curr_peer->my_state = BAD_PEER;
                    }
                }
               
                break;

            case CONNECTED_NOT_HANDSHAKED:
                 
                if (curr_peer->handshakes_tried > MAX_HANDSHAKE_RETRYS) {
                    curr_peer->my_state = BAD_PEER;
                    break;
                }
                /* send handshake */
                char *pstr = "BitTorrent protocol";
                ssize_t len = 49 + strlen(pstr);
                char *buf = malloc(len);
                buf[0] = strlen(pstr);

                int curr_idx = 1;
                curr_idx += sprintf(buf + curr_idx, "%s", pstr);
                for (int j = 0; j < 8; j++) {
                    buf[curr_idx++] = 0;
                }

                /* append info hash of file */
                for (int j = 0; j < 20; j++) {
                    buf[curr_idx++] = the_tracker->info_hash[j];
                }

                /* append my peer id */
                for (int j = 0; j < 20; j++) {
                    buf[curr_idx++] = peer_id[j];
                }

                // printf("TEST HANDSHAKER:");
                // for (size_t i = 0; i < len; i++) {
                //     printf("%c", buf[i]);
                // }

                // printf("\n");

                /* OK WE NEED TO UHHH WAIT FOR THEIR HAND SHAKE ON A TIMEOUT AND
                 * SEND HANDSHAKE AGAIN... */
              
                if (safely_send(curr_peer->peer_sock, buf, len) != len) {
                    curr_peer->my_state = BAD_PEER;
                } 
             
                

                clock_gettime(CLOCK_REALTIME, &(curr_peer->last_handshake_time));
                curr_peer->my_state = CONNECTED_HANDSHAKE_SENT;

                curr_peer->handshakes_tried++;
                free(buf);

             
                break;

            case CONNECTED_HANDSHAKE_SENT:
                pfd.fd = the_tracker->peer_list[i].peer_sock;
                pfd.events = POLLIN;

                /* Check if he timedout and need to go back to connected no
                 * CONNECTED_NOT_HANDSHAKED */
                clock_gettime(CLOCK_REALTIME, &curr_time);
                if (time_delta(curr_time, the_tracker->peer_list[i].last_handshake_time) >= HANDSHAKE_TIMEOUT) {
                    the_tracker->peer_list[i].my_state = CONNECTED_NOT_HANDSHAKED;
                } else if (poll(&pfd, 1, 0) > 0) { /* thanks bbgurl */
                   
                    uint8_t *recv_buf = malloc(1);
                    if (recv(the_tracker->peer_list[i].peer_sock, recv_buf, 1, 0) <= 0) {
                        /* what is this? */
                        free(recv_buf);
                        break;
                    }
                    int pstrlen = recv_buf[0];
                    free(recv_buf);
                    

                    recv_buf = malloc(49 + pstrlen);

                    int failed_to_recv = 0;
                    if (safely_recv(curr_peer->peer_sock, recv_buf + 1, 48 + pstrlen) != 48 + pstrlen) {
                        printf("BAD HANDSHAKE with len: %d\n", pstrlen);
                        fflush(stdout);
                        failed_to_recv = 1;
                    }

                    if (!failed_to_recv) {

                        /* Verify that yess indeeeeed we are serving the umm
                         * thing */
                        int failed_to_verify = 0;
                        for (int j = 0; j < 20; j++) {
                            if (the_tracker->info_hash[j] != recv_buf[1 + pstrlen + 8 + j]) {
                                failed_to_verify = 1;
                                break;
                            }
                        }
                        if (!failed_to_verify) {
                            
                            curr_peer->my_state = CONNECTED_HANDSHAKE_RECVD;

                            connected_hand_peers++;
                                                
                            curr_peer->handshakes_tried = 0;
                            //make_socket_blocking_again(curr_peer->peer_sock);
                        } else {
                            printf("FAILED TO VERIFY\n");
                            fflush(stdout);
                        }
                    } 

              
                    free(recv_buf);
                    
                }

                
                break;

            case CONNECTED_HANDSHAKE_RECVD:
              
                /* Send bitmap to peer */
                 /* OOOH maybe we shall send him bitmap now if we have anything
                 * lol */
                if (!curr_peer->sent_bit_field && the_tracker->owned_pieces > 0) {
                  
                    send_bit_field(curr_peer, the_tracker);


                   
                }


                /* Recieve message from peer */
                void *recv_buf = NULL;
                struct timespec start;
                clock_gettime(CLOCK_REALTIME, &start);
                ssize_t bytes_got = recv_message_from_peer(&(the_tracker->peer_list[i]), &recv_buf);

                if (bytes_got > 0) {
                    process_peer_message(recv_buf, bytes_got, curr_peer, the_tracker);
                    
                    free(recv_buf);
                    curr_peer->recv_buf = NULL;

                    struct timespec end;
                    clock_gettime(CLOCK_REALTIME, &end);
                    // printf("Time del: %f\n", time_delta(start, end));
                    // fflush(stdout);
                }

                
                request_pieces(curr_peer, the_tracker);

              
                break;

            case BAD_PEER:
                if (the_tracker->peer_list[i].my_bit_field) {
                    free(the_tracker->peer_list[i].my_bit_field);
                    the_tracker->peer_list[i].my_bit_field = NULL;
                }
                if (the_tracker->peer_list[i].peer_sock > 0) {
                    close(the_tracker->peer_list[i].peer_sock);
                    the_tracker->peer_list[i].peer_sock = -1;
                }
                the_tracker->peer_list[i].port = 0;
                break;
            }
        }
    }


    return 0;
}
