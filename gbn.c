#include "gbn.h"
/*--- Timeout ---*/
volatile sig_atomic_t to_flag = false;

/*Sets timeout flag to alert program*/
void timeout_handler( int sig )
{
    to_flag = true;
		printf("~~ Timeout ~~\n");
}
/*Reset timeout*/
void reset_timeout()
{
	to_flag = false;
}

state_t machine = {SLOW, CLOSED, 2};

/*--- Global ---*/
struct sockaddr * hostAddr, * clientAddr;
socklen_t hostLen, clientLen;

/*--- Packet Tools ---*/
gbnhdr make_header(int type, uint8_t sequence_num)
{
	gbnhdr header;
	header.type = type;
	header.seqnum = sequence_num;
	header.checksum = 0; /* initial checksum*/

	return header;
}

gbnhdr* make_packet(int type, uint8_t sequence_num, char *buffer, int data_length)
{
	gbnhdr * packet = malloc(sizeof(gbnhdr));
	packet->type = type;
	packet->seqnum = sequence_num;

	memcpy(packet->data, buffer, data_length);
  packet->len = data_length;

	packet->checksum = checksum((uint16_t *) buffer, data_length);

	return packet;
}

int check_packet(gbnhdr * packet, int type, int len)
{
	/* Check timeout*/
	if (to_flag == true || len ==-1) {
		reset_timeout();
		return -1;
	}
	/* Check type */
	else if (packet->type != type) {
		printf("Wrong packet type received, %d, expecting %d\n", packet->type, type);
		return -1;
	}
  /* Check SYN*/
  else if (packet->type == SYN) {
    printf("Recieved SYN\n");
    return 0;
  }
	/* Check seqnum*/
	else if (packet->seqnum < machine.seqnum){
		printf("Wrong seqnum, rec: %d, sent: %d\n",packet->seqnum, machine.seqnum );
		return -1;
	}
  printf("Received packet type %d\n", packet->type);
	return 0;
}

int check_header(char *buffer, int length)
{
	if (length != 4){
		return -1;
	}
	else if (buffer[0] == SYN){
		return 0;
	}

  return -1;
}

/*/*/
uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags)
{
	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	int cur_mode = machine.mode;
	int cur_seq = rand();

	machine.seqnum = cur_seq;

	int remaining = len;
	int cur_size = 0;
	int track = 0;
	int attempts;


	char * tempBuf = (char *) malloc(DATALEN * sizeof(char));
	/*Keep sending till end of file*/
	while (track < len) {

		/* Clear the packet buffer*/
		memset(tempBuf, '\0', DATALEN);

		if (remaining >= DATALEN) {
			cur_size = DATALEN;
		}
		else {
			cur_size = remaining;
		}

		/* SLOW*/
    attempts = 0;
		if (cur_mode == SLOW) {
      printf("Sending slow\n");
      gbnhdr * nextPack;
      gbnhdr * rec_buf;

			memcpy(tempBuf, buf + track, cur_size);

			while(machine.state != ACK_RCVD && attempts < 5) {
				nextPack = make_packet(DATA, cur_seq, tempBuf, cur_size);


				int rtn = sendto(sockfd, nextPack, sizeof(*nextPack), 0, clientAddr, clientLen);

				if (rtn == -1) {
					printf("Failed to send packet, attempt: %d\n", ++attempts);
					continue;
				}

				machine.state = DATA_SENT;
				alarm(TIMEOUT);
        printf("Sent packet, waiting for response...\n");
				rec_buf = malloc(sizeof(gbnhdr));
				int rec_size = recvfrom(sockfd, rec_buf, sizeof(gbnhdr), 0, hostAddr, &hostLen);


        if(check_packet(rec_buf, DATAACK, rec_size) == 0){
          machine.state = ACK_RCVD;
					cur_mode = FAST;
          track += cur_size;
          remaining = remaining - cur_size;
          cur_seq++;
          machine.seqnum = cur_seq;
        } else {
          attempts++;
        }

			}

			/* Close out after 5 attempts*/
			if (machine.state == DATA_SENT) {
        printf("Failed after %d attempts\n", attempts);
				return -1;
			}

      free(nextPack);
      free(rec_buf);
			machine.state = ESTABLISHED;
		} else { /* FAST*/
      printf("Sending fast\n");
			memcpy(tempBuf, buf + track, cur_size);
			machine.state = ESTABLISHED;

			int firstTrack = track;
			int firstLen  = cur_size;
			int firstSeqnum = cur_seq;

			/* send first packet*/
      gbnhdr * firstPack = make_packet(DATA, cur_seq, tempBuf, cur_size);

      sendto(sockfd, firstPack,
                sizeof(*firstPack), 0, hostAddr, hostLen);

			machine.state = DATA_SENT;


			/* Clear the buffer*/
			memset(tempBuf, '\0', DATALEN);

			/* Send second only if theres still remaining buffer*/
      int secondTrack;
      int secondLen;
      int secondSeqnum;
			if (track + cur_size < len) {
				cur_seq++;
        machine.seqnum = cur_seq;
        track += cur_size;

        secondTrack = track;
        secondSeqnum = cur_seq;

        /* Check size*/
        if (remaining >= DATALEN*2) {
  				secondLen = DATALEN;
  			}
  			else {
  				secondLen = remaining - DATALEN;
  			}

        memcpy(tempBuf, buf + track, cur_size);
        gbnhdr * secondPack = make_packet(DATA, cur_seq, tempBuf, cur_size);

        sendto(sockfd, secondPack,
                                sizeof(*secondPack), 0, hostAddr, hostLen);

			}
      else {
        secondSeqnum = cur_seq;
        secondLen = firstLen;
      }

      cur_seq = firstSeqnum;
      gbnhdr * rec_buf;
      while(attempts < 5 && machine.state != ACK_RCVD){
        alarm(TIMEOUT);
        rec_buf = malloc(sizeof(gbnhdr));
        int rec_size = recvfrom(sockfd, rec_buf, sizeof * rec_buf, 0, hostAddr, &hostLen);

        if(check_packet(rec_buf, DATAACK, rec_size) ==0){
          if(rec_buf->seqnum == secondSeqnum) {
            printf("Ack second packet, seqnum: %d\n", rec_buf->seqnum);
            machine.state = ACK_RCVD;
            track += secondLen;
            remaining -= (secondLen);
            cur_seq++;
            machine.seqnum = cur_seq;
          }
          else if(rec_buf->seqnum == firstSeqnum) {
            printf("Ack first packet, seqnum: %d\n", rec_buf->seqnum);
            remaining -= firstLen;
            cur_seq = secondSeqnum;
          }
          else {
            attempts++;
            continue;
          }
        } else {
          if (rec_buf->seqnum == firstSeqnum) {
            cur_mode = SLOW;
            track = firstTrack;
            cur_seq = firstSeqnum;
            break;
          }
          else if (rec_buf->seqnum == secondSeqnum && cur_seq == secondSeqnum){
            cur_mode = SLOW;
            track = secondTrack;
            break;
          }
          else {
            attempts++;
          }
        }
        free(rec_buf);
      }
      /* Start over again with first packer */
      if (attempts == 5) {
        cur_mode = SLOW;
        track = firstTrack;
        cur_seq = firstSeqnum;
      }
		}
	}
	machine.isFin = 1;
  printf("Finished sending, remaining %d\n", attempts);
	return remaining;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags)
{
  printf("Receiving packet...\n");
  gbnhdr * data_buffer = malloc(sizeof(gbnhdr));
	int rtn = recvfrom(sockfd, data_buffer, sizeof(gbnhdr), 0, clientAddr, &clientLen);

	int lenData = sizeof(*data_buffer->data);
	/* Check packet type */
	if (data_buffer->type == DATA) {
    printf("Received DATA\n");
		char cp_buf[lenData];
		memcpy(cp_buf, data_buffer->data, lenData);
		int Sum = checksum(buf, lenData);

		gbnhdr ack_header = make_header(DATAACK, data_buffer->seqnum);
		int sendack = sendto(sockfd, &ack_header, sizeof(gbnhdr), 0, hostAddr, hostLen);
		if (sendack == -1){
			return -1;
		}

		memcpy(buf, data_buffer->data, data_buffer->len);
		return data_buffer->len;
	}
	else {
    printf("Received other\n");
		gbnhdr finack_header = make_header(FINACK, 0);
		if(sendto(sockfd, &finack_header, sizeof(gbnhdr), 0, hostAddr, hostLen) == -1)
      return -1;
    else
      return 0;
	}
}

int gbn_close(int sockfd)
{
  printf("Closing connection\n");
  if (sockfd < 0) {
		return(-1);
	}

	else {
		if (machine.isFin == 1) {
			gbnhdr finHeader = make_header(FIN, 0);
			if (sendto(sockfd, &finHeader, sizeof(gbnhdr), 0, clientAddr, clientLen) == -1)
			{
				return-1;
			}
		}

		else {
			gbnhdr finackHeader = make_header(FINACK, 0);
			int sendfinack = sendto(sockfd, &finackHeader, sizeof(gbnhdr), 0, hostAddr, hostLen);
			if (sendfinack == -1)
				return -1;
			close(sockfd);
		}
	}

	return 0;
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen)
{
	clientAddr = server;
	clientLen = socklen;

	/* If connection is broken*/
	if (sockfd < 0)
		return -1;

	int attempt = 0;
	gbnhdr syn_header = make_header(SYN, 0);
	machine.state = SYN_SENT;
	machine.isFin = 0;
	printf("SYN sent\n");

	/* Attempt to send the SYN packet up to 5 times*/
	while (attempt < 5) {

		int rtn = sendto(sockfd, &syn_header, sizeof syn_header, 0, server, socklen);

		if (rtn == -1) { /* Send error, try again*/
			attempt++;
			continue;
		}

		alarm(TIMEOUT); /* Signal at timeout*/

		/*Receive ack*/
		/*char buf[1030];*/
		gbnhdr * rec_buf = malloc(sizeof(gbnhdr));
		int rec_size = recvfrom(sockfd, rec_buf, sizeof(gbnhdr), 0, hostAddr, &hostLen);

		/* Timeout or nothing received*/
		if (to_flag==true || rec_size == -19) {
			attempt++;
			reset_timeout();
		}
		else { /* Received a packet*/
			if (rec_buf->type == SYNACK) { /* Check to see if we got the right response*/
				machine.state = ESTABLISHED;
				printf("Connection established\n");
				return 0;
			}

			attempt++;
		}
	}

	machine.state = CLOSED;
	return -1;

}

int gbn_listen(int sockfd, int backlog)
{
	printf("Listening...\n");
	gbnhdr * buffer = malloc(sizeof(gbnhdr));
	int ackPack = recvfrom(sockfd, buffer, sizeof(gbnhdr), 0, hostAddr, &hostLen);
	printf("Found packet\n");

	return check_packet(buffer, SYN, ackPack);
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen)
{

	hostAddr = server;
	hostLen = socklen;

	if (sockfd < 0) {
		return -1;
	}
	else {
		if (bind(sockfd, server, socklen) != 0){
			return -1;
		}

	}
	printf("Bind complete\n");
	return 0;
}

int gbn_socket(int domain, int type, int protocol)
{

	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

	/*Set timeout handler*/
	signal(SIGALRM, timeout_handler);

	int sock = socket(domain, type, protocol);
	return sock;
}

int gbn_accept(int sockfd, struct sockaddr *host, socklen_t *socklen)
{

	if (sockfd < 0) {
		return(-1);
	}
	else {
		gbnhdr synack_header = make_header(SYNACK, 0);
		int sendsynack = sendto(sockfd, &synack_header, sizeof(synack_header), 0, hostAddr, hostLen);
		if (sendsynack == -1) return -1;
	}
  printf("Accept connection to peer\n");
	return sockfd;
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen)
{
	char *buffer = malloc(len);
	memcpy(buffer, buf, len);


	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){
		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){

			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buffer[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buffer[index] = c;
		}

		/*----- Sending the packet -----*/
		int retval = sendto(s, buffer, len, flags, to, tolen);
		free(buffer);
		return retval;
	}
	/*----- Packet lost -----*/
	else
		return(len);  /* Simulate a success */
}
