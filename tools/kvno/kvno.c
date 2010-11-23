#include <time.h>
#include <stdio.h>
#include <string.h>
#include <k5.h>

int main(int argc, char *argv[])
{
  k5_context k5 = NULL;
  k5_ticket ticket;

  if (argc != 3) {
    fprintf(stderr, "Usage: kvno service hostname\n");
    return -1;
  }

  k5_init_context(&k5, NULL);
  if (!k5_get_service_ticket(k5, argv[1], argv[2], &ticket)) {
    printf("server: %s\nclient: %s\n", ticket.server_name, ticket.client_name);
    printf("kvno: %d\n", ticket.ticket->enc_part.kvno);
    k5_clear_ticket(k5, &ticket);
  }
  k5_free_context(k5);
  return 0;
}
