#include <stdio.h>
#include <time.h>
#include <string.h>
#include <k5.h>

int main(int argc, char *argv[])
{
  k5_context k5 = NULL;
  k5_klist_entries klist;
  int i;

  k5_init_context(&k5, NULL);
  k5_klist(k5, &klist);

  printf("Principal: %s\n", klist.defname);
  for (i = 0; i < klist.count; ++i) {
    k5_ticket *ticket = &klist.tickets[i];

    printf("\nTicket %d: \n", i);
    printf(" server: %s\n client: %s\n", ticket->server_name, ticket->client_name);
    printf(" key: %s\n ticket: %s\n", ticket->key_enc, ticket->ticket_enc);
    printf(" flags: %s\n", ticket->flags);
    printf(" data: %zd bytes\n", ticket->data_size);
    printf(" auth: %s", ctime(&ticket->authtime));
    printf(" start: %s", ctime(&ticket->starttime));
    printf(" end: %s", ctime(&ticket->endtime));
    printf(" renew: %s", ctime(&ticket->renew_till));
    printf(" kvno: %d\n", ticket->ticket->enc_part.kvno);
  }

  k5_clear_klist(k5, &klist);
  k5_free_context(k5);
}
