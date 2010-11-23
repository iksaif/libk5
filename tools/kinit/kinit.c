#include <stdio.h>
#include <time.h>
#include <string.h>
#include <k5.h>

int main(int argc, char *argv[])
{
  k5_context k5 = NULL;

  if (argc != 3 && argc != 2) {
    fprintf(stderr, "Usage: kinit principal [service]\n");
    return -1;
  }

  k5_init_context(&k5, NULL);
  {
    k5_kinit_req req;
    k5_ticket ticket;

    memset(&req, 0, sizeof (req));
    req.action = K5_KINIT_PW;
    //req.action = K5_RENEW;
    //req.action = K5_VALIDATE;
    req.forwardable = 1;
    req.proxiable = 1;
    req.principal_name = argv[1];
    req.service_name = argv[2];
    req.prompter = krb5_prompter_posix;

    if (!k5_kinit(k5, &req, &ticket)) {
      printf("server: %s\nclient: %s\n", ticket.server_name, ticket.client_name);
      k5_clear_ticket(k5, &ticket);
    }
  }

  k5_free_context(k5);
}
