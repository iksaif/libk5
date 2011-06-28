#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#if defined(_WIN32)
#include <winsock.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <k5.h>

#if defined(__linux__)
#include <et/com_err.h>
#else
#include <com_err.h>
# if defined(_WIN32)
extern et_old_error_hook_func set_com_err_hook (et_old_error_hook_func);
# endif
#endif

enum action {
  INTERACTIVE = 1,
  LIST,
  DESTROY,
  TGT,
  SERVICE,
  MSLSA
};

struct opt
{
  k5_context k5;
  int action;
  char *hostname;
  char *service;
  char *principal;
  char *cache;
};

static void usage()
{
  fprintf(stderr, "Usage: krb5-test [options]\n"
	  "\n"
	  "-i, --interactive     interactive mode (default)\n"
	  "-l, --list            list tickets\n"
	  "-d, --destroy         destroy tickets\n"
	  "-t, --tgt             get tgt\n"
	  "-s, --service         get service ticket\n"
	  "-m, --mslsa           import mslsa cache\n"
	  "\n"
	  "-p, --principal       principal ([service/]host@REALM)\n"
	  "-H, --host            host\n"
	  "-S, --service-name    service name\n"
	  "-c, --cache           cache name\n");
  exit(1);
}

static const struct option long_options[] =
  {
    {"interactive", no_argument, NULL, 'i'},
    {"list", no_argument, NULL, 'l'},
    {"destroy", no_argument, NULL, 'd'},
    {"tgt", no_argument, NULL, 't'},
    {"service", no_argument, NULL, 's'},
    {"mslsa", no_argument, NULL, 'm'},
    {"principal", required_argument, NULL, 'p'},
    {"host", required_argument, NULL, 'H'},
    {"service-name", required_argument, NULL, 'S'},
    {"cache", required_argument, NULL, 'c'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
  };

static void parse_args(int argc, char *argv[], struct opt *opt)
{
  while (1) {
    char c = getopt_long(argc, argv, "ildtsmp:H:S:c:h",
			 long_options, NULL);

    if (c == -1)
      break ;

    switch(c) {
    case 'i':
    case 'l':
    case 'd':
    case 't':
    case 's':
    case 'm':
      if (opt->action)
	usage();

      if (c == 'i')
	opt->action = INTERACTIVE;
      if (c == 'l')
	opt->action = LIST;
      if (c == 'd')
	opt->action = DESTROY;
      if (c == 't')
	opt->action = TGT;
      if (c == 's')
	opt->action = SERVICE;
      if (c == 'm')
	opt->action = MSLSA;
      break;
    case 'p':
      if (opt->principal)
	usage();
      opt->principal = strdup(optarg);
      break;
    case 'H':
      if (opt->hostname)
	usage();
      opt->hostname = strdup(optarg);
      break;
    case 'S':
      if (opt->service)
	usage();
      opt->service = strdup(optarg);
      break;
    case 'c':
      if (opt->cache)
	usage();
      opt->cache = strdup(optarg);
      break;
    case 'h':
    case '?':
      usage();
      break ;
    default:
      if (isprint(c))
	printf("unknown arg %c\n", c);
      usage();
    }
  }
}

static void check_opts(struct opt *opt)
{
  if (opt->action == TGT && !opt->principal) {
    fprintf(stderr, "no principal specified (see --help)\n");
    exit(1);
  }

  if (opt->action == SERVICE && !opt->principal
      && !(opt->hostname && opt->service)) {
    fprintf(stderr, "no service specified (see --help)\n");
    exit(1);
  }

  if (!opt->action)
    opt->action = INTERACTIVE;
}

static void free_opts(struct opt *opt)
{
  free(opt->hostname);
  free(opt->service);
  free(opt->principal);
  free(opt->cache);
}

static void list(struct opt *opt)
{
  int ret, i;
  k5_klist_entries klist;

  ret = k5_klist(opt->k5, &klist);

  if (ret) {
    fprintf(stderr, "[-] klist failed\n");
    return ;
  }

  printf("[+] Principal: %s\n", klist.defname);

  for (i = 0; i < klist.count; ++i) {
    k5_ticket *ticket = &klist.tickets[i];

    printf("\nTicket %d: \n", i);
    printf(" server: %s\n client: %s\n", ticket->server_name, ticket->client_name);
    printf(" key: %s\n ticket: %s\n", ticket->key_enc, ticket->ticket_enc);
    printf(" flags: %s\n", ticket->flags);
    printf(" data: %d bytes\n", (int)ticket->data_size);
    printf(" auth: %s", ctime(&ticket->authtime));
    printf(" start: %s", ctime(&ticket->starttime));
    printf(" end: %s", ctime(&ticket->endtime));
    printf(" renew: %s", ctime(&ticket->renew_till));
    printf(" kvno: %d\n", ticket->ticket->enc_part.kvno);
  }

  k5_clear_klist(opt->k5, &klist);
}

static void destroy(struct opt *opt)
{
  k5_kdestroy(opt->k5);
}

static void tgt(struct opt *opt)
{
  k5_kinit_req req;
  int ret;

  memset(&req, 0, sizeof (req));
  req.action = K5_KINIT_PW;
  req.forwardable = 1;
  req.proxiable = 1;
  req.principal_name = opt->principal;
  if (opt->service)
    req.service_name = opt->service;
  req.prompter = krb5_prompter_posix;

  fprintf(stderr, "[ ] Trying to get a new TGT\n");

  ret = k5_kinit(opt->k5, &req, NULL);

  if (opt->service) {
    if (ret)
      fprintf(stderr, "[-] Failed to get service ticket for %s\n", opt->service);
    else
      fprintf(stderr, "[+] Successfully got a new service ticket for %s\n", opt->service);
  } else {
    if (ret)
      fprintf(stderr, "[-] Failed to get TGT\n");
    else
      fprintf(stderr, "[+] Successfully got a new TGT\n");
  }

  return ;
}

static int service(struct opt *opt)
{
  k5_ticket ticket;
  int ret;

  if (opt->principal)
    fprintf(stderr, "[ ] Trying to get a service ticket for %s\n", opt->principal);
  else
    fprintf(stderr, "[ ] Trying to get a service ticket for %s@%s\n", opt->service, opt->hostname);

  if (opt->principal)
    ret = k5_get_service_ticket(opt->k5, NULL, opt->principal, &ticket);
  else
    ret = k5_get_service_ticket_gss(opt->k5, opt->service, opt->hostname, &ticket);

  if (ret) {
    fprintf(stderr, "[-] Failed to get a service ticket\n");
  } else {
    fprintf(stderr, "[+] Successfully fetched service ticket\n");
    printf(" server: %s\n client: %s\n", ticket.server_name, ticket.client_name);
    if (opt->hostname)
      printf(" gss: %s\n", ticket.gss_base64);
    k5_clear_ticket(opt->k5, &ticket);
  }

  return ret;
}

#ifdef WIN32
static int mslsa(struct opt *opt)
{
  fprintf(stderr, "[ ] Trying to import tokens from MSLSA cache\n");

  if (!k5_ms2mit(opt->k5)) {
    fprintf(stderr, "[+] Successfully imported MSLSA cache\n");
    return 0;
  }

  fprintf(stderr, "[-] Failed to import MSLSA, checking registry\n");

  if (!k5_mslsa_check_registry()) {
    fprintf(stderr, "[-] Unknown failure, exiting. Check that you're really connected to your AD\n");
    return -1;
  }

  fprintf(stderr, "[-] Regitry modification needed...\n");

  if (k5_mslsa_set_registry(1)) {
    fprintf(stderr, "[-] Failed to apply registry modification, exiting\n");
    return -1;
  } else {
    fprintf(stderr, "[+] Successfully patched registry\n");
  }

  fprintf(stderr, "[ ] Re-Trying to import tokens from MSLSA cache\n");

  if (k5_ms2mit(opt->k5)) {
    fprintf(stderr, "[-] Failed two times to import MSLSA, exiting\n");
    return -1;
  }

  fprintf(stderr, "[+] Successfully imported MSLSA cache\n");
  return 0;
}
#else
static void mslsa(struct opt *opt)
{
  fprintf(stderr, "Only available on win32 platform\n");
}
#endif

static char *ip2str(const struct sockaddr *sa, char *s, size_t maxlen)
{
  memset(s, 0, maxlen);

  switch(sa->sa_family) {
  case AF_INET:
    inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
	      s, maxlen);
    break;
  case AF_INET6:
    inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
	      s, maxlen);
    break;

  default:
    strncpy(s, "Unknown AF", maxlen);
    return NULL;
  }

  return s;
}

static void check_dns(const char *service)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  char str[INET6_ADDRSTRLEN];
  int ret;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = 0;
  hints.ai_flags = 0;
  hints.ai_protocol = SOCK_STREAM; /* Set Protocol to avoid duplicates */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  ret = getaddrinfo(service, NULL, &hints, &result);
  if (ret != 0) {
    fprintf(stderr, "[-] getaddrinfo(%s): %s\n", service, gai_strerror(ret));
    return ;
  }

  fprintf(stderr, "[ ] getaddrinfo(%s) = ", service);

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    ip2str(rp->ai_addr, str, sizeof (str));
    fprintf(stderr, "%s ", str);
  }

  fprintf(stderr, "\n");

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    char host[NI_MAXHOST], service[NI_MAXSERV];

    ip2str(rp->ai_addr, str, sizeof (str));

    ret = getnameinfo(rp->ai_addr, rp->ai_addrlen,
		      host, NI_MAXHOST,
		      service, NI_MAXSERV, NI_NUMERICSERV);

    if (ret != 0) {
      fprintf(stderr, "[-] getnameinfo(%s): %s\n", str, gai_strerror(ret));
      continue ;
    }

    fprintf(stderr, "[ ] getnameinfo(%s): %s\n", str, host);
  }

  freeaddrinfo(result);
}

static void check_tgt(struct opt *opt)
{
  k5_klist_entries klist;
  int ret, i;

  ret = k5_klist(opt->k5, &klist);

  if (ret) {
    fprintf(stderr, "[-] klist failed\n");
    return ;
  }

  fprintf(stderr, "[+] Principal: %s\n", klist.defname);

  for (i = 0; i < klist.count; ++i) {
    k5_ticket *ticket = &klist.tickets[i];

    if (strstr(ticket->server_name, "krbtgt/") == ticket->server_name) {
      fprintf(stderr, "[+] server: %s - client: %s\n", ticket->server_name, ticket->client_name);
    }
  }

  k5_clear_klist(opt->k5, &klist);
}

static void interactive(struct opt *opt)
{
  if (!opt->principal && !(opt->hostname && opt->service)) {
    char service[1024];
    char *p = NULL;

    memset(service, 0, sizeof(service));

    while ((p = strchr(service, '@')) == NULL) {
      fprintf(stderr, "[?] Service (service@hostname): ");
      if (fgets(service, sizeof(service), stdin)) {
	service[strlen(service) - 1] = '\0';
      }
    }

    *p = '\0';
    opt->service = strdup(service);
    opt->hostname = strdup(p + 1);
  }

  if (opt->hostname)
    check_dns(opt->hostname);

  fprintf(stderr, "[ ] Checking your TGT\n");
  check_tgt(opt);

  if (!service(opt)) {
    fprintf(stderr, "[ ] Showing available tickets\n");
    list(opt);
    return ;
  }

#ifdef WIN32
  if (!mslsa(opt)) {
    fprintf(stderr, "[ ] Re-Trying to get a service ticket\n");

    if (!service(opt)) {
      fprintf(stderr, "[ ] Showing available tickets\n");
      list(opt) ;
      return ;
    }
  }
#endif

  fprintf(stderr, "[ ] Checking your TGT\n");
  check_tgt(opt);
}

static void
hook(const char *whoami, long code,
     const char *format, va_list args)
{
  fprintf(stderr, "[-] %s: %s ", whoami, error_message(code));
  vfprintf(stderr, format, args);
  fprintf(stderr, "\n");
}

int main(int argc, char *argv[])
{
  struct opt opt;
  memset(&opt, 0, sizeof(opt));
  parse_args(argc, argv, &opt);
  check_opts(&opt);

  set_com_err_hook(hook);
  if (k5_init_context(&opt.k5, opt.cache)) {
    fprintf(stderr, "failed to initilize kerberos\n");
    return -1;
  }

  k5_set_verbose(opt.k5, 1);

  if (opt.action == INTERACTIVE)
    interactive(&opt);
  else if (opt.action == LIST)
    list(&opt);
  else if (opt.action == SERVICE)
    service(&opt);
  else if (opt.action == MSLSA)
    mslsa(&opt);
  else if (opt.action == TGT)
    tgt(&opt);
  else if (opt.action == DESTROY)
    destroy(&opt);

  free_opts(&opt);
  k5_free_context(opt.k5);

  return 0;
}
