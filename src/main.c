#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "kerberos.h"

#if defined(__WXMSW__) || defined(WIN32)
#include <windows.h>

LONG Win32FaultHandler(struct _EXCEPTION_POINTERS *  ExInfo)

{
  char  *FaultTx = "";

  switch(ExInfo->ExceptionRecord->ExceptionCode)
    {
    case EXCEPTION_ACCESS_VIOLATION      :
      FaultTx = "ACCESS VIOLATION"         ; break;
    case EXCEPTION_DATATYPE_MISALIGNMENT :
      FaultTx = "DATATYPE MISALIGNMENT"    ; break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO    :
      FaultTx = "FLT DIVIDE BY ZERO"       ; break;
    default: FaultTx = "(unknown)";           break;
    }
  int    wsFault    = ExInfo->ExceptionRecord->ExceptionCode;
  PVOID  CodeAddress = ExInfo->ExceptionRecord->ExceptionAddress;

  FILE *LogFile = fopen("Win32Fault.log", "w");
  fprintf(LogFile, "****************************************************\n");
  fprintf(LogFile, "*** A Program Fault occurred:\n");
  fprintf(LogFile, "*** Error code %08X: %s\n", wsFault, FaultTx);
  fprintf(LogFile, "****************************************************\n");
  fprintf(LogFile, "***   Address: %08X\n", (int)CodeAddress);
  fprintf(LogFile, "***     Flags: %08X\n",
	  ExInfo->ExceptionRecord->ExceptionFlags);
	fclose(LogFile);
  return EXCEPTION_EXECUTE_HANDLER;
}
void InstallFaultHandler()
{
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER) Win32FaultHandler);
}
#else
void InstallFaultHandler()
{
}
#endif

static void
usage(void)
{
  fprintf(stderr, "krb5_test [-s service] [-u user] [-r REALM]\n");
  exit(0);
}

static const struct option long_options[] =
  {
    {"service", required_argument, NULL, 's'},
    {"realm", required_argument, NULL, 'r'},
    {"user", required_argument, NULL, 'u'},
    {"password", required_argument, NULL, 'p'}
  };

static void
parse_args(int argc, char *argv[], struct vb_krb5 *k)
{
  int s = 0;

  while (1) {
    char c = getopt_long(argc, argv, "s:r:u:p:",
			 long_options, NULL);
    if (c == -1)
      break ;

    switch(c) {
    case 's':
      vbkrb5_set_service(k, optarg);
      s = 1;
      break;
    case 'r':
      vbkrb5_set_realm(k, optarg);
      break;
    case 'u':
      vbkrb5_set_login(k, optarg);
      break;
    case 'p':
      vbkrb5_set_password(k, vbkrb5_simple_password_cb, optarg);
      break;
    default:
      if (isprint(c))
	printf("unknown arg %c\n", c);
      usage();
    }
  }
  if (!s) {
    char service[1024];

    printf("Service: ");
    if (fgets(service, sizeof(service), stdin)) {
      service[strlen(service) - 1] = '\0';
      vbkrb5_set_service(k, service);
    }
  }
}

int
main(int argc, char *argv[])
{
  struct vb_krb5 *k;
  const char *p;

  InstallFaultHandler();

  k = vbkrb5_alloc();
  parse_args(argc, argv, k);

  if (!vbkrb5_check_tokens(k)) {
    printf("Unable to get a token\n");
    if (vbkrb5_errno(k))
      fprintf(stderr, "Error: %s\n", vbkrb5_error(vbkrb5_errno(k)));
    goto out;
  }
  printf("Token (len: %d)\n", vbkrb5_get_otoken_len(k));
  p = vbkrb5_get_otoken_base64(k);
  if (p)
    printf("%s\n", p);
  else
    printf("Can't convert to base64\n");
 out:
  vbkrb5_clear(k);
#if defined(__WXMSW__) || defined(WIN32)
  printf("\nPress a key to exit\n");
  getchar();
#endif
  return 0;
}
