#include <stdio.h>
#include <string.h>
#include <k5.h>

int main(int argc, char *argv[])
{
  k5_context k5 = NULL;

  k5_init_context(&k5, NULL);
  k5_kdestroy(k5);
  k5_free_context(k5);
}
