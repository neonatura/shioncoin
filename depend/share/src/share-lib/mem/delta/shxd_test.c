
#include "share.h"

#define XD3_MAIN
#include "xdelta3.c"

int main(int argc, char *argv[])
{
  return (xd3_selftest());
}

