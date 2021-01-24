#!/usr/bin/env bash

# Auto generate single AllTests file for CuTest.
# Searches through all *.c files in the current directory.
# Prints to stdout.
# Author: Asim Jalis
# Date: 01/08/2003

if test $# -eq 0 ; then FILES=*/*.c ; else FILES=$* ; fi

echo '

/* This is auto-generated code. Edit at your own peril. */
#include <stdio.h>
#include <stdlib.h>

#include "CuTest.h"

'

cat $FILES | grep '^_TEST(' | 
    sed -e 's/^_TEST(//' \
        -e 's/).*$//' \
        -e 's/$/(CuTest*);/' \
        -e 's/^/extern TEST_/'

echo \
'

int RunAllTests(void) 
{
    CuString *output = CuStringNew();
    CuSuite* suite = CuSuiteNew();
    int fails;

'
cat $FILES | grep '^_TEST(' | 
    sed -e 's/^_TEST(//' \
        -e 's/).*$//' \
        -e 's/^/    SUITE_ADD_TEST(suite, TEST_/' \
        -e 's/$/);/'

echo \
'
    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    printf("%s\n", output->buffer);
    CuStringDelete(output);
    fails = suite->failCount;
    CuSuiteDelete(suite);
    return (fails);
}

int test_main(void)
{
  return (RunAllTests());
}
'
