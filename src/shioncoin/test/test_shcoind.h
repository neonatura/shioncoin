
#ifndef __TEST__SHTEST_H__
#define __TEST__SHTEST_H__


#include "shcoind.h"
#include "CuTest.h"

#define _TEST(_name) void TEST_##_name(CuTest *ct) 
#define _END_TEST

#define _TRUE(testexpr) \
  CuAssertTrue(ct, (testexpr))
#define _FALSE(testexpr) \
  CuAssertTrue(ct, !(testexpr))

#define _TRUE_EQUAL(_a,_b) \
  _TRUE((_a) == (_b))
#define _TRUE_NE(_a,_b) \
  _TRUE((_a) != (_b))
#define _TRUE_GT(_a,_b) \
  _TRUE((_a) > (_b))
  

static void *_cutest_ptr;
#define _TRUEPTR(testptr) \
  _cutest_ptr = (testptr); CuAssertPtrNotNull(ct, _cutest_ptr)

int test_shcoind_main(void);



#endif /* ndef __TEST__SHTEST_H__ */


