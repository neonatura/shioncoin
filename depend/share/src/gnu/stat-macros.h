/* All the mode bits that can be affected by chmod. */ 
/* Macros for futimens and utimensat.  */

#if !S_ISUID
# define S_ISUID 04000
#endif

#if !S_ISGID
# define S_ISGID 02000
#endif

/* S_ISVTX is a common extension to POSIX.  */
#ifndef S_ISVTX
# define S_ISVTX 01000
#endif

#define CHMOD_MODE_BITS \
  (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO)
