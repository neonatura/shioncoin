#ifndef __COMPAT_H
#define __COMPAT_H 1

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#ifndef INvALID_SOCKET
#define INVALID_SOCKET      (unsigned int)(~0)
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR        -1
#endif


#define closesocket(_sk)      descriptor_release(_sk)


#endif
