#ifndef __wrappedlibxauTYPES_H_
#define __wrappedlibxauTYPES_H_

#ifndef LIBNAME
#error You should only #include this file inside a wrapped*.c file
#endif
#ifndef ADDED_FUNCTIONS
#define ADDED_FUNCTIONS()
#endif


#define SUPER() ADDED_FUNCTIONS()

#endif // __wrappedlibxauTYPES_H_
