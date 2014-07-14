/*
 * rpc.h
 *
 * This file defines all of the rpc related infomation.
 */
#ifdef __cplusplus
extern "C" {
#endif

#define LOOKUP              1
#define EXECUTE             2
#define EXECUTE_SUCCESS     3
#define EXECUTE_FAILURE     4
#define INIT                5
#define REGISTER            6
#define TERMINATE           7

#define NAME_SIZE           64

#define ARG_TYPE_MASK       0xFFFF0000
#define ARG_ARRAY_LEN_MASK  0x0000FFFF


#define ARG_CHAR    1
#define ARG_SHORT   2
#define ARG_INT     3
#define ARG_LONG    4
#define ARG_DOUBLE  5
#define ARG_FLOAT   6

#define ARG_INPUT   31
#define ARG_OUTPUT  30


typedef int (*skeleton)(int *, void **);

extern void rpcReset();
extern int rpcInit();
extern int rpcCall(char* name, int* argTypes, void** args);
extern int rpcCacheCall(char* name, int* argTypes, void** args);
extern int rpcRegister(char* name, int* argTypes, skeleton f);
extern int rpcExecute();
extern int rpcTerminate();

#ifdef __cplusplus
}
#endif

