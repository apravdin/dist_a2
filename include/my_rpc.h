#ifndef MY_RPC_H
#define MY_RPC_H

#define LOOKUP              1
#define EXECUTE             2
#define EXECUTE_SUCCESS     3
#define EXECUTE_FAILURE     4
#define INIT                5
#define REGISTER            6
#define TERMINATE           7

#define ARG_HASH_MASK       0x3FFF0000
#define ARG_TYPE_MASK       0x0FFF0000
#define ARG_IO_MASK         0xC0000000
#define ARG_ARRAY_LEN_MASK  0x0000FFFF


#endif /* MY_RPC_H */
