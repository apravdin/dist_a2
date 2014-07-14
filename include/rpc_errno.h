#ifndef RPC_ERRNO_H
#define RPC_ERRNO_H

#define RETVAL_SUCCESS 1

// General errors
#define ERRNO_ENV_VAR_NOT_SET   -1
#define ERRNO_FAILED_TO_CONNECT -2
#define ERRNO_FAILED_READ       -3
#define ERRNO_FUNC_NOT_FOUND    -4
#define ERRNO_FAILED_SEND       -5


// Binder errors
#define BINDER_INVALID_COMMAND -1

#endif /* RPC_ERRNO_H */
