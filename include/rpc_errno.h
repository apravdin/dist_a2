#ifndef RPC_ERRNO_H
#define RPC_ERRNO_H

#define RETVAL_SUCCESS 0

// General errors
#define ERRNO_ENV_VAR_NOT_SET   -1
#define ERRNO_FAILED_TO_CONNECT -2
#define ERRNO_FAILED_READ       -3
#define ERRNO_FAILED_SEND       -4
#define ERRNO_NO_SPACE          -5


// RPC errors
#define ERRNO_FUNC_NOT_FOUND            -10
#define ERRNO_INIT_FAILED               -11
#define ERRNO_FAILED_TO_START_SERVER    -12
#define ERRNO_REGISTER_FAILED           -13
#define ERRNO_EXECUTE_FAILED            -14

// Binder errors
#define BINDER_INVALID_COMMAND -20

#endif /* RPC_ERRNO_H */
