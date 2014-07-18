#include "server_functions.h"
#include <stdio.h>
#include <string.h>
#include <iostream>

int f0_Skel(int *argTypes, void **args) {
  std::cout << "f0 Skel" << std::endl;

  std::cout << "other:" << *(int *)args[0] << " a:" << *(int *)args[1] << " b:" << *(int *)args[2] << std::endl;
  *(int *)args[0] = f0(*(int *)args[1], *(int *)args[2]);
  return 0;
}

int f1_Skel(int *argTypes, void **args) {

  *((long *)*args) = f1( *((char *)(*(args + 1))),
		        *((short *)(*(args + 2))),
		        *((int *)(*(args + 3))),
		        *((long *)(*(args + 4))) );

  return 0;
}

int f2_Skel(int *argTypes, void **args) {

  /* (char *)*args = f2( *((float *)(*(args + 1))), *((double *)(*(args + 2))) ); */
  *args = f2( *((float *)(*(args + 1))), *((double *)(*(args + 2))) );

  return 0;
}

int f3_Skel(int *argTypes, void **args) {

  f3((long *)(*args));
  return 0;
}

/*
 * this skeleton doesn't do anything except returns
 * a negative value to mimic an error during the
 * server function execution, i.e. file not exist
 */
int f4_Skel(int *argTypes, void **args) {

  return -1; /* can not print the file */
}

