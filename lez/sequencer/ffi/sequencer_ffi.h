#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum OperationStatus {
  Ok = 0,
  NullPointer = 1,
  InitializationError = 2,
  ClientError = 3,
} OperationStatus;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

bool is_ok(const enum OperationStatus *self);

bool is_error(const enum OperationStatus *self);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
