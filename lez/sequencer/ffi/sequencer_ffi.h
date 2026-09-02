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

/**
 * Initializes logging for the sequencer at `level`.
 *
 * - `level` is a null-terminated string (`off`/`error`/`warn`/`info`/`debug`/ `trace`,
 *   case-insensitive); null or unparseable falls back to `info`.
 *
 * Only the `sequencer_ffi` and `sequencer_core` targets are enabled!
 *
 * # Safety
 * - `level` must be a valid null-terminated C string, or null.
 * - First call to this function wins; subsequent calls are no-ops.
 */
void init_logger(const char *level);

/**
 * # Safety
 * It's up to the caller to pass a proper pointer, if somehow from c/c++ side
 * this is called with a type which doesn't come from a returned `CString` it
 * will cause a segfault.
 */
void free_cstring(char *block);

bool is_ok(const enum OperationStatus *self);

bool is_error(const enum OperationStatus *self);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
