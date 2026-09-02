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

typedef enum PointerKind_Tag {
  Owned,
  Borrowed,
  Null,
} PointerKind_Tag;

typedef struct PointerKind {
  PointerKind_Tag tag;
  union {
    struct {
      void *owned;
    };
    struct {
      const void *borrowed;
    };
  };
} PointerKind;

typedef struct Pointer_Runtime {
  struct PointerKind kind;
} Pointer_Runtime;

/**
 * Wrapper around [`tokio::runtime::Runtime`] that can be safely passed across the FFI boundary.
 */
typedef struct Runtime {
  struct Pointer_Runtime inner;
} Runtime;

/**
 * FFI-owned sequencer.
 *
 * - A [`StorageActor`] used to get acess to db.
 * - An [`ExecutorActor`] used to query the node.
 * - The [`Runtime`] used to run async queries against the store (either owned or borrowed),
 *   already FFI-safe.
 */
typedef struct SequencerServiceFFI {
  void *storage_actor;
  void *executor_actor;
  struct Runtime runtime;
} SequencerServiceFFI;

/**
 * Simple wrapper around a pointer to a value or an error.
 *
 * Pointer is not guaranteed. You should check the error field before
 * dereferencing the pointer.
 */
typedef struct PointerResult_SequencerServiceFFI__OperationStatus {
  struct SequencerServiceFFI *value;
  enum OperationStatus error;
} PointerResult_SequencerServiceFFI__OperationStatus;

typedef struct PointerResult_SequencerServiceFFI__OperationStatus InitializedSequencerServiceFFIResult;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Creates and starts an sequencer based on the provided
 * configuration file path.
 *
 * # Arguments
 *
 * - `runtime`: A runtime for the sequencer to run on, or null to have the sequencer create and own
 *   one.
 * - `config_path`: A pointer to a string representing the path to the configuration file.
 *
 * # Returns
 *
 * An `InitializedSequencerServiceFFIResult` containing either a pointer to the
 * initialized `SequencerServiceFFI` or an error code.
 *
 * # Safety
 * The caller must ensure that:
 * - `runtime` is either null or a valid pointer to a [`Runtime`] that outlives the sequencer.
 * - `config_path` is a valid pointer to a null-terminated C string.
 */
InitializedSequencerServiceFFIResult start_sequencer(const struct Runtime *runtime,
                                                     const char *config_path);

/**
 * Stops and frees the resources associated with the given sequencer service.
 *
 * # Arguments
 *
 * - `sequencer`: A pointer to the `SequencerServiceFFI` instance to be stopped.
 *
 * # Returns
 *
 * An `OperationStatus` indicating success or failure.
 *
 * # Safety
 *
 * The caller must ensure that:
 * - `sequencer` is a valid pointer to a `SequencerServiceFFI` instance
 * - The `SequencerServiceFFI` instance was created by this library
 * - The pointer will not be used after this function returns
 */
enum OperationStatus stop_sequencer(struct SequencerServiceFFI *sequencer);

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
