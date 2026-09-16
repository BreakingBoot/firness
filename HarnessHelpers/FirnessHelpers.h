#ifndef __FIRNESS_HELPERS_H__
#define __FIRNESS_HELPERS_H__

#include "FirnessIncludes.h"
typedef struct {
  UINT8 *Buffer;
  UINTN Length;
} INPUT_BUFFER;

// Read in a specified number of bytes from the input buffer
// and copy them to the output buffer. The input buffer is
// updated to remove the extracted bytes. If the input buffer
// does not contain enough bytes, the output buffer is filled
// with zeros. The output buffer is allocated by this function
// and must be freed by the caller. The output buffer can be any
// type of buffer which is why it is a void pointer.
EFI_STATUS
EFIAPI
ReadBytes(
  IN INPUT_BUFFER *inputBuffer, 
  IN UINTN numBytes, 
  OUT VOID *outputBuffer
  );

/**
  Duplicate a string.

  @param  Src  The string to be duplicated.

**/
CHAR16 *
EFIAPI
StrDuplicate (
  IN CHAR16  *Src
  );

/**
  Make a buffer of fuzzer bytes into a device path the callee can walk.

  A device path is a chain of nodes, each carrying its own Length, ending in an End node:
  type 0x7F, subtype 0xFF, length 4. Everything that takes one walks it by those lengths
  until it meets the End -- GetDevicePathSize, DevicePathType, NextDevicePathNode -- and
  none of them takes a bound, because the caller is required to hand over a terminated
  path. A buffer of fuzzer bytes is not one, so they read past it, which is the harness
  breaking the contract rather than the firmware doing anything wrong. Every protocol that
  takes a device path reported the same one-byte overread in DevicePathType because of it.

  Walk it here first: clamp each node's length so the chain stays inside the buffer, and
  write the End node wherever the walk stops. What the fuzzer chose -- how many nodes,
  their types and subtypes, how long each claims to be -- is left alone.

  @param  Buffer  The buffer to fix up, already filled with whatever the fuzzer wanted.
  @param  Size    How many bytes of it there are.

**/
VOID
EFIAPI
FirnessMakeDevicePath (
  IN OUT VOID   *Buffer,
  IN     UINTN  Size
  );

#endif