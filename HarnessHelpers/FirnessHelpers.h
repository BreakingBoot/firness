#ifndef __FIRNESS_HELPERS_H__
#define __FIRNESS_HELPERS_H__

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
STATIC
EFI_STATUS
EFIAPI
ReadBytes(
  INPUT_BUFFER *inputBuffer, 
  UINTN numBytes, 
  VOID *outputBuffer
  )
{
  // Check for valid input
  if (inputBuffer == NULL || outputBuffer == NULL) 
  {
    return EFI_ABORTED;
  }

  // Allocate memory for the output buffer
  outputBuffer = (VOID*)AllocateZeroPool(numBytes);
  if (outputBuffer == NULL) 
  {
    return EFI_ABORTED;
  }

  // Determine the actual number of bytes to extract
  UINTN actualBytes = (numBytes > inputBuffer->Length) ? inputBuffer->Length : numBytes;

  // Copy the bytes from the input buffer to the output buffer
  CopyMem((UINT8*)outputBuffer, inputBuffer->Buffer, actualBytes);

  // Fill the remaining part of the output buffer with zeros if necessary
  if (actualBytes < numBytes) 
  {
    ZeroMem((UINT8*)outputBuffer + actualBytes, numBytes - actualBytes);
  }

  // Update the input buffer to remove the extracted bytes
  CopyMem(inputBuffer->Buffer, inputBuffer->Buffer + actualBytes, inputBuffer->Length - actualBytes);
  inputBuffer->Length -= actualBytes;

  return EFI_SUCCESS;
}

#endif