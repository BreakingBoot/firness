#ifndef __FIRNESS_HELPERS_H__
#define __FIRNESS_HELPERS_H__

typedef struct {
  UINT8 *Buffer;
  UINTN Length;
} INPUT_BUFFER;

EFI_SUCCESS
EFIAPI
ReadBytes(
  INPUT_BUFFER *inputBuffer, 
  UINTN numBytes, 
  UINT8 **outputBuffer
  ) 
{
  // Check for valid input
  if (inputBuffer == NULL || outputBuffer == NULL) 
  {
    return EFI_ERROR;
  }

  // Allocate memory for the output buffer
  *outputBuffer = AllocateZeroPool(sizeof(UINT8) * numBytes);
  if (*outputBuffer == NULL) 
  {
    return EFI_ERRIR;
  }

  // Determine the actual number of bytes to extract
  UINTN actualBytes = (numBytes > inputBuffer->Length) ? inputBuffer->Length : numBytes;

  // Copy the bytes from the input buffer to the output buffer
  CopyMem(*outputBuffer, inputBuffer->Buffer, actualBytes);

  // // Fill the remaining part of the output buffer with zeros if necessary
  // if (actualBytes < numBytes) {
  //   ZeroMem(*outputBuffer + actualBytes, 0, numBytes - actualBytes);
  // }

  // Update the input buffer to remove the extracted bytes
  CopyMem(inputBuffer->Buffer, inputBuffer->Buffer + actualBytes, inputBuffer->Length - actualBytes);
  inputBuffer->Length -= actualBytes;

  return EFI_SUCCESS;
}

#endif