#include "FirnessHelpers.h"



/**
  Duplicate a string.

  @param  Src  The string to be duplicated.

**/
CHAR16 *
EFIAPI
StrDuplicate (
  IN CHAR16  *Src
  )
{
  CHAR16  *Dest;
  UINTN   Size;

  Size = (StrLen (Src) + 1) * sizeof (CHAR16);
  Dest = AllocateZeroPool (Size);
  if (Dest != NULL) {
    CopyMem (Dest, Src, Size);
  }

  return Dest;
}


EFI_STATUS
EFIAPI
ReadBytes(
  IN INPUT_BUFFER *inputBuffer, 
  IN UINTN numBytes, 
  OUT VOID *outputBuffer
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