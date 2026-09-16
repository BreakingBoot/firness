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

__attribute__((no_sanitize("address")))
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

  if (inputBuffer->Buffer == NULL)
  {
    inputBuffer->Length = 0;
  }

  // Determine the actual number of bytes to extract. Both operands are UINTN, so
  // "Length - numBytes >= 0" would always be true and over-read a short buffer.
  UINTN actualBytes = (inputBuffer->Length >= numBytes) ? numBytes : inputBuffer->Length;

  // Bytes the input cannot supply are zero, per the contract in FirnessHelpers.h
  SetMem(outputBuffer, numBytes, 0);

  // Copy the bytes from the input buffer to the output buffer
  if (actualBytes > 0)
  {
    CopyMem((UINT8*)outputBuffer, inputBuffer->Buffer, actualBytes);
  }

  // Update the input buffer to remove the extracted bytes. Advance the cursor inside
  // the buffer; advancing inputBuffer itself walks the struct pointer off its object.
  inputBuffer->Buffer += actualBytes;
  inputBuffer->Length -= actualBytes;

  return EFI_SUCCESS;
}

VOID
EFIAPI
FirnessMakeDevicePath (
  IN OUT VOID   *Buffer,
  IN     UINTN  Size
  )
{
  UINT8  *Bytes;
  UINTN  Offset;
  UINTN  Length;

  //
  // Four bytes is one node header, and the shortest legal path is a single End node.
  //
  if ((Buffer == NULL) || (Size < 4)) {
    return;
  }

  Bytes  = (UINT8 *)Buffer;
  Offset = 0;

  //
  // Advance while this node's header and an End node after it both still fit.
  //
  while ((Offset + 4 + 4) <= Size) {
    if (Bytes[Offset] == 0x7F) {
      break;                                   // the fuzzer ended the path here
    }

    Length = (UINTN)Bytes[Offset + 2] | ((UINTN)Bytes[Offset + 3] << 8);

    //
    // A length below the header never advances, and one that runs past the buffer is
    // the overread this exists to prevent. Either way the path ends here.
    //
    if ((Length < 4) || ((Offset + Length + 4) > Size)) {
      break;
    }

    Offset += Length;
  }

  Bytes[Offset + 0] = 0x7F;                    // END_DEVICE_PATH_TYPE
  Bytes[Offset + 1] = 0xFF;                    // END_ENTIRE_DEVICE_PATH_SUBTYPE
  Bytes[Offset + 2] = 4;
  Bytes[Offset + 3] = 0;
}
