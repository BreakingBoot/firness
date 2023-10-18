#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define UINT32 uint32_t

typedef struct {
  char Header[16];
  ///
  /// Device's PnP hardware ID stored in a numeric 32-bit
  /// compressed EISA-type ID. This value must match the
  /// corresponding _HID in the ACPI name space.
  ///
  UINT32 HID;
  ///
  /// Unique ID that is required by ACPI if two devices have the
  /// same _HID. This value must also match the corresponding
  /// _UID/_HID pair in the ACPI name space. Only the 32-bit
  /// numeric value type of _UID is supported. Thus, strings must
  /// not be used for the _UID in the ACPI name space.
  ///
  UINT32 UID;
} ACPI_HID_DEVICE_PATH;

void* CopyMem (/* OUT */ void *DestinationBuffer, /* IN */ void *SourceBuffer, /* IN */ UINT32 Length)
{
  if (Length == 0) {
    return DestinationBuffer;
  }

  return SourceBuffer;
}

int Ascii(int a)
{
    return a;
}

int main ()
{
    uint32_t Com;
    ACPI_HID_DEVICE_PATH *Acpi;
    Acpi->UID = 10;
    Acpi->HID = 20;
    Com = 0;
    CopyMem (&Com, &Acpi->UID, (sizeof (UINT32)));
    CopyMem (&Com, &Acpi->UID, Ascii(sizeof (UINT32)));
    return 0;
}