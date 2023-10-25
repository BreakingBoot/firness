#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define UINT32 uint32_t
#define UINT16 uint16_t
#define UINT8 uint8_t

#define ONE 0
#define TWO 1
#define THREE 3

#define SOME_STRING "abababab"
typedef struct {
  UINT32  Data1;
  UINT16  Data2;
  UINT16  Data3;
  UINT8   Data4[8];
} EFI_GUID;

typedef struct {
  UINT8 Type;       ///< 0x01 Hardware Device Path.
                    ///< 0x02 ACPI Device Path.
                    ///< 0x03 Messaging Device Path.
                    ///< 0x04 Media Device Path.
                    ///< 0x05 BIOS Boot Specification Device Path.
                    ///< 0x7F End of Hardware Device Path.

  UINT8 SubType;    ///< Varies by Type
                    ///< 0xFF End Entire Device Path, or
                    ///< 0x01 End This Instance of a Device Path and start a new
                    ///< Device Path.

  UINT8 Length[2];  ///< Specific Device Path data. Type and Sub-Type define
                    ///< type of data. Size of data is included in Length.

} EFI_DEVICE_PATH_PROTOCOL;

typedef bool (*CHOOSE_HANDLER)(
  EFI_DEVICE_PATH_PROTOCOL  *FilePath
  );

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

bool CreateDriverOptionFromFile (
  EFI_DEVICE_PATH_PROTOCOL  *FilePath
  )
{
  return true;
}

int ChooseFile (
  EFI_DEVICE_PATH_PROTOCOL  *RootDirectory,
  char                    *FileType,
  CHOOSE_HANDLER            ChooseHandler,
  EFI_DEVICE_PATH_PROTOCOL  **File
  )
{
  return 1;
}

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
    EFI_DEVICE_PATH_PROTOCOL  *File;
    Com = 0;
    char* walker = "SOME_STRING";
    CopyMem (walker, &Acpi->UID, (sizeof (EFI_GUID))+ 10);
    CopyMem (&Com, &Acpi->UID, (ONE | TWO | THREE));
    CopyMem (&Com, &Acpi->UID, Ascii(sizeof (UINT32)));
    ChooseFile (NULL, ".efi", CreateDriverOptionFromFile, &File);
    return 0;
}