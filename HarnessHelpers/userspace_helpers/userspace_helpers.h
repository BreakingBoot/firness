#ifndef _INTERRUPT_H_
#define _INTERRUPT_H_

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/io.h>
#include <uchar.h>
#include <wchar.h>
#include <stddef.h>
#include <inttypes.h>


#define MAX_LENGTH          1024

#define SMMC_SEARCH_ADDR    0x7E6C2000
#define MAX_SEARCH          0x00010000

#define MAP_SIZE            4096UL
#define MAP_MASK            (MAP_SIZE - 1)

#define VALID_COMMBUFF_ADDR 0x7E5D6000

#define SIGNATURE_16(A, B)                    ((A) | (B << 8))
#define SIGNATURE_32(A, B, C, D)              (SIGNATURE_16 (A, B) | (SIGNATURE_16 (C, D) << 16))
#define SIGNATURE_64(A, B, C, D, E, F, G, H)  (SIGNATURE_32 (A, B, C, D) | ((UINT64) (SIGNATURE_32 (E, F, G, H)) << 32))

#define SMM_CORE_PRIVATE_DATA_SIGNATURE  SIGNATURE_32 ('s', 'm', 'm', 'c')
#define EFI_RUNTIME_SERVICES_SIGNATURE   SIGNATURE_64 ('R','U','N','T','S','E','R','V')
#define OFFSET_OF(TYPE, Field) ((uint32_t)(size_t) &(((TYPE *)0)->Field))

typedef unsigned long long  UINT64;
typedef long long           INT64;
typedef unsigned int        UINT32;
typedef int                 INT32;
typedef unsigned short      UINT16;
typedef unsigned short      CHAR16;
typedef short               INT16;
typedef unsigned char       BOOLEAN;
typedef unsigned char       UINT8;
typedef char                CHAR8;
typedef signed char         INT8;
typedef void                VOID;

typedef UINT64              UINTN;
typedef INT64               INTN;
typedef UINT64              EFI_STATUS;


typedef struct {
  UINT8 *Buffer;
  UINTN Length;
} INPUT_BUFFER;

VOID  copyWideCharacters  (VOID*, VOID*, size_t);
VOID* writeCommBuffer     (VOID*, UINTN);
UINTN locateSignature     (UINTN, UINTN);
VOID  writeLongInteger    (UINTN, UINTN);
UINTN readLongInteger     (UINTN);
VOID  triggerSmi          (UINT8, UINT16);
EFI_STATUS ReadBytes(INPUT_BUFFER *inputBuffer, size_t numBytes, void *outputBuffer);
INPUT_BUFFER ReadFileToInputBuffer(const char *filename);

typedef struct SMM_CORE_PRIVATE_DATA{
  UINTN    Signature;
  UINTN    SmmIplImageHandle;
  UINTN    SmramRangeCount;
  UINTN    SmramRanges;
  UINTN    SmmEntryPoint;
  UINT32   SmmEntryPointRegistered;
  UINT32   InSmm;
  UINTN    *Smst;
  UINTN    CommunicationBuffer;
  UINTN    BufferSize;
  UINTN    ReturnStatus;
  UINTN    PiSmmCoreImageBase;
  UINTN    PiSmmCoreImageSize;
  UINTN    PiSmmCoreEntryPoint;
} SMM_CORE_PRIVATE_DATA;

typedef struct EFI_GUID {
  UINT32   Data1;
  UINT16   Data2;
  UINT16   Data3;
  UINT8    Data4[8];
} EFI_GUID;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _LIST_ENTRY {
  LIST_ENTRY    *ForwardLink;
  LIST_ENTRY    *BackLink;
};

typedef struct EFI_MM_COMMUNICATE_HEADER{
  EFI_GUID   HeaderGuid;
  UINTN      MessageLength;
  UINT8      Data[1];
} EFI_MM_COMMUNICATE_HEADER;
#define EFI_MM_COMM_HEADER_SIZE  (OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data))

#endif