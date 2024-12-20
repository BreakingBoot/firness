#ifndef _SMI_TYPES_H_
#define _SMI_TYPES_H_


typedef void VOID;
typedef size_t UINTN;
typedef ssize_t INTN;
typedef uint64_t UINT64;
typedef int64_t INT64;
typedef uint32_t UINT32;
typedef int32_t INT32;
typedef uint16_t UINT16;
typedef int16_t INT16;
typedef uint8_t UINT8;
typedef int8_t INT8;
typedef uint8_t CHAR8;
typedef uint16_t CHAR16;
typedef bool BOOLEAN;
typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef uint64_t EFI_VIRTUAL_ADDRESS;

typedef uint64_t EFI_HANDLE;
typedef uint64_t EFI_STATUS;



typedef struct
{
   uint32_t    Data1;
   uint16_t    Data2;
   uint16_t    Data3;
   uint8_t     Data4[8];
} EFI_GUID;


//
// Status codes common to all execution phases
//
typedef UINTN RETURN_STATUS;



///
/// A value of native width with the highest bit set.
///
#define MAX_BIT  0x8000000000000000ULL
///
/// A value of native width with the two highest bits set.
///
#define MAX_2_BITS  0xC000000000000000ULL

///
/// Maximum legal x64 address
///
#define MAX_ADDRESS  0xFFFFFFFFFFFFFFFFULL

///
/// Maximum usable address at boot time
///
#define MAX_ALLOC_ADDRESS  MAX_ADDRESS

///
/// Maximum legal x64 INTN and UINTN values.
///
#define MAX_INTN   ((INTN)0x7FFFFFFFFFFFFFFFULL)
#define MAX_UINTN  ((UINTN)0xFFFFFFFFFFFFFFFFULL)

///
/// Minimum legal x64 INTN value.
///
#define MIN_INTN  (((INTN)-9223372036854775807LL) - 1)



/**
  Produces a RETURN_STATUS code with the highest bit set.

  @param  StatusCode    The status code value to convert into a warning code.
                        StatusCode must be in the range 0x00000000..0x7FFFFFFF.

  @return The value specified by StatusCode with the highest bit set.

**/
#define ENCODE_ERROR(StatusCode)  ((RETURN_STATUS)(MAX_BIT | (StatusCode)))

/**
  Produces a RETURN_STATUS code with the highest bit clear.

  @param  StatusCode    The status code value to convert into a warning code.
                        StatusCode must be in the range 0x00000000..0x7FFFFFFF.

  @return The value specified by StatusCode with the highest bit clear.

**/
#define ENCODE_WARNING(StatusCode)  ((RETURN_STATUS)(StatusCode))

/**
  Returns TRUE if a specified RETURN_STATUS code is an error code.

  This function returns TRUE if StatusCode has the high bit set.  Otherwise, FALSE is returned.

  @param  StatusCode    The status code value to evaluate.

  @retval TRUE          The high bit of StatusCode is set.
  @retval FALSE         The high bit of StatusCode is clear.

**/
#define RETURN_ERROR(StatusCode)  (((INTN)(RETURN_STATUS)(StatusCode)) < 0)

///
/// The operation completed successfully.
///
#define RETURN_SUCCESS  (RETURN_STATUS)(0)

///
/// The image failed to load.
///
#define RETURN_LOAD_ERROR  ENCODE_ERROR (1)

///
/// The parameter was incorrect.
///
#define RETURN_INVALID_PARAMETER  ENCODE_ERROR (2)

///
/// The operation is not supported.
///
#define RETURN_UNSUPPORTED  ENCODE_ERROR (3)

///
/// The buffer was not the proper size for the request.
///
#define RETURN_BAD_BUFFER_SIZE  ENCODE_ERROR (4)

///
/// The buffer was not large enough to hold the requested data.
/// The required buffer size is returned in the appropriate
/// parameter when this error occurs.
///
#define RETURN_BUFFER_TOO_SMALL  ENCODE_ERROR (5)

///
/// There is no data pending upon return.
///
#define RETURN_NOT_READY  ENCODE_ERROR (6)

///
/// The physical device reported an error while attempting the
/// operation.
///
#define RETURN_DEVICE_ERROR  ENCODE_ERROR (7)

///
/// The device can not be written to.
///
#define RETURN_WRITE_PROTECTED  ENCODE_ERROR (8)

///
/// The resource has run out.
///
#define RETURN_OUT_OF_RESOURCES  ENCODE_ERROR (9)

///
/// An inconsistency was detected on the file system causing the
/// operation to fail.
///
#define RETURN_VOLUME_CORRUPTED  ENCODE_ERROR (10)

///
/// There is no more space on the file system.
///
#define RETURN_VOLUME_FULL  ENCODE_ERROR (11)

///
/// The device does not contain any medium to perform the
/// operation.
///
#define RETURN_NO_MEDIA  ENCODE_ERROR (12)

///
/// The medium in the device has changed since the last
/// access.
///
#define RETURN_MEDIA_CHANGED  ENCODE_ERROR (13)

///
/// The item was not found.
///
#define RETURN_NOT_FOUND  ENCODE_ERROR (14)

///
/// Access was denied.
///
#define RETURN_ACCESS_DENIED  ENCODE_ERROR (15)

///
/// The server was not found or did not respond to the request.
///
#define RETURN_NO_RESPONSE  ENCODE_ERROR (16)

///
/// A mapping to the device does not exist.
///
#define RETURN_NO_MAPPING  ENCODE_ERROR (17)

///
/// A timeout time expired.
///
#define RETURN_TIMEOUT  ENCODE_ERROR (18)

///
/// The protocol has not been started.
///
#define RETURN_NOT_STARTED  ENCODE_ERROR (19)

///
/// The protocol has already been started.
///
#define RETURN_ALREADY_STARTED  ENCODE_ERROR (20)

///
/// The operation was aborted.
///
#define RETURN_ABORTED  ENCODE_ERROR (21)

///
/// An ICMP error occurred during the network operation.
///
#define RETURN_ICMP_ERROR  ENCODE_ERROR (22)

///
/// A TFTP error occurred during the network operation.
///
#define RETURN_TFTP_ERROR  ENCODE_ERROR (23)

///
/// A protocol error occurred during the network operation.
///
#define RETURN_PROTOCOL_ERROR  ENCODE_ERROR (24)

///
/// A function encountered an internal version that was
/// incompatible with a version requested by the caller.
///
#define RETURN_INCOMPATIBLE_VERSION  ENCODE_ERROR (25)

///
/// The function was not performed due to a security violation.
///
#define RETURN_SECURITY_VIOLATION  ENCODE_ERROR (26)

///
/// A CRC error was detected.
///
#define RETURN_CRC_ERROR  ENCODE_ERROR (27)

///
/// The beginning or end of media was reached.
///
#define RETURN_END_OF_MEDIA  ENCODE_ERROR (28)

///
/// The end of the file was reached.
///
#define RETURN_END_OF_FILE  ENCODE_ERROR (31)

///
/// The language specified was invalid.
///
#define RETURN_INVALID_LANGUAGE  ENCODE_ERROR (32)

///
/// The security status of the data is unknown or compromised
/// and the data must be updated or replaced to restore a valid
/// security status.
///
#define RETURN_COMPROMISED_DATA  ENCODE_ERROR (33)

///
/// A HTTP error occurred during the network operation.
///
#define RETURN_HTTP_ERROR  ENCODE_ERROR (35)

///
/// The string contained one or more characters that
/// the device could not render and were skipped.
///
#define RETURN_WARN_UNKNOWN_GLYPH  ENCODE_WARNING (1)

///
/// The handle was closed, but the file was not deleted.
///
#define RETURN_WARN_DELETE_FAILURE  ENCODE_WARNING (2)

///
/// The handle was closed, but the data to the file was not
/// flushed properly.
///
#define RETURN_WARN_WRITE_FAILURE  ENCODE_WARNING (3)

///
/// The resulting buffer was too small, and the data was
/// truncated to the buffer size.
///
#define RETURN_WARN_BUFFER_TOO_SMALL  ENCODE_WARNING (4)

///
/// The data has not been updated within the timeframe set by
/// local policy for this type of data.
///
#define RETURN_WARN_STALE_DATA  ENCODE_WARNING (5)

///
/// The resulting buffer contains UEFI-compliant file system.
///
#define RETURN_WARN_FILE_SYSTEM  ENCODE_WARNING (6)


#define SIGNATURE_16(A, B)        ((A) | (B << 8))
#define SIGNATURE_32(A, B, C, D)  (SIGNATURE_16 (A, B) | (SIGNATURE_16 (C, D) << 16))
#define SIGNATURE_64(A, B, C, D, E, F, G, H) \
    (SIGNATURE_32 (A, B, C, D) | ((UINT64) (SIGNATURE_32 (E, F, G, H)) << 32))

#define SMM_CORE_PRIVATE_DATA_SIGNATURE  SIGNATURE_32 ('s', 'm', 'm', 'c')


static inline int wcslen(const UINT16 *s)
{
  int len = 0;
  while (*s++)
    len++;
  return len;
}

static inline void *wcscpy(UINT16 *dst, UINT16 *src)
{
	return memcpy(dst, src, wcslen(src)*2);
}

typedef struct {
  EFI_PHYSICAL_ADDRESS PhysicalStart;
  EFI_PHYSICAL_ADDRESS CpuStart;
  UINT64 PhysicalSize;
  UINT64 RegionState;
} EFI_MMRAM_DESCRIPTOR;

typedef EFI_MMRAM_DESCRIPTOR EFI_SMRAM_DESCRIPTOR;

typedef void (*EFI_SMM_ENTRY_POINT)(const void *SmmEntryContext);


typedef struct {
  UINTN                   Signature;
  EFI_HANDLE              SmmIplImageHandle;
  UINTN                   SmramRangeCount;
  EFI_SMRAM_DESCRIPTOR    *SmramRanges;
  EFI_SMM_ENTRY_POINT      SmmEntryPoint;
  BOOLEAN                  SmmEntryPointRegistered;
  BOOLEAN                  InSmm;
  void                     *Smst;
  VOID                     *CommunicationBuffer;
  UINTN                    BufferSize;
  EFI_STATUS               ReturnStatus;
  EFI_PHYSICAL_ADDRESS     PiSmmCoreImageBase;
  UINT64                   PiSmmCoreImageSize;
  EFI_PHYSICAL_ADDRESS     PiSmmCoreEntryPoint;
} SMM_CORE_PRIVATE_DATA;

typedef struct {
  ///
  /// Allows for disambiguation of the message format.
  ///
  EFI_GUID    HeaderGuid;
  ///
  /// Describes the size of Data (in bytes) and does not include the size of the header.
  ///
  UINTN       MessageLength;
  ///
  /// Designates an array of bytes that is MessageLength in size.
  ///
  UINT8       Data[1];
} EFI_MM_COMMUNICATE_HEADER;

typedef EFI_MM_COMMUNICATE_HEADER EFI_SMM_COMMUNICATE_HEADER;

#endif // _SMI_TYPES_H_