#include "userspace_helpers.h"

UINTN locateSignature(UINTN base, UINTN signature)
{
    UINTN i;
    UINTN j;

    for (i = 0; i < base + MAX_SEARCH; i += 4)
    {
        j = readLongInteger(base + i);
        if (signature == j) return (base + i);
    }

    return (UINTN)0;
}

UINTN readLongInteger(UINTN address)
{
    int     memfd;
    VOID*   map_base;
    VOID*   virt_addr;
    UINTN   value;

    if ((memfd = open("/dev/mem", O_RDONLY)) == -1)
    {
        perror("Failed to open /dev/mem !!!");
        exit(EXIT_FAILURE);
    }

    map_base = mmap(NULL, MAP_SIZE, PROT_READ, MAP_SHARED, memfd, address & ~MAP_MASK);
    if (map_base == (VOID *)(-1))
    {
        perror("Failed to map file descriptor !!!");
        exit(EXIT_FAILURE);
    }

    virt_addr = map_base + (address & MAP_MASK);
    value = *((UINTN *)virt_addr);

    if (munmap(map_base, MAP_SIZE) == -1)
    {
        perror("Failed to unmap file descriptor");
    }

    close(memfd);

    return value;
}

VOID writeLongInteger(UINTN address, UINTN value)
{
    int     memfd;
    VOID*   map_base;
    VOID*   virt_addr;

    if ((memfd = open("/dev/mem", O_RDWR | O_SYNC)) == -1)
    {
        perror("Failed to open /dev/mem !!!");
        exit(EXIT_FAILURE);
    }

    map_base = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, address & ~MAP_MASK);
    if (map_base == (VOID *)(-1))
    {
        perror("Failed to map file descriptor !!!");
        exit(EXIT_FAILURE);
    }

    virt_addr = map_base + (address & MAP_MASK);
    *((UINTN *)virt_addr) = value;

    if (munmap(map_base, MAP_SIZE) == -1)
    {
        perror("Failed to unmap file descriptor");
    }

    close(memfd);
}

VOID copyWideCharacters(VOID *destination, VOID *source, size_t length)
{
    unsigned short int  value   = 0;
    UINTN               offset  = 0;
    
    for (offset = 0; offset < length; offset += sizeof(value))
    {
        value = *(unsigned short int *)(source + offset);
        *(unsigned short int *)(destination + offset) = value;
    }
}

VOID* writeCommBuffer(VOID *buffer, UINTN size)
{
    UINT32  value = 0;
    UINTN   offset;

    printf("Writing communication buffer (%llu)\n", size);

    for (offset = 0; offset < size; offset += 4)
    {
        memcpy(&value, buffer + offset, 4);
        writeLongInteger((VALID_COMMBUFF_ADDR + offset), value);
    }
}

VOID triggerSmi(UINT8 data, UINT16 port)
{
    if (ioperm(port, 3, 1))
    {
        perror("Failed port permission set !!!");
        exit(EXIT_FAILURE);
    }

    outb(data, port);
}

EFI_STATUS ReadBytes(INPUT_BUFFER *inputBuffer, size_t numBytes, void *outputBuffer)
{
    if (inputBuffer == NULL || outputBuffer == NULL) 
    {
        return 0x1;
    }

    size_t actualBytes = (inputBuffer->Length >= numBytes) ? numBytes : inputBuffer->Length;

    memcpy(outputBuffer, inputBuffer->Buffer, actualBytes);

    inputBuffer->Buffer += actualBytes;
    inputBuffer->Length -= actualBytes;

    return 0x0;
}

INPUT_BUFFER ReadFileToInputBuffer(const char *filename)
{
    INPUT_BUFFER inputBuffer = { NULL, 0 };
    FILE *file = fopen(filename, "rb");
    
    if (file == NULL) {
        perror("Failed to open file");
        return inputBuffer;  // Return empty
    }

    // Seek to the end to determine file size
    if (fseek(file, 0, SEEK_END) != 0) {
        perror("Failed to seek file");
        fclose(file);
        return inputBuffer;
    }

    long fileSize = ftell(file);
    if (fileSize < 0) {
        perror("Failed to tell file size");
        fclose(file);
        return inputBuffer;
    }
    rewind(file); // Go back to the start

    // Allocate buffer
    inputBuffer.Buffer = (uint8_t *)malloc(fileSize);
    if (inputBuffer.Buffer == NULL) {
        perror("Failed to allocate memory");
        fclose(file);
        return inputBuffer;
    }

    size_t bytesRead = fread(inputBuffer.Buffer, 1, fileSize, file);
    if (bytesRead != (size_t)fileSize) {
        perror("Failed to read entire file");
        free(inputBuffer.Buffer);
        inputBuffer.Buffer = NULL;
        inputBuffer.Length = 0;
        fclose(file);
        return inputBuffer;
    }

    inputBuffer.Length = bytesRead;
    fclose(file);
    return inputBuffer;
}
