#include <windows.h>
#include <iostream>
#include <cstdint>
#include <winnt.h>

int main(int argc, char* argv[]) {
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    SIZE_T fileSize = GetFileSize(hFile, NULL);
    PVOID buffer = malloc(fileSize);
    BOOL ok = ReadFile(hFile, buffer, fileSize, NULL, NULL);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)buffer + pDosHeader->e_lfanew);
    DWORD sizeOfImage = pImageNtHeader->OptionalHeader.SizeOfImage;

    LPVOID ImageBaseAddr = VirtualAlloc((PVOID)pImageNtHeader->OptionalHeader.ImageBase, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    // fallback
    if (ImageBaseAddr == NULL) {
        ImageBaseAddr = VirtualAlloc(NULL, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    // write headers to ImageBaseAddr
    memcpy(ImageBaseAddr, buffer, pImageNtHeader->OptionalHeader.SizeOfHeaders);

    // now use the in memory header
    pDosHeader = (PIMAGE_DOS_HEADER)ImageBaseAddr;
    pImageNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)ImageBaseAddr + pDosHeader->e_lfanew);

    // get the first section
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pImageNtHeader);
    // writing sections to ImageBaseAddr
    for (int i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++) {
        PVOID destAddr = (PVOID)((PBYTE)ImageBaseAddr + sectionHeader->VirtualAddress);
        PVOID srcAddr = (PVOID)((PBYTE)buffer + sectionHeader->PointerToRawData);

        if (sectionHeader->SizeOfRawData > 0) {
            memcpy(destAddr, srcAddr, sectionHeader->SizeOfRawData);
            if (sectionHeader->Misc.VirtualSize > sectionHeader->SizeOfRawData) {
                // zero out the remainder
                memset((PVOID)((PBYTE)destAddr + sectionHeader->SizeOfRawData), 0, sectionHeader->Misc.VirtualSize - sectionHeader->SizeOfRawData);
            }
        } else {
            // if theres no data, just zero the whole thing
            memset(destAddr, 0, sectionHeader->Misc.VirtualSize);
        }
        sectionHeader++;
    }

    ULONG_PTR delta = (ULONG_PTR)ImageBaseAddr - pImageNtHeader->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY& relocDir = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        // check if theres reloc table
        if (relocDir.VirtualAddress != 0 || relocDir.Size != 0) {
            PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)ImageBaseAddr + relocDir.VirtualAddress);
            DWORD bytesProcessed = 0;

            while (bytesProcessed < relocDir.Size && block->SizeOfBlock > 0) {
                DWORD entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD entries = (PWORD)(block + 1);

                for (DWORD i = 0; i < entryCount; i++) {
                    WORD type = entries[i] >> 12; // top 4 bits
                    WORD offset = entries[i] & 0x0FFF; // bottom 12 bits
                    PULONG_PTR patchAddr = (PULONG_PTR)((ULONG_PTR)ImageBaseAddr + block->VirtualAddress + offset);

                    switch (type) {
                        case IMAGE_REL_BASED_ABSOLUTE: break;
                        case IMAGE_REL_BASED_HIGH:
                            *(PDWORD)(patchAddr) += HIWORD(delta);
                            break;
                        case IMAGE_REL_BASED_LOW:
                            *(PUINT64)(patchAddr) += LOWORD(delta);
                            break;
                        default: break;
                    }
                }

                bytesProcessed += block->SizeOfBlock;
                block = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)block + block->SizeOfBlock);
            }
        }
    }

    PIMAGE_IMPORT_DESCRIPTOR importTable = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)ImageBaseAddr + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importTable->Name != 0) {
        PIMAGE_THUNK_DATA ilt = (PIMAGE_THUNK_DATA)((PBYTE)ImageBaseAddr + importTable->OriginalFirstThunk);
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)((PBYTE)ImageBaseAddr + importTable->FirstThunk);

        char* dllName = (char*)((PBYTE)ImageBaseAddr + importTable->Name);
        HMODULE hModule = GetModuleHandleA(dllName);
        if (!hModule) hModule = LoadLibraryA(dllName);

        while (ilt->u1.AddressOfData != 0) {
            FARPROC funcAddr;
            if (ilt->u1.AddressOfData & IMAGE_ORDINAL_FLAG) {
                DWORD ordinal = ilt->u1.Ordinal & 0xFFFF;
                funcAddr = GetProcAddress(hModule, MAKEINTRESOURCEA(ordinal));
            } else {
                PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)ImageBaseAddr + ilt->u1.AddressOfData);
                funcAddr = GetProcAddress(hModule, importName->Name);
            }

            iat->u1.Function = (ULONG_PTR)funcAddr;
            iat++;
            ilt++;
        }
        importTable++;
    }

    // handle TLS callback
    IMAGE_DATA_DIRECTORY tlsDir = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    // Guard against no TLS directory
    if (tlsDir.VirtualAddress != 0 && tlsDir.Size != 0) {
        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)((PBYTE)ImageBaseAddr + tlsDir.VirtualAddress);

        if (tls->AddressOfCallBacks) {
            // AddressOfCallBacks is an absolute VA — adjust for relocation delta
            PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)(tls->AddressOfCallBacks + delta);
            while (*callback) {
                (*callback)((PVOID)ImageBaseAddr, DLL_PROCESS_ATTACH, NULL);
                callback++;
            }
        }
    }

    // handle exception directories
    // find .pdata
    IMAGE_DATA_DIRECTORY exceptionDir = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    PRUNTIME_FUNCTION pdata = (PRUNTIME_FUNCTION)((PBYTE)ImageBaseAddr + exceptionDir.VirtualAddress);
    DWORD entryCount = exceptionDir.Size / sizeof(RUNTIME_FUNCTION);

    // register the table
    if (exceptionDir.VirtualAddress && exceptionDir.Size) {
        BOOLEAN ok = RtlAddFunctionTable(pdata, entryCount, (DWORD64)ImageBaseAddr);
        if (!ok) {
            // just quit i guess
            return 1;
        }
    }

    printf("executing...");
    // execute the entry point
    PVOID entryPointAddr = (PVOID)((PBYTE)ImageBaseAddr + pImageNtHeader->OptionalHeader.AddressOfEntryPoint);
    typedef void (*EntryPointFunc)();
    EntryPointFunc entryPoint = (EntryPointFunc)entryPointAddr;
    entryPoint();

    return 0;
}
