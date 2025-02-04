#include <ntddk.h>

typedef struct _MEMORY_REQUEST {
    ULONG ProcessId;
    PVOID Address;
    PVOID Buffer;
    SIZE_T Size;
    BOOLEAN Write;
} MEMORY_REQUEST, *PMEMORY_REQUEST;

NTSTATUS ReadWriteMemory(PMEMORY_REQUEST request) {
    PEPROCESS process;
    if (PsLookupProcessByProcessId((HANDLE)request->ProcessId, &process) != STATUS_SUCCESS)
        return STATUS_INVALID_PARAMETER;

    SIZE_T bytes = 0;
    if (request->Write) {
        MmCopyVirtualMemory(PsGetCurrentProcess(), request->Buffer, process, request->Address, request->Size, KernelMode, &bytes);
    } else {
        MmCopyVirtualMemory(process, request->Address, PsGetCurrentProcess(), request->Buffer, request->Size, KernelMode, &bytes);
    }

    return STATUS_SUCCESS;
}

NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    if (controlCode == CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)) {
        MEMORY_REQUEST* request = (MEMORY_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
        Irp->IoStatus.Status = ReadWriteMemory(request);
        Irp->IoStatus.Information = sizeof(MEMORY_REQUEST);
    } else {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;
    return STATUS_SUCCESS;
}
