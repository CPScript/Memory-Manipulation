#include <ntddk.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("EXAMPLE Kernel Driver Loaded.\n");

    DriverObject->DriverUnload = UnloadDriver;

    return STATUS_SUCCESS;
}

void UnloadDriver(PDRIVER_OBJECT DriverObject) {
    DbgPrint("EXAMPLE Kernel Driver Unloaded.\n");
}
