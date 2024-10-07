#pragma once
extern "C"
{
	#include <ntifs.h>
	#include <ntddk.h>
	NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath);
	NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
}