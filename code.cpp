//系统头文件
#include <intrin.h>
#include "header.h"

#include "通过Vad遍历区段是否有疑似shellcode注入.h"
#define STACK_WALK_WEIGHT 20
#define DebugPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,__VA_ARGS__)

#ifdef UNICODE
#define tstrlen wcslen
#else
#define tstrlen strlen
#endif



TCHAR g_GlobalBuffer[0x1000];
SIZE_T g_Pid = 0; //从三环获取到要保护的Pid
BOOLEAN hLoadImageNotify;

NTKERNELAPI NTSTATUS NTAPI ZwQueryInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
);






VOID ThreadCreateNotifyRoutine(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
)
{
	ProcessId;
	ThreadId;
	Create;
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return;
	if (ProcessId == (HANDLE)g_Pid)
	{
		Enum_Zone((HANDLE)g_Pid);
	}
	return;
}


void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	if (hLoadImageNotify)
		PsRemoveCreateThreadNotifyRoutine(&ThreadCreateNotifyRoutine);
	if (pDriverObject->DeviceObject != NULL)
	{
		UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\MyDevice_Link");
		IoDeleteSymbolicLink(&symbolicLink);
		IoDeleteDevice(pDriverObject->DeviceObject);
	}
	DebugPrint("Driver unload successfully \n");
}


// 将UNICODE_STRING转换为整数的函数
int StringToInt(TCHAR* String)
{
	int result = 0;
	int sign = 1;  // 默认为正数
	int i = 0;

	// unicodeString->Buffer 是 WCHAR 数组，长度是以字节计算的，所以需要除以2
	SIZE_T length = tstrlen((TCHAR*)String);

	// 检查是否有负号
	if (String[0] == TEXT('-'))
	{
		sign = -1;
		i = 1;  // 跳过负号
	}

	// 遍历字符串的每个字符
	for (; i < length; i++)
	{
		TCHAR wc = String[i];

		// 检查是否为数字字符
		if (wc >= TEXT('0') && wc <= TEXT('9'))
		{
			result = result * 10 + (wc - TEXT('0'));  // 将字符转换为数字并累加到结果中
		}
		else
		{
			// 如果遇到非数字字符，停止转换
			break;
		}
	}

	// 返回结果，考虑符号
	return result * sign;
}


// MyWrite
NTSTATUS WriteRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	DeviceObject;
	// PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(Irp);
	VOID* lpBuf = Irp->UserBuffer; // Use SystemBuffer
	DebugPrint(("Write\n"));
	__try {
		//DEVICE_EXTENSION* device_extension_ptr = (DEVICE_EXTENSION*)DeviceObject->DeviceExtension;
		// Validate and probe user buffer
		if (MmIsAddressValid(lpBuf)) {
			ProbeForRead(lpBuf, sizeof(lpBuf), 1);
		}
		else {
			DebugPrint(("Invalid user buffer address\n"));
			Irp->IoStatus.Status = STATUS_INVALID_USER_BUFFER;
			Irp->IoStatus.Information = 0;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return STATUS_INVALID_USER_BUFFER;
		}
		RtlCopyMemory(g_GlobalBuffer, lpBuf, wcslen((const TCHAR*)lpBuf) * sizeof(TCHAR) + 1);
		g_Pid = StringToInt(g_GlobalBuffer);
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = wcslen((TCHAR*)lpBuf) * sizeof(TCHAR);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DebugPrint(("Exception occurred: Access violation\n"));
		// Set IRP status for exception
		Irp->IoStatus.Status = GetExceptionCode();
		Irp->IoStatus.Information = 0;
	}
	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}



NTSTATUS CreateRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp;
	DeviceObject;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS CloseRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	DeviceObject;
	Irp;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}




NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	pRegPath;


	//创建设备
	NTSTATUS status;
	PDEVICE_OBJECT DeviceObject = NULL;
	UNICODE_STRING DeviceName;
	RtlInitUnicodeString(&DeviceName, L"\\Device\\MyDevice");
	status = IoCreateDevice(
		pDriverObject,               // 驱动程序对象
		0,                           // 设备扩展大小
		&DeviceName,                 // 设备名称
		FILE_DEVICE_UNKNOWN,         // 设备类型
		0,                           // 设备特征
		FALSE,                       // 非独占设备
		&DeviceObject                // 返回的设备对象指针
	);

	if (!NT_SUCCESS(status))
	{
		DebugPrint(("Failed to create device\n"));
		return status;
	}
	DebugPrint(("Device created successfully\n"));

	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\MyDevice_Link");
	status = IoCreateSymbolicLink(&symbolicLink, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		DebugPrint(("Failed to create device\n"));
		return status;
	}




	hLoadImageNotify = NT_SUCCESS(PsSetCreateThreadNotifyRoutine(&ThreadCreateNotifyRoutine));
	if (!hLoadImageNotify)
	{
		DebugPrint("LoadImageNotify failed\r\n");
		return STATUS_UNSUCCESSFUL;
	}
	pDriverObject->DriverUnload = DriverUnload;

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateRoutine;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = WriteRoutine;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseRoutine;


	DebugPrint("Driver load successfully\n");
	return STATUS_SUCCESS;
}