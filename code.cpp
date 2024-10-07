//ϵͳͷ�ļ�
#include <intrin.h>
#include "header.h"

#include "ͨ��Vad���������Ƿ�������shellcodeע��.h"
#define STACK_WALK_WEIGHT 20
#define DebugPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,__VA_ARGS__)

#ifdef UNICODE
#define tstrlen wcslen
#else
#define tstrlen strlen
#endif



TCHAR g_GlobalBuffer[0x1000];
SIZE_T g_Pid = 0; //��������ȡ��Ҫ������Pid
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


// ��UNICODE_STRINGת��Ϊ�����ĺ���
int StringToInt(TCHAR* String)
{
	int result = 0;
	int sign = 1;  // Ĭ��Ϊ����
	int i = 0;

	// unicodeString->Buffer �� WCHAR ���飬���������ֽڼ���ģ�������Ҫ����2
	SIZE_T length = tstrlen((TCHAR*)String);

	// ����Ƿ��и���
	if (String[0] == TEXT('-'))
	{
		sign = -1;
		i = 1;  // ��������
	}

	// �����ַ�����ÿ���ַ�
	for (; i < length; i++)
	{
		TCHAR wc = String[i];

		// ����Ƿ�Ϊ�����ַ�
		if (wc >= TEXT('0') && wc <= TEXT('9'))
		{
			result = result * 10 + (wc - TEXT('0'));  // ���ַ�ת��Ϊ���ֲ��ۼӵ������
		}
		else
		{
			// ��������������ַ���ֹͣת��
			break;
		}
	}

	// ���ؽ�������Ƿ���
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


	//�����豸
	NTSTATUS status;
	PDEVICE_OBJECT DeviceObject = NULL;
	UNICODE_STRING DeviceName;
	RtlInitUnicodeString(&DeviceName, L"\\Device\\MyDevice");
	status = IoCreateDevice(
		pDriverObject,               // �����������
		0,                           // �豸��չ��С
		&DeviceName,                 // �豸����
		FILE_DEVICE_UNKNOWN,         // �豸����
		0,                           // �豸����
		FALSE,                       // �Ƕ�ռ�豸
		&DeviceObject                // ���ص��豸����ָ��
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