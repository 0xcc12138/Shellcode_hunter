#include "header.h"
#include "通过Vad遍历区段是否有疑似shellcode注入.h"
#define DebugPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,__VA_ARGS__)




//通过Pid返回EPROCESS结构体指针
PEPROCESS GetProcessById(HANDLE ProcessId)
{
	PEPROCESS Process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
	if (!NT_SUCCESS(status))
	{
		// 处理错误情况
		return NULL;
	}
	return Process;
}


VOID EnumVad(MMVAD* Root)
{
	bool alarm1 = false;
	bool alarm2 = false;
	char* str;
	char* str2;
	if (Root->u.PrivateMemory==1)
	{
		//KdPrint(("This VAD is Private.\n"));
		str = "Private";
		alarm1 = true;
	}
	else
	{
		str = "Map";
		alarm1 = false;
	}


	//0x7  PAGE_EXECUTE_READWRITE
	//
	
	if (Root->u.Protection&2)
	{
		str2 = "可执行";
		alarm2 = true;
	}
	else
	{
		str2 = "不可执行";
		alarm2 = false;
	}

	PEPROCESS currentProcess = PsGetCurrentProcess();
	UCHAR* processName = PsGetProcessImageFileName(currentProcess);

	if (alarm1 == true && alarm2 == true)
	{
		DebugPrint("进程：%s:有疑似shellcode注入!\n", processName);
	}

	//DebugPrint("进程：%s: start:0x%x  end:0x%x   %s    %s\n", processName, Root->StartingVpn, Root->EndingVpn, str, str2);
	__try
	{
		if (MmIsAddressValid(Root->LeftChild))
			EnumVad(Root->LeftChild);

		if (MmIsAddressValid(Root->RightChild))
			EnumVad(Root->RightChild);
	}
	__except (1)
	{
		KdPrint(("异常！！"));
		return;
	}

}


NTSTATUS Enum_Zone(HANDLE Pid)
{

	PEPROCESS TargetPEPROCESS = nullptr;
	KAPC_STATE apcState;
	PMMAVL_TABLE Table=nullptr;

	//通过PID获取到PEPROCESS
	TargetPEPROCESS = GetProcessById(Pid);
	if (!TargetPEPROCESS)//没拿到PEPROCESS结构体就返回不成功
	{
		return STATUS_UNSUCCESSFUL;
	}
	KeStackAttachProcess(TargetPEPROCESS, &apcState);//获取对应进程的上下文
	
	Table = (PMMAVL_TABLE)((UCHAR*)TargetPEPROCESS + 0x448);//找到VadRoot
	if (Table->BalancedRoot.LeftChild)  //开始遍历
		EnumVad((MMVAD*)Table->BalancedRoot.LeftChild);

	if (Table->BalancedRoot.RightChild)
		EnumVad((MMVAD*)Table->BalancedRoot.RightChild);

	KeUnstackDetachProcess(&apcState);//恢复原始上下文环境
	return STATUS_SUCCESS;
}