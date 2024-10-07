#include "header.h"
#include "ͨ��Vad���������Ƿ�������shellcodeע��.h"
#define DebugPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,__VA_ARGS__)




//ͨ��Pid����EPROCESS�ṹ��ָ��
PEPROCESS GetProcessById(HANDLE ProcessId)
{
	PEPROCESS Process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &Process);
	if (!NT_SUCCESS(status))
	{
		// ����������
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
		str2 = "��ִ��";
		alarm2 = true;
	}
	else
	{
		str2 = "����ִ��";
		alarm2 = false;
	}

	PEPROCESS currentProcess = PsGetCurrentProcess();
	UCHAR* processName = PsGetProcessImageFileName(currentProcess);

	if (alarm1 == true && alarm2 == true)
	{
		DebugPrint("���̣�%s:������shellcodeע��!\n", processName);
	}

	//DebugPrint("���̣�%s: start:0x%x  end:0x%x   %s    %s\n", processName, Root->StartingVpn, Root->EndingVpn, str, str2);
	__try
	{
		if (MmIsAddressValid(Root->LeftChild))
			EnumVad(Root->LeftChild);

		if (MmIsAddressValid(Root->RightChild))
			EnumVad(Root->RightChild);
	}
	__except (1)
	{
		KdPrint(("�쳣����"));
		return;
	}

}


NTSTATUS Enum_Zone(HANDLE Pid)
{

	PEPROCESS TargetPEPROCESS = nullptr;
	KAPC_STATE apcState;
	PMMAVL_TABLE Table=nullptr;

	//ͨ��PID��ȡ��PEPROCESS
	TargetPEPROCESS = GetProcessById(Pid);
	if (!TargetPEPROCESS)//û�õ�PEPROCESS�ṹ��ͷ��ز��ɹ�
	{
		return STATUS_UNSUCCESSFUL;
	}
	KeStackAttachProcess(TargetPEPROCESS, &apcState);//��ȡ��Ӧ���̵�������
	
	Table = (PMMAVL_TABLE)((UCHAR*)TargetPEPROCESS + 0x448);//�ҵ�VadRoot
	if (Table->BalancedRoot.LeftChild)  //��ʼ����
		EnumVad((MMVAD*)Table->BalancedRoot.LeftChild);

	if (Table->BalancedRoot.RightChild)
		EnumVad((MMVAD*)Table->BalancedRoot.RightChild);

	KeUnstackDetachProcess(&apcState);//�ָ�ԭʼ�����Ļ���
	return STATUS_SUCCESS;
}