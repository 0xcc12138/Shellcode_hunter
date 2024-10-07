#pragma once
typedef struct _MMADDRESS_NODE
{
	ULONG64 u1;
	struct _MMADDRESS_NODE* LeftChild;
	struct _MMADDRESS_NODE* RightChild;
	ULONG64 StartingVpn;
	ULONG64 EndingVpn;
}MMADDRESS_NODE, * PMMADDRESS_NODE;
typedef struct _EX_FAST_REF
{
	union
	{
		PVOID Object;
		ULONG_PTR RefCnt : 3;
		ULONG_PTR Value;
	};
} EX_FAST_REF, * PEX_FAST_REF;
struct _SEGMENT
{
	struct _CONTROL_AREA* ControlArea;
	ULONG TotalNumberOfPtes;
	ULONG SegmentFlags;
	ULONG64 NumberOfCommittedPages;
	ULONG64 SizeOfSegment;
	union
	{
		struct _MMEXTEND_INFO* ExtendInfo;
		void* BasedAddress;
	};
	ULONG64 SegmentLock;
	ULONG64 u1;
	ULONG64 u2;
	struct _MMPTE* PrototypePte;
	ULONGLONG ThePtes[0x1];
};
//控制区
struct _CONTROL_AREA
{
	struct _SEGMENT* Segment;
	struct _LIST_ENTRY DereferenceList;
	unsigned __int64 NumberOfSectionReferences;
	unsigned __int64 NumberOfPfnReferences;
	unsigned __int64 NumberOfMappedViews;
	unsigned __int64 NumberOfUserReferences;
	ULONG  u;
	ULONG FlushInProgressCount;
	struct _EX_FAST_REF FilePointer;

	/*ULONG ControlAreaLock;
	ULONG ModifiedWriteCount;
	ULONG StartingFrame;
	ULONG64 WaitingForDeletion;
	ULONG64 u2; //0x10字节
	ULONG64 LockedPages;
	_LIST_ENTRY ViewList;*/
};
struct _SUBSECTION
{
	struct _CONTROL_AREA* ControlArea;
	struct _MMPTE* SubsectionBase;
	struct _SUBSECTION* NextSubsection;
	ULONG PtesInSubsection;
	ULONG UnusedPtes;
	struct _MM_AVL_TABLE* GlobalPerSessionHead;
	ULONG u;
	ULONG StartingSector;
	ULONG NumberOfFullSectors;
};

typedef struct _MMVAD_FLAGS
{
#ifdef _WIN64
	ULONG_PTR CommitCharge : 51;
#else
	ULONG_PTR CommitCharge : 19;
#endif
	ULONG_PTR NoChange : 1;
	ULONG_PTR VadType : 3;
	ULONG_PTR MemCommit : 1;
	ULONG_PTR Protection : 5;
	ULONG_PTR Spare : 2;
	ULONG_PTR PrivateMemory : 1;
} MMVAD_FLAGS;

typedef struct _MMVAD
{
	ULONG64 u1;
	struct _MMVAD* LeftChild;
	struct _MMVAD* RightChild;
	ULONG64 StartingVpn;
	ULONG64 EndingVpn;
	MMVAD_FLAGS u;
	ULONG64 PushLock;
	ULONG64 u5;
	ULONG64 u2;
	struct _SUBSECTION* Subsection;
	struct _MSUBSECTION* MappedSubsection;
	struct _MMPTE* FirstPrototypePte;
	struct _MMPTE* LastContiguousPte;
	struct _LIST_ENTRY ViewLinks;
	struct _EPROCESS* VadsProcess;
}MMVAD;






typedef struct   tag_MM_AVL_TABLE
{
	struct _MMADDRESS_NODE BalancedRoot;
	ULONG64 DepthOfTree;
	ULONG64 Unused;
	ULONG64 NumberGenericTableElements;
	void* NodeHint;
	void* NodeFreeHint;
}MM_AVL_TABLE, * PMMAVL_TABLE;



//通过Pid返回EPROCESS结构体指针
PEPROCESS GetProcessById(HANDLE ProcessId);

//用Vad遍历
VOID EnumVad(MMVAD* Root);

//遍历区段
NTSTATUS Enum_Zone(HANDLE Pid);