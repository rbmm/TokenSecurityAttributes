#include "stdafx.h"

_NT_BEGIN

extern const SECURITY_QUALITY_OF_SERVICE sqos = {
	sizeof (sqos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE
};

extern const OBJECT_ATTRIBUTES oa_sqos = { sizeof(oa_sqos), 0, 0, 0, 0, const_cast<SECURITY_QUALITY_OF_SERVICE*>(&sqos) };

NTSTATUS GetToken(_In_ PVOID buf, _In_ const TOKEN_PRIVILEGES* RequiredSet, _Out_ PHANDLE phToken)
{
	NTSTATUS status;

	union {
		PVOID pv;
		PBYTE pb;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	pv = buf;
	ULONG NextEntryOffset = 0;

	do 
	{
		pb += NextEntryOffset;

		HANDLE hProcess, hToken, hNewToken;

		CLIENT_ID ClientId = { pspi->UniqueProcessId };

		if (ClientId.UniqueProcess)
		{
			if (0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, 
				const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), &ClientId))
			{
				status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

				NtClose(hProcess);

				if (0 <= status)
				{
					status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE|TOKEN_QUERY, 
						const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), FALSE, TokenImpersonation, &hNewToken);

					NtClose(hToken);

					if (0 <= status)
					{
						status = NtAdjustPrivilegesToken(hNewToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(RequiredSet), 0, 0, 0);

						if (STATUS_SUCCESS == status)	
						{
							*phToken = hNewToken;
							return STATUS_SUCCESS;
						}

						NtClose(hNewToken);
					}
				}
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS GetToken(_In_ const TOKEN_PRIVILEGES* RequiredSet, _Out_ PHANDLE phToken)
/*++
Routine Description:
	try found process token with RequiredSet; duplicate and adjust privilege 
Arguments:
	RequiredSet - set of privileges which must be in token
	phToken - Impersonation Token with all privileges from RequiredSet, all it is enabled (even if some is disabled in original token)
--*/
{
	NTSTATUS status;

	ULONG cb = 0x40000;

	do 
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (PBYTE buf = new BYTE[cb += PAGE_SIZE])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
			{
				status = GetToken(buf, RequiredSet, phToken);

				if (status == STATUS_INFO_LENGTH_MISMATCH)
				{
					status = STATUS_UNSUCCESSFUL;
				}
			}

			delete [] buf;
		}

	} while(status == STATUS_INFO_LENGTH_MISMATCH);

	return status;
}

_NT_END