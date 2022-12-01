#include "stdafx.h"

_NT_BEGIN

#include "wlog.h"
#include "tok_attr.h"

NTSTATUS GetToken(_In_ const TOKEN_PRIVILEGES* RequiredSet, _Out_ PHANDLE phToken);

NTSTATUS AddTokenAttrs(_Inout_ HANDLE hToken, 
					   _In_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION Attributes,
					   _In_ TOKEN_SECURITY_ATTRIBUTE_OPERATION op)
/*++
Routine Description:
	current thread/process token must have SE_TCB_PRIVILEGE

Arguments:
	hToken - The handle must have the TOKEN_ADJUST_DEFAULT access rights

Return Value:

	Status from NtSetInformationToken(hToken, TokenSecurityAttributes,..)

	Among other errors, can return one of the following errors.

	STATUS_ACCESS_DENIED - hToken have not TOKEN_ADJUST_DEFAULT
	STATUS_PRIVILEGE_NOT_HELD - caller have not SE_TCB_PRIVILEGE

--*/
{
	TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION tsaoiData = { Attributes, &op };
	return NtSetInformationToken(hToken, TokenSecurityAttributes, &tsaoiData, sizeof(tsaoiData));
}

NTSTATUS DemoAddTokenAttrs(_Inout_ HANDLE hToken)
{
	UNICODE_STRING Strings[2];
	RtlInitUnicodeString(&Strings[0], L"[Demo String #1]");
	RtlInitUnicodeString(&Strings[1], L"[Demo String #2]");

	TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE Sids[2] = {
		{ 0, RtlLengthRequiredSid(1) },
		{ 0, RtlLengthRequiredSid(2) },
	};

	TOKEN_SECURITY_ATTRIBUTE_V1 Attributes[] = {
		{ {}, TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING, 0, TOKEN_SECURITY_ATTRIBUTE_NON_INHERITABLE, _countof(Strings), Strings },
		{ {}, TOKEN_SECURITY_ATTRIBUTE_TYPE_SID, 0, TOKEN_SECURITY_ATTRIBUTE_NON_INHERITABLE, _countof(Sids), Sids },
	};

	TOKEN_SECURITY_ATTRIBUTES_INFORMATION attr_info = {
		TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION, 0, _countof(Attributes), Attributes
	};

	RtlInitUnicodeString(&Attributes[0].Name, L"Attribute #1");
	RtlInitUnicodeString(&Attributes[1].Name, L"Attribute #2");

	PSID Sid;
	static const SID_IDENTIFIER_AUTHORITY IdentifierAuthority = SECURITY_NT_AUTHORITY;

	Sids[0].pValue = Sid = alloca(Sids[0].ValueLength);
	RtlInitializeSid(Sid, const_cast<SID_IDENTIFIER_AUTHORITY*>(&IdentifierAuthority), 1);
	*RtlSubAuthoritySid(Sid, 0) = SECURITY_LOCAL_SYSTEM_RID;

	Sids[1].pValue = Sid = alloca(Sids[1].ValueLength);
	RtlInitializeSid(Sid, const_cast<SID_IDENTIFIER_AUTHORITY*>(&IdentifierAuthority), 2);
	*RtlSubAuthoritySid(Sid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
	*RtlSubAuthoritySid(Sid, 1) = DOMAIN_ALIAS_RID_ADMINS;

	return AddTokenAttrs(hToken, &attr_info, TOKEN_SECURITY_ATTRIBUTE_OPERATION_REPLACE_ALL);
}

NTSTATUS RtlSetCurrentThreadToken(_In_ HANDLE hToken = 0)
{
	return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
}

extern volatile const UCHAR guz = 0;

PCWSTR GetValueType(_In_ ULONG ValueType, _Out_ PWSTR psz, _In_ ULONG cch)
{
	switch (ValueType)
	{
	case TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID: return L"INVALID";
	case TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64: return L"INT64";
	case TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64: return L"UINT64";
	case TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING: return L"STRING";
	case TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN: return L"FQBN";
	case TOKEN_SECURITY_ATTRIBUTE_TYPE_SID: return L"SID";
	case TOKEN_SECURITY_ATTRIBUTE_TYPE_BOOLEAN: return L"BOOLEAN";
	case TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING: return L"OCTET_STRING";
	}

	swprintf_s(psz, cch, L"[%x]", ValueType);
	return psz;
}

NTSTATUS PrintTokenAttrs(_In_ WLog& log, _In_ HANDLE hToken)
{
	ULONG cb = 0, rcb;
	TOKEN_STATISTICS ts;

	if (0 <= NtQueryInformationToken(hToken, TokenStatistics, &ts, sizeof(ts), &rcb))
	{
		log(L"TokenId = %x, ModifiedId = %x\r\n", ts.TokenId, ts.ModifiedId);
	}

	PVOID stack = alloca(guz);

	union {
		PTOKEN_SECURITY_ATTRIBUTES_INFORMATION p;
		PVOID buf;
	};

	NTSTATUS status;
	do 
	{
		if (cb < rcb)
		{
			cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}

		status = NtQueryInformationToken(hToken, TokenSecurityAttributes, buf, cb, &rcb);

	} while (status == STATUS_BUFFER_TOO_SMALL);

	log(L"Query TokenSecurityAttributes = %x\r\n", status)[status];

	if (0 <= status)
	{
		if (ULONG AttributeCount = p->AttributeCount)
		{
			PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1 = p->pAttributeV1;
			do 
			{
				ULONG ValueType = pAttributeV1->ValueType;

				WCHAR szUnkType[16];

				log(L"%s Flags=%x %wZ\r\n", 
					GetValueType(ValueType, szUnkType, _countof(szUnkType)), 
					pAttributeV1->Flags, &pAttributeV1->Name);

				if (ULONG ValueCount = pAttributeV1->ValueCount)
				{
					union
					{
						PVOID pValue;
						PLONG64 pInt64;
						PULONG64 pUint64;
						PBOOLEAN pb;
						PUNICODE_STRING pString;
						PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
						PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
					};

					pValue = pAttributeV1->pValues;

					do 
					{
						UNICODE_STRING szSid;

						switch (ValueType)
						{
						case TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING:
							log(L"\t%wZ\r\n", pString++);
							break;

						case TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64:
							log(L"\t%I64d\r\n", *pInt64++);
							break;

						case TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64:
							log(L"\t%I64x\r\n", *pUint64++);
							break;

						case TOKEN_SECURITY_ATTRIBUTE_TYPE_SID:
							if (0 <= RtlConvertSidToUnicodeString(&szSid, pOctetString++->pValue, TRUE))
							{
								log(L"\t%wZ\r\n", &szSid);
								RtlFreeUnicodeString(&szSid);
							}
							break;

						case TOKEN_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
							log(L"\t%x\r\n", *pb++);
							break;

						case TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN:
							log(L"\t%x %wZ\r\n", pFqbn->Version, &pFqbn->Name);
							pFqbn++;
							break;

						case TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
							if (ULONG ValueLength = pOctetString->ValueLength)
							{
								PBYTE pbBinary = (PBYTE)pOctetString->pValue;
								PWSTR psz = 0, pc;
								ULONG cch = 0;
								while (CryptBinaryToStringW(pbBinary, ValueLength, CRYPT_STRING_HEXASCIIADDR, psz, &cch))
								{
									if (pc = psz)
									{
										do 
										{
											log(L"%.*s", cb = min(0x100, cch), pc);
										} while (pc += cb, cch -= cb);
										break;
									}

									if (!(psz = new WCHAR[cch]))
									{
										break;
									}
								}

								if (psz)
								{
									delete [] psz;
								}
							}
							pOctetString++;
							break;

						case TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID:
							log(L"\tINVALID");
							break;

						default:
							log(L"\tUnknown");
							break;
						}

					} while (--ValueCount);
				}

			} while (pAttributeV1++, --AttributeCount);
		}
	}

	log << L"\r\n";
	return status;
}

BEGIN_PRIVILEGES(tp_tcb, 1)
	LAA(SE_TCB_PRIVILEGE),
END_PRIVILEGES

BEGIN_PRIVILEGES(tp_dbg, 2)
	LAA(SE_DEBUG_PRIVILEGE),		// need for open processes
	LAA(SE_IMPERSONATE_PRIVILEGE),	// need for impersonate token
END_PRIVILEGES

void attr(_In_ WLog& log)
{
	NTSTATUS status;
	HANDLE hToken, hSysToken;

	if (0 <= (status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_ADJUST_DEFAULT|TOKEN_QUERY, &hToken)))
	{
		PrintTokenAttrs(log, hToken);

		status = NtAdjustPrivilegesToken(hToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(&tp_dbg), 0, 0, 0);

		log(L"AdjustPrivilegesToken = %x\r\n", status)[status];

		if (STATUS_SUCCESS == status)
		{
			status = GetToken(&tp_tcb, &hSysToken);

			log(L"Get TCB token = %x\r\n", status)[status];

			if (0 <= status)
			{
				status = RtlSetCurrentThreadToken(hSysToken);
				NtClose(hSysToken);

				log(L"Impersonate = %x\r\n", status)[status];

				if (0 <= status)
				{
					status = DemoAddTokenAttrs(hToken);

					log(L"AddTokenAttrs = %x\r\n", status)[status];

					if (0 <= status)
					{
						log(L"\r\n********************************\r\n");
						PrintTokenAttrs(log, hToken);
					}

					RtlSetCurrentThreadToken();
				}
			}
		}

		NtClose(hToken);
	}
}

void CALLBACK ep(void*)
{
	WLog log;
	if (!log.Init(0x80000))
	{
		if (HWND hwnd = CreateWindowExW(0, WC_EDIT, L"Token Security Attributes", 
			WS_OVERLAPPEDWINDOW|WS_HSCROLL|WS_VSCROLL|ES_MULTILINE,
			CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, HWND_DESKTOP, 0, 0, 0))
		{
			static const int 
				X_index[] = { SM_CXSMICON, SM_CXICON }, 
				Y_index[] = { SM_CYSMICON, SM_CYICON },
				icon_type[] = { ICON_SMALL, ICON_BIG};

			ULONG i = _countof(icon_type) - 1;

			HICON hii[2]{};
			do 
			{
				HICON hi;

				if (0 <= LoadIconWithScaleDown((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(1), 
					GetSystemMetrics(X_index[i]), GetSystemMetrics(Y_index[i]), &hi))
				{
					hii[i] = hi;
				}
			} while (i--);

			HFONT hFont = 0;
			NONCLIENTMETRICS ncm = { sizeof(NONCLIENTMETRICS) };
			if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
			{
				wcscpy(ncm.lfMessageFont.lfFaceName, L"Courier New");
				ncm.lfMessageFont.lfHeight = -ncm.iMenuHeight;
				ncm.lfMessageFont.lfWeight = FW_NORMAL;
				ncm.lfMessageFont.lfQuality = CLEARTYPE_QUALITY;
				ncm.lfMessageFont.lfPitchAndFamily = FIXED_PITCH|FF_MODERN;
				ncm.lfMessageFont.lfHeight = -ncm.iMenuHeight;

				hFont = CreateFontIndirect(&ncm.lfMessageFont);
			}

			if (hFont) SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, 0);

			ULONG n = 8;
			SendMessage(hwnd, EM_SETTABSTOPS, 1, (LPARAM)&n);

			attr(log);

			log >> hwnd;

			SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hii[0]);
			SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hii[1]);

			ShowWindow(hwnd, SW_SHOWNORMAL);

			MSG msg;
			while (IsWindow(hwnd) && 0 < GetMessageW(&msg, 0, 0, 0))
			{
				TranslateMessage(&msg);
				DispatchMessageW(&msg);
			}

			if (hFont) DeleteObject(hFont);

			i = _countof(hii);
			do 
			{
				if (HICON hi = hii[--i])
				{
					DestroyIcon(hi);
				}
			} while (i);
		}
	}

	ExitProcess(0);
}

_NT_END