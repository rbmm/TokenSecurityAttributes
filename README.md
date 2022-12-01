# TokenSecurityAttributes

result of run:
 
TokenId = 12c6982, ModifiedId = 12c69bf
Query TokenSecurityAttributes = 0
The operation completed successfully.
UINT64 Flags=41 TSA://ProcUnique
  a6
  12c6983

AdjustPrivilegesToken = 0
The operation completed successfully.
Get TCB token = 0
The operation completed successfully.
Impersonate = 0
The operation completed successfully.
AddTokenAttrs = 0
The operation completed successfully.

********************************
TokenId = 12c6982, ModifiedId = 12c6aeb
Query TokenSecurityAttributes = 0
The operation completed successfully.
STRING Flags=1 Attribute #1
  [Demo String #1]
  [Demo String #2]
SID Flags=1 Attribute #2
  S-1-5-18
  S-1-5-32-544


initially token have TSA://ProcUnique attribute with 2 UINT64
the second UINT64 value is always (in tests) equal TokenId+1
so probably ZwAllocateLocallyUniqueId used for create it, just after init TokenId ( Specifies a locally unique identifier (LUID) that identifies this instance of the token object)

look [also](https://twitter.com/hakril/status/1205072307443638272) and
[The Internals of AppLocker - Part 3 - Access Tokens and Access Checking](https://malware.news/t/the-internals-of-applocker-part-3-access-tokens-and-access-checking/34880)


about TSA://ProcUnique