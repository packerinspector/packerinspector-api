# ![dpi-logo](https://www.packerinspector.com/box-mini.png)  packerinspector-api

[Deep Packer Inspector's](https://www.packerinspector.com/) API.

You can access the API reference at: [https://www.packerinspector.com/reference#dpi-api-v1](https://www.packerinspector.com/reference#dpi-api-v1)

## How to install

```
pip install packerinspector-api
```

## How to use

You are given an API key when you create an account at Deep Packer Inspector
(create an account [here](https://www.packerinspector.com/login)), copy your
API key from [here](https://www.packerinspector.com/settings).

```python
import packerinspector


dpi = packerinspector.PublicAPI('your API key')

# Public scan
response = dpi.scan_sample('path-to-sample.exe', private=False)

# Public scan with some extra dlls
response = dpi.scan_sample('path-to-sample.exe', private=False,
                           'extrastuff.dll', 'another.dll')

# Private scan
response = dpi.scan_sample('path-to-sample.exe', private=True)

# Force sample re-scan (aka private scan)
response = dpi.rescan_sample('path-to-sample.exe')

# Get analysis report
response = dpi.get_report('MzU2Ng.taDvVrLuqvOn1GRXgTRJiDGSfsE')  # report id

# Get only the behavioural packer analysis info
response = dpi.get_report('MzU2Ng.taDvVrLuqvOn1GRXgTRJiDGSfsE',
                          get_static_pe_info=False,
                          get_vt_scans=False)

# Download unpacking graph (stores a png in the given folder)
error = dpi.get_unpacking_graph('MzU2Ng.taDvVrLuqvOn1GRXgTRJiDGSfsE',
                                '/path/to/graphs-folder/')

# Download memory dump (stores a tar.gz in the given folder)
error = dpi.get_memory_dump('report-id', '/path/to/memory-dumps-folder/')

```

### Unpacking graph example

![unpacking graph](https://www.packerinspector.com/graph/2e965b6c2734dfef93c5b517f192607c97219c5334c76fa22b0971ffdfaafbd920170608135058423189)

### Report example

See [https://www.packerinspector.com/reference#get-report-response-example](https://www.packerinspector.com/reference#get-report-response-example) for a description of each field.

```json
{
    "report-url": "https://www.packerinspector.com/report/2e965b6c2734dfef93c5b517f192607c97219c5334c76fa22b0971ffdfaafbd9/MzUzOQ.QwIOR1r3E1pMnRzZZhFKYO1PCVA", 
    "status": 200, 
    "description": "Report successfully retrieved.",
    "dpicode": 1,
    "id": "MzUzOQ.QwIOR1r3E1pMnRzZZhFKYO1PCVA", 
    "vt-scans": true, 
    "file-identification": true, 
    "static-pe-information": true,
    "packer-analysis": true,
    "report": { 
        "packer-analysis": {
            "layers-and-regions": [
                {
                    "lowest-address": 4198400, 
                    "highest-address": 4198400, 
                    "regions": 1, 
                    "layer-num": 0, 
                    "frames": 0, 
                    "size": 34487
                }, 
                {
                    "lowest-address": 50514240, 
                    "highest-address": 50514240, 
                    "regions": 1, 
                    "layer-num": 1, 
                    "frames": 1, 
                    "size": 281
                }, 
                {
                    "lowest-address": 1184486, 
                    "highest-address": 1184486, 
                    "regions": 1, 
                    "layer-num": 2, 
                    "frames": 1, 
                    "size": 4579
                }, 
                {
                    "lowest-address": 64946176, 
                    "highest-address": 64946176, 
                    "regions": 1, 
                    "layer-num": 3, 
                    "frames": 1, 
                    "size": 3776
                }
            ], 
            "num-downward-trans": 17, 
            "remote-memory-writes": [
                {
                    "source-address": "", 
                    "dest-process": 0, 
                    "source-process": 0, 
                    "dest-address": 65142784, 
                    "type": "Memory unmap|deallocate", 
                    "size": 12288
                }, 
                {
                    "source-address": "", 
                    "dest-process": 0, 
                    "source-process": 0, 
                    "dest-address": 65077248, 
                    "type": "Memory unmap|deallocate", 
                    "size": 12288
                }, 
                {
                    "source-address": "", 
                    "dest-process": 0, 
                    "source-process": 0, 
                    "dest-address": 65077248, 
                    "type": "Memory unmap|deallocate", 
                    "size": 65536
                }
            ], 
            "num-layers": 4, 
            "graph": "https://www.packerinspector.com/graph/2e965b6c2734dfef93c5b517f192607c97219c5334c76fa22b0971ffdfaafbd920170608135058423189", 
            "num-regions": 4, 
            "api-calls": {
                "1": {
                    "0": {
                        "address-space": "50514240-50514521", 
                        "total-api-calls": 0
                    }, 
                    "total-api-calls": 0
                }, 
                "0": {
                    "0": {
                        "ntdll.dll": [
                            "RtlImageNtHeader", 
                            "ZwFsControlFile", 
                            "ZwPulseEvent", 
                            "RtlValidateUnicodeString", 
                            "RtlImageDirectoryEntryToData", 
                            "RtlNtStatusToDosError", 
                            "KiFastSystemCallRet", 
                            "bsearch", 
                            "KiFastSystemCall", 
                            "RtlAcquirePebLock", 
                            "RtlInitializeCriticalSectionAndSpinCount", 
                            "RtlInitString", 
                            "ZwRequestWakeupLatency", 
                            "RtlFindCharInUnicodeString", 
                            "ZwQueryPerformanceCounter", 
                            "RtlFreeHeap", 
                            "ZwOpenThreadToken", 
                            "RtlReleasePebLock", 
                            "ZwContinue", 
                            "ZwQueryVirtualMemory", 
                            "strchr", 
                            "RtlCreateHeap", 
                            "ZwFlushBuffersFile", 
                            "LdrLockLoaderLock", 
                            "ZwAdjustPrivilegesToken", 
                            "RtlSetLastWin32Error", 
                            "RtlFindActivationContextSectionString", 
                            "ZwDuplicateToken", 
                            "RtlUnicodeToMultiByteN", 
                            "RtlUnicodeStringToAnsiString", 
                            "RtlUnlockHeap", 
                            "RtlGetLastWin32Error", 
                            "RtlFindClearBits", 
                            "RtlLogStackBackTrace", 
                            "RtlImpersonateSelf", 
                            "RtlAllocateHeap", 
                            "RtlHashUnicodeString", 
                            "memmove", 
                            "RtlEqualUnicodeString", 
                            "RtlSetBits", 
                            "LdrGetDllHandle", 
                            "RtlEncodePointer", 
                            "RtlNtStatusToDosErrorNoTeb", 
                            "ZwOpenProcessToken", 
                            "RtlFreeUnicodeString", 
                            "RtlDecodePointer", 
                            "RtlSizeHeap", 
                            "RtlCompactHeap", 
                            "RtlIsValidHandle", 
                            "RtlFindClearBitsAndSet", 
                            "ZwOpenProcess", 
                            "RtlDosApplyFileIsolationRedirection_Ustr", 
                            "RtlLeaveCriticalSection", 
                            "LdrUnlockLoaderLock", 
                            "RtlLockHeap", 
                            "ZwClose", 
                            "ZwSetInformationThread", 
                            "LdrGetDllHandleEx", 
                            "RtlInitUnicodeString", 
                            "ZwQueryInformationProcess", 
                            "RtlTryEnterCriticalSection", 
                            "ZwAllocateVirtualMemory", 
                            "ZwQuerySystemInformation", 
                            "RtlEnterCriticalSection", 
                            "LdrGetProcedureAddress", 
                            "RtlGetNtGlobalFlags", 
                            "ZwProtectVirtualMemory", 
                            "ZwSetInformationProcess", 
                            "RtlInitAnsiString"
                        ], 
                        "KERNEL32.DLL": [
                            "RequestWakeupLatency", 
                            "QueryPerformanceCounter", 
                            "GetEnvironmentStringsW", 
                            "GetModuleFileNameW", 
                            "PulseEvent", 
                            "GlobalUnfix", 
                            "GetProcessHandleCount", 
                            "GetProcAddress", 
                            "GetStartupInfoA", 
                            "InterlockedIncrement", 
                            "CloseHandle", 
                            "InterlockedDecrement", 
                            "GetCurrentThreadId", 
                            "GetSystemTimeAsFileTime", 
                            "LocalCompact", 
                            "GetCPInfo", 
                            "MultiByteToWideChar", 
                            "FlushFileBuffers", 
                            "GetCommandLineA", 
                            "IsWow64Process", 
                            "UnhandledExceptionFilter", 
                            "VirtualQuery", 
                            "SetUnhandledExceptionFilter", 
                            "GlobalUnWire", 
                            "OpenProcess", 
                            "GetModuleFileNameA", 
                            "TlsGetValue", 
                            "LCMapStringW", 
                            "TlsAlloc", 
                            "IsValidCodePage", 
                            "HeapCreate", 
                            "SetHandleCount", 
                            "GetModuleHandleW", 
                            "InitializeCriticalSectionAndSpinCount", 
                            "GetProcessHeap", 
                            "GetStdHandle", 
                            "FreeEnvironmentStringsW", 
                            "GetACP", 
                            "GetFileType", 
                            "SetProcessPriorityBoost", 
                            "GetTickCount", 
                            "VirtualQueryEx", 
                            "GetProcessTimes", 
                            "WideCharToMultiByte", 
                            "GetCurrentProcessId", 
                            "GlobalUnlock", 
                            "SetProcessWorkingSetSize", 
                            "TlsSetValue", 
                            "GetStringTypeW", 
                            "GetVersion", 
                            "PeekNamedPipe", 
                            "VerifyConsoleIoHandle"
                        ], 
                        "address-space": "4198400-4232887", 
                        "total-api-calls": 169960
                    }, 
                    "total-api-calls": 169960
                }, 
                "3": {
                    "0": {
                        "ntdll.dll": [
                            "ZwUnmapViewOfSection", 
                            "ZwCreateSection", 
                            "RtlLeaveCriticalSection", 
                            "ZwClose", 
                            "RtlImageDirectoryEntryToData", 
                            "KiFastSystemCallRet", 
                            "KiFastSystemCall", 
                            "ZwFreeVirtualMemory", 
                            "ZwMapViewOfSection", 
                            "ZwAllocateVirtualMemory", 
                            "ZwQuerySystemInformation", 
                            "RtlEnterCriticalSection", 
                            "LdrGetProcedureAddress", 
                            "wcscpy", 
                            "RtlInitString"
                        ], 
                        "KERNEL32.DLL": [
                            "Process32Next", 
                            "lstrcpyW", 
                            "GetCurrentProcessId", 
                            "Process32First", 
                            "CloseHandle", 
                            "GetProcAddress", 
                            "Process32FirstW", 
                            "WideCharToMultiByte", 
                            "CreateToolhelp32Snapshot", 
                            "Process32NextW"
                        ], 
                        "address-space": "64946176-64949952", 
                        "total-api-calls": 467
                    }, 
                    "total-api-calls": 467
                }, 
                "2": {
                    "0": {
                        "ntdll.dll": [
                            "RtlValidateUnicodeString", 
                            "RtlImageNtHeader", 
                            "RtlMultiByteToUnicodeN", 
                            "RtlFreeHeap", 
                            "RtlFindCharInUnicodeString", 
                            "RtlInitUnicodeString", 
                            "RtlTryEnterCriticalSection", 
                            "LdrLoadDll", 
                            "RtlLeaveCriticalSection", 
                            "LdrUnlockLoaderLock", 
                            "ZwSetInformationThread", 
                            "RtlUpcaseUnicodeChar", 
                            "RtlAnsiStringToUnicodeString", 
                            "_stricmp", 
                            "LdrFindResource_U", 
                            "RtlAllocateHeap", 
                            "wcsncmp", 
                            "RtlFreeUnicodeString", 
                            "RtlImageDirectoryEntryToData", 
                            "RtlHashUnicodeString", 
                            "LdrAlternateResourcesEnabled", 
                            "LdrLoadAlternateResourceModule", 
                            "RtlNtStatusToDosError", 
                            "KiFastSystemCallRet", 
                            "bsearch", 
                            "KiFastSystemCall", 
                            "LdrLockLoaderLock", 
                            "memmove", 
                            "RtlReleasePebLock", 
                            "wcsrchr", 
                            "RtlFindActivationContextSectionString", 
                            "RtlAcquirePebLock", 
                            "wcslen", 
                            "wcschr", 
                            "ZwAllocateVirtualMemory", 
                            "RtlEnterCriticalSection", 
                            "LdrAccessResource", 
                            "RtlNtStatusToDosErrorNoTeb", 
                            "RtlQueryEnvironmentVariable_U", 
                            "LdrGetProcedureAddress", 
                            "RtlGetNtGlobalFlags", 
                            "RtlInitString", 
                            "KiUserExceptionDispatcher", 
                            "RtlDosApplyFileIsolationRedirection_Ustr", 
                            "RtlInitAnsiString", 
                            "RtlEqualUnicodeString"
                        ], 
                        "KERNEL32.DLL": [
                            "LoadLibraryExA", 
                            "LocalAlloc", 
                            "FindResourceA", 
                            "SetHandleCount", 
                            "GetModuleHandleA", 
                            "SetThreadIdealProcessor", 
                            "GetProcAddress", 
                            "LoadLibraryA", 
                            "VirtualAlloc", 
                            "VirtualAllocEx", 
                            "LoadLibraryExW", 
                            "LoadResource", 
                            "SizeofResource"
                        ], 
                        "address-space": "1184486-1189065", 
                        "total-api-calls": 1343
                    }, 
                    "total-api-calls": 1343
                }
            }, 
            "num-upward-trans": 20, 
            "complexity-type": 3, 
            "num-regions-special-apis": 2, 
            "loaded-modules": [
                {
                    "pid": 1968, 
                    "name": "dbghelp.dll", 
                    "start-address": 1565196288, 
                    "size": 659456
                }, 
                {
                    "pid": 1968, 
                    "name": "comdlg32.dll", 
                    "start-address": 1983250432, 
                    "size": 303104
                }, 
                {
                    "pid": 1968, 
                    "name": "msvcrt.dll", 
                    "start-address": 2008940544, 
                    "size": 360448
                }, 
                {
                    "pid": 1968, 
                    "name": "version.dll", 
                    "start-address": 2008875008, 
                    "size": 32768
                }, 
                {
                    "pid": 1968, 
                    "name": "gdi32.dll", 
                    "start-address": 2012151808, 
                    "size": 299008
                }, 
                {
                    "pid": 1968, 
                    "name": "advapi32.dll", 
                    "start-address": 2010775552, 
                    "size": 704512
                }, 
                {
                    "pid": 1968, 
                    "name": "kernel32.dll", 
                    "start-address": 2088763392, 
                    "size": 1060864
                }, 
                {
                    "pid": 1968, 
                    "name": "shell32.dll", 
                    "start-address": 2120876032, 
                    "size": 8523776
                }, 
                {
                    "pid": 1968, 
                    "name": "secur32.dll", 
                    "start-address": 2013003776, 
                    "size": 69632
                }, 
                {
                    "pid": 1968, 
                    "name": "rpcrt4.dll", 
                    "start-address": 2011496448, 
                    "size": 598016
                }, 
                {
                    "pid": 1968, 
                    "name": "45317968759d3e37282ceb75149f627d648534c5b4685f6da3966d8f6fca662", 
                    "start-address": 4194304, 
                    "size": 54423552
                }, 
                {
                    "pid": 1968, 
                    "name": "ntdll.dll", 
                    "start-address": 2089877504, 
                    "size": 741376
                }, 
                {
                    "pid": 1968, 
                    "name": "shlwapi.dll", 
                    "start-address": 2012479488, 
                    "size": 483328
                }, 
                {
                    "pid": 1968, 
                    "name": "user32.dll", 
                    "start-address": 2117664768, 
                    "size": 593920
                }, 
                {
                    "pid": 1968, 
                    "name": "comctl32.dll", 
                    "start-address": 1489174528, 
                    "size": 630784
                }
            ], 
            "execution-time": 1804, 
            "granularity": "Not applicable", 
            "num-pro-ipc": 0, 
            "last-executed-region": {
                "calls-api-getvers": false, 
                "calls-api-getcomm": false, 
                "num-api-fun-called": 25, 
                "writes-exe-region": false, 
                "process": 0, 
                "address": 64946176, 
                "num-diff-apis-called": 25, 
                "layer-num": 3, 
                "modified-by-extern-pro": false, 
                "memory-type": "", 
                "calls-api-getmodu": false, 
                "region-num": 0, 
                "size": 3776
            }, 
            "num-processes": 1, 
            "regions-pot-original": []
        }, 
        "file-identification": {
            "size": 246272, 
            "sdhash": "omitted",
            "first-seen": "Thu, 08 Jun 2017 13:50:58 GMT", 
            "auxiliary-files": [], 
            "mime-type": "application/x-dosexec", 
            "trid": [
                {
                    "type": "(.DLL) Win32 Dynamic Link Library (generic)", 
                    "percent": 14.2
                }, 
                {
                    "type": "(.EXE) Win32 Executable (generic)", 
                    "percent": 9.7
                }, 
                {
                    "type": "(.EXE) Generic Win/DOS Executable", 
                    "percent": 4.3
                }, 
                {
                    "type": "(.EXE) DOS Executable Generic", 
                    "percent": 4.3
                }, 
                {
                    "type": "(.EXE) Win32 Executable MS Visual C++ (generic)", 
                    "percent": 67.3
                }
            ], 
            "sha256": "45317968759d3e37282ceb75149f627d648534c5b4685f6da3966d8f6fca662d", 
            "sha1": "ca963033b9a285b8cd0044df38146a932c838071", 
            "entropy": 5.41605, 
            "known-names": [
                "45317968759d3e37282ceb75149f627d648534c5b4685f6da3966d8f6fca662d"
            ], 
            "imphash": "edbc0337cc897a187d263d79c09c15c7", 
            "file-type": "PE32 executable (GUI) Intel 80386, for MS Windows", 
            "packer-signatures": [], 
            "ssdeep": "3072:xkeyloECBch6ZCGBGSmHJ0y5lj6jdojK7+MGOXpXx8z3Lp7Yoq:xGlnCIwMpj6ijKfxx8z3F0V", 
            "md5": "47363b94cee907e2b8926c1be61150c7"
        },
        "vt-scans": [
            {
                "sha256": "45317968759d3e37282ceb75149f627d648534c5b4685f6da3966d8f6fca662d", 
                "scans": {
                    "date": "Wed, 24 May 2017 12:42:12 GMT", 
                    "status": 3, 
                    "description": "VT scan available.", 
                    "results": [
                        {
                            "result": "W32.Ransomware_LTK.Trojan", 
                            "antivirus": "Bkav", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.GenericKD.2080196", 
                            "antivirus": "MicroWorld-eScan", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan/W32.Agent.246272.IJ", 
                            "antivirus": "nProtect", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Not detected", 
                            "antivirus": "CMC", 
                            "update": 20170523
                        }, 
                        {
                            "result": "Ransom.CryptoWall.WR5", 
                            "antivirus": "CAT-QuickHeal", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.GenericKD.2080196", 
                            "antivirus": "ALYac", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.Agent.0BGen", 
                            "antivirus": "Malwarebytes", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.Win32.CryptoWall.gen", 
                            "antivirus": "VIPRE", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan/Injector.bstc", 
                            "antivirus": "TheHacker", 
                            "update": 20170522
                        }, 
                        {
                            "result": "Trojan.GenericKD.2080196", 
                            "antivirus": "BitDefender", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan ( 004b3f201 )", 
                            "antivirus": "K7GW", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan ( 004b3f201 )", 
                            "antivirus": "K7AntiVirus", 
                            "update": 20170524
                        }, 
                        {
                            "result": "W32/Backdoor2.HXGO", 
                            "antivirus": "F-Prot", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Ransom.Cryptodefense", 
                            "antivirus": "Symantec", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Win32/Filecoder.CryptoWall.D", 
                            "antivirus": "ESET-NOD32", 
                            "update": 20170524
                        }, 
                        {
                            "result": "TROJ_CRYPTWALL.F", 
                            "antivirus": "TrendMicro-HouseCall", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Win32:Androp [Drp]", 
                            "antivirus": "Avast", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Win.Malware.Vawtrak-860", 
                            "antivirus": "ClamAV", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.Win32.Agent.ieva", 
                            "antivirus": "Kaspersky", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.Win32.Panda.eahzta", 
                            "antivirus": "NANO-Antivirus", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.Win32.Agent.246272.E[h]", 
                            "antivirus": "ViRobot", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Troj.Ransom.W32.Cryptodef.cbs!c", 
                            "antivirus": "AegisLab", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.GenericKD.2080196", 
                            "antivirus": "Ad-Aware", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Troj/Vawtrak-AN", 
                            "antivirus": "Sophos", 
                            "update": 20170524
                        }, 
                        {
                            "result": "TrojWare.Win32.Ransom.Crowti.~RM", 
                            "antivirus": "Comodo", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.GenericKD.2080196", 
                            "antivirus": "F-Secure", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.PWS.Panda.7278", 
                            "antivirus": "DrWeb", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Backdoor.Androm.Win32.14641", 
                            "antivirus": "Zillya", 
                            "update": 20170523
                        }, 
                        {
                            "result": "TROJ_CRYPTWALL.F", 
                            "antivirus": "TrendMicro", 
                            "update": 20170524
                        }, 
                        {
                            "result": "BehavesLike.Win32.PackedAP.dm", 
                            "antivirus": "McAfee-GW-Edition", 
                            "update": 20170523
                        }, 
                        {
                            "result": "Trojan.GenericKD.2080196 (B)", 
                            "antivirus": "Emsisoft", 
                            "update": 20170524
                        }, 
                        {
                            "result": "W32/Backdoor.CNGJ-2770", 
                            "antivirus": "Cyren", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Backdoor/Androm.ebf", 
                            "antivirus": "Jiangmin", 
                            "update": 20170524
                        }, 
                        {
                            "result": "W32/Vawtrak.AN!tr", 
                            "antivirus": "Fortinet", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan[Backdoor]/Win32.Androm", 
                            "antivirus": "Antiy-AVL", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Not detected", 
                            "antivirus": "Kingsoft", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.Generic.D1FBDC4", 
                            "antivirus": "Arcabit", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.Agent/Gen-Injector", 
                            "antivirus": "SUPERAntiSpyware", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Ransom:Win32/Crowti.A", 
                            "antivirus": "Microsoft", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan/Win32.MDA.R131384", 
                            "antivirus": "AhnLab-V3", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Ransom-CWall", 
                            "antivirus": "McAfee", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.Win32.CryptoWall.gen", 
                            "antivirus": "AVware", 
                            "update": 20170524
                        }, 
                        {
                            "result": "SScope.Trojan.Agent.2315", 
                            "antivirus": "VBA32", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Not detected", 
                            "antivirus": "Zoner", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Win32.Trojan.Bp-generic.Wpav", 
                            "antivirus": "Tencent", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan-Ransom.CryptoWall3", 
                            "antivirus": "Ikarus", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Win32.Trojan-Ransom.CryptoWall.C", 
                            "antivirus": "GData", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Generic_r.EKI", 
                            "antivirus": "AVG", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trj/WLT.B", 
                            "antivirus": "Panda", 
                            "update": 20170523
                        }, 
                        {
                            "result": "HEUR/QVM10.1.Malware.Gen", 
                            "antivirus": "Qihoo-360", 
                            "update": 20170524
                        }, 
                        {
                            "result": "TR/Crypt.Xpack.134743", 
                            "antivirus": "Avira", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.Generic (cloud:07G3VqhU2BR) ", 
                            "antivirus": "Rising", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.Cryptodef!", 
                            "antivirus": "Yandex", 
                            "update": 20170518
                        }, 
                        {
                            "result": "worm.win32.dorkbot.i", 
                            "antivirus": "Invincea", 
                            "update": 20170519
                        }, 
                        {
                            "result": "malicious_confidence_100% (W)", 
                            "antivirus": "CrowdStrike", 
                            "update": 20170130
                        }, 
                        {
                            "result": "malicious (high confidence)", 
                            "antivirus": "Endgame", 
                            "update": 20170515
                        }, 
                        {
                            "result": "W32.Malware.gen", 
                            "antivirus": "Webroot", 
                            "update": 20170524
                        }, 
                        {
                            "result": "Trojan.Win32.Agent.ieva", 
                            "antivirus": "ZoneAlarm", 
                            "update": 20170524
                        }, 
                        {
                            "result": "generic.ml", 
                            "antivirus": "Paloalto", 
                            "update": 20170524
                        }, 
                        {
                            "result": "static engine - malicious", 
                            "antivirus": "SentinelOne", 
                            "update": 20170516
                        }
                    ]
                }
            }
        ], 
        "static-pe-analysis": {
            "exports": [], 
            "target-machine": "Intel 386 or later processors and compatible processors", 
            "overlay-size": 0, 
            "imports": {
                "dbghelp.dll": [
                    "ImageNtHeader", 
                    "ImageRvaToSection", 
                    "ImageRvaToVa"
                ], 
                "comdlg32.dll": [
                    "GetSaveFileNameA", 
                    "GetOpenFileNameA"
                ], 
                "KERNEL32.DLL": [
                    "IsValidCodePage", 
                    "GetOEMCP", 
                    "GetACP", 
                    "GetCPInfo", 
                    "GetSystemTimeAsFileTime", 
                    "GetCurrentProcessId", 
                    "GetTickCount", 
                    "QueryPerformanceCounter", 
                    "HeapFree", 
                    "VirtualFree", 
                    "HeapCreate", 
                    "GetFileType", 
                    "SetHandleCount", 
                    "GetEnvironmentStringsW", 
                    "WideCharToMultiByte", 
                    "FreeEnvironmentStringsW", 
                    "GetEnvironmentStrings", 
                    "FreeEnvironmentStringsA", 
                    "InitializeCriticalSectionAndSpinCount", 
                    "LoadLibraryA", 
                    "IsDebuggerPresent", 
                    "SetUnhandledExceptionFilter", 
                    "UnhandledExceptionFilter", 
                    "GetCurrentProcess", 
                    "TerminateProcess", 
                    "EnterCriticalSection", 
                    "HeapSize", 
                    "LeaveCriticalSection", 
                    "DeleteCriticalSection", 
                    "GetLocaleInfoA", 
                    "WriteFile", 
                    "InterlockedDecrement", 
                    "GetLastError", 
                    "GetCurrentThreadId", 
                    "SetLastError", 
                    "InterlockedIncrement", 
                    "TlsFree", 
                    "TlsSetValue", 
                    "TlsAlloc", 
                    "TlsGetValue", 
                    "GetStartupInfoA", 
                    "ExitProcess", 
                    "GetProcAddress", 
                    "Sleep", 
                    "GetModuleHandleW", 
                    "GlobalCompact", 
                    "SetProcessWorkingSetSize", 
                    "EncodePointer", 
                    "OpenProcess", 
                    "GlobalUnWire", 
                    "GetStdHandle", 
                    "IsWow64Process", 
                    "GetProcessHandleCount", 
                    "GetProcessHeap", 
                    "FlushFileBuffers", 
                    "PulseEvent", 
                    "GetVersion", 
                    "RtlUnwind", 
                    "HeapAlloc", 
                    "VirtualAlloc", 
                    "HeapReAlloc", 
                    "GetStringTypeA", 
                    "MultiByteToWideChar", 
                    "GetStringTypeW", 
                    "GetCommandLineA", 
                    "GetProcessId", 
                    "LockResource", 
                    "GlobalDeleteAtom", 
                    "LCMapStringA", 
                    "LCMapStringW", 
                    "GetModuleFileNameA", 
                    "SetProcessPriorityBoost", 
                    "GlobalUnfix", 
                    "RequestWakeupLatency", 
                    "IsProcessInJob", 
                    "GetThreadTimes", 
                    "GetProcessTimes", 
                    "PeekNamedPipe"
                ], 
                "ADVAPI32.dll": [
                    "RegSetValueA", 
                    "RegQueryValueExA", 
                    "OpenProcessToken", 
                    "LookupPrivilegeValueA", 
                    "AdjustTokenPrivileges", 
                    "RegOpenKeyExA", 
                    "RegCloseKey", 
                    "RegCreateKeyA", 
                    "RegDeleteKeyA", 
                    "GetUserNameA"
                ], 
                "USER32.DLL": [
                    "EnableMenuItem", 
                    "GetDlgItem", 
                    "SendDlgItemMessageA", 
                    "AppendMenuA", 
                    "GetWindowLongA", 
                    "wvsprintfA", 
                    "SetWindowPos", 
                    "FindWindowA", 
                    "RedrawWindow", 
                    "GetWindowTextA", 
                    "EnableWindow", 
                    "GetSystemMetrics", 
                    "IsWindow", 
                    "CheckRadioButton", 
                    "UnregisterClassA", 
                    "SetCursor", 
                    "GetSysColorBrush", 
                    "DialogBoxParamA", 
                    "DestroyAcceleratorTable", 
                    "DispatchMessageA", 
                    "TranslateMessage", 
                    "LoadIconA", 
                    "EmptyClipboard", 
                    "SetClipboardData", 
                    "SetFocus", 
                    "CharUpperA", 
                    "OpenClipboard", 
                    "IsDialogMessageA", 
                    "TranslateAcceleratorA", 
                    "GetMessageA", 
                    "LoadAcceleratorsA", 
                    "RemoveMenu", 
                    "InvalidateRect", 
                    "ChildWindowFromPoint", 
                    "PostMessageA", 
                    "DestroyCursor", 
                    "CreateDialogParamA", 
                    "GetWindowRect", 
                    "IsMenu", 
                    "GetSubMenu", 
                    "SetDlgItemInt", 
                    "GetWindowPlacement", 
                    "CharLowerBuffA", 
                    "LoadCursorA", 
                    "CheckMenuRadioItem", 
                    "GetSysColor", 
                    "KillTimer", 
                    "DestroyIcon", 
                    "DestroyWindow", 
                    "PostQuitMessage", 
                    "GetClientRect", 
                    "MoveWindow", 
                    "GetSystemMenu", 
                    "SetTimer", 
                    "SetWindowPlacement", 
                    "InsertMenuItemA", 
                    "GetMenu", 
                    "CheckMenuItem", 
                    "SetMenuItemInfoA", 
                    "SetActiveWindow", 
                    "DefDlgProcA", 
                    "RegisterClassA", 
                    "EndDialog", 
                    "SetDlgItemTextA", 
                    "EnumClipboardFormats", 
                    "GetClipboardData", 
                    "CloseClipboard", 
                    "GetClassInfoA", 
                    "CallWindowProcA", 
                    "SetWindowLongA", 
                    "IsDlgButtonChecked", 
                    "SetWindowTextA", 
                    "CheckDlgButton", 
                    "GetActiveWindow", 
                    "MessageBoxA", 
                    "wsprintfA", 
                    "GetDlgItemTextA", 
                    "SendMessageA", 
                    "GetCursorPos", 
                    "TrackPopupMenu", 
                    "ClientToScreen", 
                    "DestroyMenu", 
                    "CreatePopupMenu"
                ], 
                "COMCTL32.dll": [
                    "ImageList_Destroy", 
                    "InitCommonControlsEx", 
                    "ImageList_ReplaceIcon", 
                    "ImageList_Remove", 
                    "CreateToolbarEx", 
                    "ImageList_SetBkColor", 
                    "ImageList_Create"
                ]
            }, 
            "overlay-entropy": 0, 
            "resources": [
                {
                    "count": 1, 
                    "sha1": "57d1f324f19a5669e9d71527d1cd73b0ff7c349d", 
                    "name": "RT_MESSAGETABLE", 
                    "size": 91740, 
                    "sha256": "ef97603fbb1ed118f972e91e194d6c34255c87c0fa23eb28089d6b58d870319d", 
                    "ssdeep": "1536:+rCm5BGSt4HJ0yfGOlXzbGcw7R4jjK7+MGVUXpXJfT8zooLpE4YZ1lObN:cCGBGSmHJ0y5lj6jdojK7+MGOXpXx8z1", 
                    "sdhash": "omitted", 
                    "type": "ASCII text, with very long lines, with no line terminators", 
                    "md5": "01351f623950a354353819e93c173cd8"
                }, 
                {
                    "count": 2, 
                    "sha1": "4260284ce14278c397aaf6f389c1609b0ab0ce51", 
                    "name": "RT_MANIFEST", 
                    "size": 381, 
                    "sha256": "4bb79dcea0a901f7d9eac5aa05728ae92acb42e0cb22e5dd14134f4421a3d8df", 
                    "ssdeep": "6:TM3iSnjUglRu9TbX+A1WBRu9TNNSTfUTdNciW7N2x8RTdN9TIHG:TM3iSnRuV1aMN2U5Nci62xA5NEG", 
                    "sdhash": "Not applicable", 
                    "type": "XML 1.0 document text", 
                    "md5": "1e4a89b11eae0fcf8bb5fdd5ec3b6f61"
                }
            ], 
            "entry-point": "0x403487", 
            "sections": [
                {
                    "sha1": "dad1bd7bddfe0bbf5e13eac1ed754ed0c784fda4", 
                    "name": ".text\u0000\u0000\u0000", 
                    "virtual-address": "0x1000", 
                    "raw-size": "0x8800", 
                    "raw-address": "0x86b7", 
                    "sha256": "a32a62ccd0d08681c0c3018a330e9bf3135239afc707a20e6761e34973aaf3d0", 
                    "flags": [
                        {
                            "name": "IMAGE_SCN_MEM_EXECUTE", 
                            "value": 536870912
                        }, 
                        {
                            "name": "IMAGE_SCN_CNT_CODE", 
                            "value": 32
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_READ", 
                            "value": 1073741824
                        }
                    ], 
                    "virtual-size": "0x86b7", 
                    "entropy": 6.52148, 
                    "ssdeep": "768:k1T+ZKX+VvDEzu+0CXIWBVip1IcaOK1uw7W9ekK+G5:UTCmzuw45LOf1uw7ueD+", 
                    "sdhash": "omitted", 
                    "type": "Code", 
                    "md5": "c14b15c6f6e70cd124a1dcde16f070b3"
                }, 
                {
                    "sha1": "dad1bd7bddfe0bbf5e13eac1ed754ed0c784fda4", 
                    "name": ".text\u0000\u0000\u0000", 
                    "virtual-address": "0x1000", 
                    "raw-size": "0x8800", 
                    "raw-address": "0x86b7", 
                    "sha256": "a32a62ccd0d08681c0c3018a330e9bf3135239afc707a20e6761e34973aaf3d0", 
                    "flags": [
                        {
                            "name": "IMAGE_SCN_MEM_EXECUTE", 
                            "value": 536870912
                        }, 
                        {
                            "name": "IMAGE_SCN_CNT_CODE", 
                            "value": 32
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_READ", 
                            "value": 1073741824
                        }
                    ], 
                    "virtual-size": "0x86b7", 
                    "entropy": 6.52148, 
                    "ssdeep": "768:k1T+ZKX+VvDEzu+0CXIWBVip1IcaOK1uw7W9ekK+G5:UTCmzuw45LOf1uw7ueD+", 
                    "sdhash": "omitted", 
                    "type": "Code", 
                    "md5": "c14b15c6f6e70cd124a1dcde16f070b3"
                }, 
                {
                    "sha1": "dad1bd7bddfe0bbf5e13eac1ed754ed0c784fda4", 
                    "name": ".text\u0000\u0000\u0000", 
                    "virtual-address": "0x1000", 
                    "raw-size": "0x8800", 
                    "raw-address": "0x86b7", 
                    "sha256": "a32a62ccd0d08681c0c3018a330e9bf3135239afc707a20e6761e34973aaf3d0", 
                    "flags": [
                        {
                            "name": "IMAGE_SCN_MEM_EXECUTE", 
                            "value": 536870912
                        }, 
                        {
                            "name": "IMAGE_SCN_CNT_CODE", 
                            "value": 32
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_READ", 
                            "value": 1073741824
                        }
                    ], 
                    "virtual-size": "0x86b7", 
                    "entropy": 6.52148, 
                    "ssdeep": "768:k1T+ZKX+VvDEzu+0CXIWBVip1IcaOK1uw7W9ekK+G5:UTCmzuw45LOf1uw7ueD+", 
                    "sdhash": "omitted", 
                    "type": "Code", 
                    "md5": "c14b15c6f6e70cd124a1dcde16f070b3"
                }, 
                {
                    "sha1": "f031b0de605ed5cb9d615e79240fe33af12eeac8", 
                    "name": ".rdata\u0000\u0000", 
                    "virtual-address": "0xa000", 
                    "raw-size": "0x2a00", 
                    "raw-address": "0x2820", 
                    "sha256": "36965f23b49ba777d7d0831f079e47087ad87ec2cf53ab952d8271e59287c43c", 
                    "flags": [
                        {
                            "name": "IMAGE_SCN_CNT_INITIALIZED_DATA", 
                            "value": 64
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_READ", 
                            "value": 1073741824
                        }
                    ], 
                    "virtual-size": "0x2820", 
                    "entropy": 5.41741, 
                    "ssdeep": "192:vhpls/KRn4nnnnnnnnnnLurh2AdTFJL/S+ZozitizDvZ1IHb7Dec8:5plGluFnJL/BZozitizDvZQPKc8", 
                    "sdhash": "omitted", 
                    "type": "Data", 
                    "md5": "196eabd2bfebff72df631efba401fbdd"
                }, 
                {
                    "sha1": "f031b0de605ed5cb9d615e79240fe33af12eeac8", 
                    "name": ".rdata\u0000\u0000", 
                    "virtual-address": "0xa000", 
                    "raw-size": "0x2a00", 
                    "raw-address": "0x2820", 
                    "sha256": "36965f23b49ba777d7d0831f079e47087ad87ec2cf53ab952d8271e59287c43c", 
                    "flags": [
                        {
                            "name": "IMAGE_SCN_CNT_INITIALIZED_DATA", 
                            "value": 64
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_READ", 
                            "value": 1073741824
                        }
                    ], 
                    "virtual-size": "0x2820", 
                    "entropy": 5.41741, 
                    "ssdeep": "192:vhpls/KRn4nnnnnnnnnnLurh2AdTFJL/S+ZozitizDvZ1IHb7Dec8:5plGluFnJL/BZozitizDvZQPKc8", 
                    "sdhash": "omitted", 
                    "type": "Data", 
                    "md5": "196eabd2bfebff72df631efba401fbdd"
                }, 
                {
                    "sha1": "b48165649b37200709423573adfac5d9297ec1e0", 
                    "name": ".data\u0000\u0000\u0000", 
                    "virtual-address": "0xd000", 
                    "raw-size": "0x1a200", 
                    "raw-address": "0x33c2be0", 
                    "sha256": "30c22d47b8294b12b0f15aeba97f129dd682de09faf32b32b9051456762e5aef", 
                    "flags": [
                        {
                            "name": "IMAGE_SCN_CNT_INITIALIZED_DATA", 
                            "value": 64
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_WRITE", 
                            "value": 2147483647
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_READ", 
                            "value": 1073741824
                        }
                    ], 
                    "virtual-size": "0x33c2be0", 
                    "entropy": 2.35016, 
                    "ssdeep": "96:jgT/tQBwX2jVmW8rP37hO50ZU0GbgtIQYtqHKm+S8/ACEba7VKbWmkdb/jABgtN0:jstQB1VmWBqUBqIQDXy4CGa7YbqECE", 
                    "sdhash": "omitted", 
                    "type": "Data", 
                    "md5": "dde216807b0f1105151c2caf33fee281"
                }, 
                {
                    "sha1": "b48165649b37200709423573adfac5d9297ec1e0", 
                    "name": ".data\u0000\u0000\u0000", 
                    "virtual-address": "0xd000", 
                    "raw-size": "0x1a200", 
                    "raw-address": "0x33c2be0", 
                    "sha256": "30c22d47b8294b12b0f15aeba97f129dd682de09faf32b32b9051456762e5aef", 
                    "flags": [
                        {
                            "name": "IMAGE_SCN_CNT_INITIALIZED_DATA", 
                            "value": 64
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_WRITE", 
                            "value": 2147483647
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_READ", 
                            "value": 1073741824
                        }
                    ], 
                    "virtual-size": "0x33c2be0", 
                    "entropy": 2.35016, 
                    "ssdeep": "96:jgT/tQBwX2jVmW8rP37hO50ZU0GbgtIQYtqHKm+S8/ACEba7VKbWmkdb/jABgtN0:jstQB1VmWBqUBqIQDXy4CGa7YbqECE", 
                    "sdhash": "omitted", 
                    "type": "Data", 
                    "md5": "dde216807b0f1105151c2caf33fee281"
                }, 
                {
                    "sha1": "b48165649b37200709423573adfac5d9297ec1e0", 
                    "name": ".data\u0000\u0000\u0000", 
                    "virtual-address": "0xd000", 
                    "raw-size": "0x1a200", 
                    "raw-address": "0x33c2be0", 
                    "sha256": "30c22d47b8294b12b0f15aeba97f129dd682de09faf32b32b9051456762e5aef", 
                    "flags": [
                        {
                            "name": "IMAGE_SCN_CNT_INITIALIZED_DATA", 
                            "value": 64
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_WRITE", 
                            "value": 2147483647
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_READ", 
                            "value": 1073741824
                        }
                    ], 
                    "virtual-size": "0x33c2be0", 
                    "entropy": 2.35016, 
                    "ssdeep": "96:jgT/tQBwX2jVmW8rP37hO50ZU0GbgtIQYtqHKm+S8/ACEba7VKbWmkdb/jABgtN0:jstQB1VmWBqUBqIQDXy4CGa7YbqECE", 
                    "sdhash": "omitted", 
                    "type": "Data", 
                    "md5": "dde216807b0f1105151c2caf33fee281"
                }, 
                {
                    "sha1": "b1be2680150b9ab2177ecc48db9dade0b4f752dc", 
                    "name": ".rsrc\u0000\u0000\u0000", 
                    "virtual-address": "0x33d0000", 
                    "raw-size": "0x16a00", 
                    "raw-address": "0x1687c", 
                    "sha256": "04f9b14aaf26e35e0f32fca09bc63e7fbdd16d6bba24618625917a54fbe8a78c", 
                    "flags": [
                        {
                            "name": "IMAGE_SCN_CNT_INITIALIZED_DATA", 
                            "value": 64
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_READ", 
                            "value": 1073741824
                        }
                    ], 
                    "virtual-size": "0x1687c", 
                    "entropy": 6.02005, 
                    "ssdeep": "1536:FrCm5BGSt4HJ0yfGOlXzbGcw7R4jjK7+MGVUXpXJfT8zooLpE4YZ1lOb+:5CGBGSmHJ0y5lj6jdojK7+MGOXpXx8zm", 
                    "sdhash": "omitted", 
                    "type": "Data", 
                    "md5": "be2219bffc936ebf7c285253194f3167"
                }, 
                {
                    "sha1": "b1be2680150b9ab2177ecc48db9dade0b4f752dc", 
                    "name": ".rsrc\u0000\u0000\u0000", 
                    "virtual-address": "0x33d0000", 
                    "raw-size": "0x16a00", 
                    "raw-address": "0x1687c", 
                    "sha256": "04f9b14aaf26e35e0f32fca09bc63e7fbdd16d6bba24618625917a54fbe8a78c", 
                    "flags": [
                        {
                            "name": "IMAGE_SCN_CNT_INITIALIZED_DATA", 
                            "value": 64
                        }, 
                        {
                            "name": "IMAGE_SCN_MEM_READ", 
                            "value": 1073741824
                        }
                    ], 
                    "virtual-size": "0x1687c", 
                    "entropy": 6.02005, 
                    "ssdeep": "1536:FrCm5BGSt4HJ0yfGOlXzbGcw7R4jjK7+MGVUXpXJfT8zooLpE4YZ1lOb+:5CGBGSmHJ0y5lj6jdojK7+MGOXpXx8zm", 
                    "sdhash": "omitted", 
                    "type": "Data", 
                    "md5": "be2219bffc936ebf7c285253194f3167"
                }
            ], 
            "compi-timestamp": "Tue, 13 Jan 2015 09:25:45 GMT"
        }
    }
}

```



