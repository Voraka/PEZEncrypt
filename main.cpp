#include <Windows.h>
#include <winnt.h>
#include <excpt.h>
#include <wchar.h>
#include <stdio.h>
#include "Injector.h"
#include "Encrypter.h"

#define BB(x) __asm _emit x

#define STRING_COMPARE(str1, str2) \
    __asm push str1 \
    __asm call get_string_length \
    __asm push eax \
    __asm push str1 \
    __asm mov eax, str2 \
    __asm push eax \
    __asm call strings_equal

#pragma code_seg(".pediy")

void __declspec(naked) injection_stub(void) {
	//Fake pushad
	BB(0x60) BB(0xE8) BB(0x03) BB(0x00) BB(0x00) BB(0x00) BB(0xE9) BB(0xEB) BB(0x05) BB(0x5D) BB(0x90) BB(0x45) BB(0x55) BB(0xC3) BB(0xE8) BB(0x01) BB(0x00) BB(0x00)
	BB(0x00) BB(0xEB) BB(0xF8) BB(0x73) BB(0x01) BB(0xEB) BB(0x58) BB(0x8B) BB(0xC8) BB(0x83) BB(0xC0) BB(0x0F) BB(0x50) BB(0x51) BB(0xC3) BB(0xEB) BB(0x61)
	__asm { //Prologue, stub entry point
		sub esp, 0x30			//Save stack place for esp law
		push ecx
		push edi
		push esi
		call ExpHandle
		mov edi, fs:[0]
		pushad                  //Save context of entry point
		push ebp
		mov fs : [0], esp
		add fs : [0], 0x4
		mov ebp, esp
		sub esp, 0x200          //Space for local variables

	}
	PIMAGE_DOS_HEADER target_image_base;
	PIMAGE_DOS_HEADER kernel32_image_base;
	__asm {
		call get_module_list    //Get PEB
		mov ebx, eax
		push 0
		push ebx
		call get_dll_base       //Get image base of process
		mov[target_image_base], eax
		push 2
		push ebx
		call get_dll_base       //Get kernel32.dll image base
		mov[kernel32_image_base], eax
	}
	__asm {
		jmp stubback
		push eax
		push fs : [0]
		mov fs : [0], esp
	}
	BB(0xEB)
		stub:
	__asm {
		push ebp
		mov ebp, esp
		sub esp, 0x20
		fldz
		fnstenv[esp - 0xC]
		pop eax
		mov esp, ebp
		pop ebp
		pop ebx
		inc ebx
		inc ebx
		jmp ebx				//ret addr+2
	}
	//eax + 0xF
	BB(0x6A) BB(0xAC) BB(0x8E)
	BB(0xAA) BB(0xCD) BB(0x0D) BB(0x2C) BB(0xCD) BB(0x8C) BB(0x8D) BB(0xAC) BB(0x8C)
	BB(0xA8) BB(0x0F) BB(0x6C) BB(0xAC) BB(0x0E) BB(0x8E) BB(0x2D) BB(0xED) BB(0xCD)
	BB(0xC8) BB(0x2D) BB(0x8D) BB(0x8E) BB(0xAC) BB(0x4E)
	BB(0)
	BB(0x66)	//Checksum stub
	//toplevelhandler	eax + 0xF + 0x1D
	__asm {
		push ebp
		mov ebp, esp
		sub esp, 0x200
	}
	struct _EXCEPTION_POINTERS *ExceptionInfo;
	DWORD DecAddr;
	__asm {
		mov eax, [ebp + 0x8]
		mov ExceptionInfo, eax
		call getjmpaddr
		getjmpaddr :
		pop eax
			jmp getjmpaddrend
			jmp epilogue
			getjmpaddrend :
			add eax, 0x3
			mov DecAddr, eax
	}
	if (ExceptionInfo->ContextRecord->Dr0 || ExceptionInfo->ContextRecord->Dr1 || ExceptionInfo->ContextRecord->Dr2 || ExceptionInfo->ContextRecord->Dr3)
	{
		DecAddr += ExceptionInfo->ContextRecord->Dr7;
	}
	ExceptionInfo->ContextRecord->Esp -= 4;
	*(DWORD*)(ExceptionInfo->ContextRecord->Esp) = ExceptionInfo->ContextRecord->Eip + 2;
	ExceptionInfo->ContextRecord->Eip = DecAddr;
	__asm{
		mov esp, ebp
		pop ebp
		mov eax, EXCEPTION_CONTINUE_EXECUTION
		ret 0x4
	}
	stubback:
	__asm{
		push 0
	}
	BB(0xCD)
	BB(0x3)
	__asm { //Dummy Code
		mov ecx, 0x23333
		l:
		call get_module_list
		inc eax
		loop l
		popad
	}
	BB(0xEB)
	BB(0x2F)
	BB(0xE8)
	BB(0x56)
	BB(0xFF)
    __asm {			//Decrypt all sections
        push kernel32_image_base
        push target_image_base
    }
	__asm{
		push 1
		int 3
	}
	__asm{			//Dummy code
		mov esp, ebp
		pop ebp
		popad
		jmp section_name
		cld
		xor eax, eax
		mov eax, [eax]
		pushad
		pushfd
	}
	BB(0xFF)
	BB(0xCD)
	BB(0xEB)
	__asm{
    	call decrypt_sections
		push ebp
		//int 0x2
		call epilogue
	}
	BB(0xE8)
    ///////////////////////////////////////////////////////////////////
    //Gets the module list
    //Preserves no registers, PEB_LDR_DATA->PPEB_LDR_DATA->InLoadOrderModuleList returned in EAX
    ///////////////////////////////////////////////////////////////////
    __asm {
    get_module_list:
            mov eax, fs:[0x30]  //PEB
            mov eax, [eax+0xC]  //PEB_LDR_DATA->PPEB_LDR_DATA
            mov eax, [eax+0xC]  //PEB_LDR_DATA->PPEB_LDR_DATA->InLoadOrderModuleList
            retn
    }
    ///////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////
    //Gets the DllBase member of the InLoadOrderModuleList structure
    //Call as void *get_dll_base(void *InLoadOrderModuleList, int index)
    ///////////////////////////////////////////////////////////////////
    __asm {
    get_dll_base:
        push ebp
        mov ebp, esp
        mov eax, [ebp+0x8]      //PEB->PPEB_LDR_DATA->InLoadOrderModuleList address
        mov ecx, [ebp+0xC]      //Set loop index
        cmp ecx, 0x0			//Initial zero check
        je done
        traverse_list:
            mov eax, [eax]      //Go to next entry
        loop traverse_list
        done:
            mov eax, [eax+0x18] //PEB->PPEB_LDR_DATA->InLoadOrderModuleList.DllBase
            mov esp, ebp
            pop ebp
            ret 0x8
    }
    ///////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////
    //Gets the length of the string passed as the parameter
    //Call as int get_string_length(char *str)
    ///////////////////////////////////////////////////////////////////
    __asm {
    get_string_length:
        push ebp
        mov ebp, esp
        mov edi, [ebp+0x8]      //String held here
        mov eax, 0x0            //EAX holds size of the string
        counting_loop:
            cmp byte ptr[edi], 0x0//Current byte is null-terminator?
            je string_done      //Done, leave loop
            inc edi             //Go to next character
            inc eax             //size++
            jmp counting_loop
        string_done:
            mov esp, ebp
            pop ebp
            retn
    }
    ///////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////
    //String comparison function, checks for equality of two strings
    //Call as bool strings_equal(char *check_string, char *known_string, int known_string_length)
    ///////////////////////////////////////////////////////////////////
    __asm {
    strings_equal:
        push ebp
        mov ebp, esp

        mov edi, [ebp+0xC]      //EDI gets known_string
        mov ecx, [ebp+0x10]     //ECX gets known_string_length
		cmp ecx, 0x0
		je comp

    restore_str:
		mov al, [edi]
		rol al, 0x3
		mov [edi], al
		inc edi
		loop restore_str

	comp:
        mov ecx, [ebp+0x10]     //ECX gets known_string_length
        mov edi, [ebp+0xC]      //EDI gets known_string
        mov esi, [ebp+0x8]      //ESI gets check_string
        cld                     //Forward comparison
    	repe cmpsb              //Start comparing
        mov esi, 0x0            //Assume unequal
        jne end1
        mov esi, 0x1            //Strings equal
	end1:
        mov edi, [ebp+0xC]      //EDI gets known_string
        mov ecx, [ebp+0x10]     //ECX gets known_string_length
		cmp ecx, 0x0
		je end2

    destore_str:
		mov al, [edi]
		rol al, 0x5
		mov [edi], al
		inc edi
		loop destore_str

    end2:
		mov eax, esi
        mov esp, ebp
        pop ebp
        ret 0xC
    }
    ///////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////
    //Implementation of GetProcAddress
    //Call as FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
    ///////////////////////////////////////////////////////////////////
    get_proc_address:
        __asm {
            push ebp
            mov ebp, esp
            sub esp, 0x200
        }
        PIMAGE_DOS_HEADER kernel32_dos_header;
        PIMAGE_NT_HEADERS kernel32_nt_headers;
        PIMAGE_EXPORT_DIRECTORY kernel32_export_dir;
        unsigned short *ordinal_table;
        unsigned long *function_table;
        FARPROC function_address;
        int function_names_equal;
        __asm { //Initializations
            mov eax, [ebp+0x8]
            mov kernel32_dos_header, eax
            mov function_names_equal, 0x0
        }
        kernel32_nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)kernel32_dos_header + kernel32_dos_header->e_lfanew);
        kernel32_export_dir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)kernel32_dos_header +
            kernel32_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        for(unsigned long i = 0; i < kernel32_export_dir->NumberOfNames; ++i) {
            char *eat_entry = (*(char **)((DWORD_PTR)kernel32_dos_header + kernel32_export_dir->AddressOfNames + i * sizeof(DWORD_PTR)))
                + (DWORD_PTR)kernel32_dos_header;   //Current name in name table
            STRING_COMPARE([ebp+0xC], eat_entry) //Compare function in name table with the one we want to find
            __asm mov function_names_equal, eax
            if(function_names_equal == 1) {
                ordinal_table = (unsigned short *)(kernel32_export_dir->AddressOfNameOrdinals + (DWORD_PTR)kernel32_dos_header);
                function_table = (unsigned long *)(kernel32_export_dir->AddressOfFunctions + (DWORD_PTR)kernel32_dos_header);
                function_address = (FARPROC)((DWORD_PTR)kernel32_dos_header + function_table[ordinal_table[i]]);
                break;
            }
        }
        __asm {
            mov eax, function_address
            mov esp, ebp
            pop ebp
            ret 0x8
        }
    ///////////////////////////////////////////////////////////////////
    //Decrypts all sections in the image, excluding .rdata/.rsrc/.pediy
    //Call as void decrypt_sections(void *image_base, void *kernel32_base)
    ///////////////////////////////////////////////////////////////////
    decrypt_sections:
        __asm {
            push ebp
            mov ebp, esp
            sub esp, 0x200
        }
        typedef BOOL (WINAPI *pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect,
            PDWORD lpflOldProtect);
        char *str_virtualprotect;
        char *str_section_name;
        char *str_rdata_name;
        char *str_rsrc_name;
        PIMAGE_DOS_HEADER target_dos_header;
        int section_offset;
        int section_names_equal;
        unsigned long old_protections;
        pVirtualProtect virtualprotect_addr;
        __asm { //String initializations
            jmp virtualprotect
            virtualprotectback:
                pop esi
                mov str_virtualprotect, esi
            jmp section_name
            section_nameback:
                pop esi
                mov str_section_name, esi
            jmp rdata_name
            rdata_nameback:
                pop esi
                mov str_rdata_name, esi
            jmp rsrc_name
            rsrc_nameback:
                pop esi
                mov str_rsrc_name, esi
        }
        __asm { //Initializations
            mov eax, [ebp+0x8]
            mov target_dos_header, eax
            mov section_offset, 0x0
            mov section_names_equal, 0x0
            push str_virtualprotect
            push [ebp+0xC]
            call get_proc_address
            mov virtualprotect_addr, eax
        }
		LPVOID ESp;
		__asm mov ESp, esp
        virtualprotect_addr(ESp, 0x400, PAGE_READWRITE, &old_protections);
		PIMAGE_NT_HEADERS target_nt_headers;
		target_nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)target_dos_header + target_dos_header->e_lfanew);
        for(unsigned long j = 0; j < target_nt_headers->FileHeader.NumberOfSections; ++j) {
            section_offset = (target_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) +
                (sizeof(IMAGE_SECTION_HEADER) * j));
            PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((DWORD_PTR)target_dos_header + section_offset);
            STRING_COMPARE(str_section_name, section_header)
            __asm mov section_names_equal, eax
            STRING_COMPARE(str_rdata_name, section_header)
            __asm add section_names_equal, eax
            STRING_COMPARE(str_rsrc_name, section_header)
            __asm add section_names_equal, eax
            if(section_names_equal == 0) {
                unsigned char *current_byte =
                    (unsigned char *)((DWORD_PTR)target_dos_header + section_header->VirtualAddress);
                unsigned char *last_byte =
                    (unsigned char *)((DWORD_PTR)target_dos_header + section_header->VirtualAddress
                    + section_header->SizeOfRawData);
                const unsigned int num_rounds = 32;
                const unsigned int key[4] = {0x12345678, 0xAABBCCDD, 0x10101010, 0xF00DBABE};
                for(current_byte; current_byte < last_byte; current_byte += 8) {
                    virtualprotect_addr(current_byte, sizeof(DWORD_PTR) * 2, PAGE_EXECUTE_READWRITE, &old_protections);
                    unsigned int block1 = (*current_byte << 24) | (*(current_byte+1) << 16) |
                        (*(current_byte+2) << 8) | *(current_byte+3);
                    unsigned int block2 = (*(current_byte+4) << 24) | (*(current_byte+5) << 16) |
                        (*(current_byte+6) << 8) | *(current_byte+7);
                    unsigned int full_block[] = {block1, block2};
                    unsigned int delta = 0x9E3779B9;
                    unsigned int sum = (delta * num_rounds);
                    for (unsigned int i = 0; i < num_rounds; ++i) {
                        full_block[1] -= (((full_block[0] << 4) ^ (full_block[0] >> 5)) + full_block[0]) ^ (sum + key[(sum >> 11) & 3]);
                        sum -= delta;
                        full_block[0] -= (((full_block[1] << 4) ^ (full_block[1] >> 5)) + full_block[1]) ^ (sum + key[sum & 3]);
                    }
                    virtualprotect_addr(current_byte, sizeof(DWORD_PTR) * 2, old_protections, NULL);
                    *(current_byte+3) = (full_block[0] & 0x000000FF);
                    *(current_byte+2) = (full_block[0] & 0x0000FF00) >> 8;
                    *(current_byte+1) = (full_block[0] & 0x00FF0000) >> 16;
                    *(current_byte+0) = (full_block[0] & 0xFF000000) >> 24;
                    *(current_byte+7) = (full_block[1] & 0x000000FF);
                    *(current_byte+6) = (full_block[1] & 0x0000FF00) >> 8;
                    *(current_byte+5) = (full_block[1] & 0x00FF0000) >> 16;
                    *(current_byte+4) = (full_block[1] & 0xFF000000) >> 24;
                }
            }
            section_names_equal = 0;
        }
        __asm {
            mov esp, ebp
            pop ebp
            ret 0x8
        }

	BB(0xEB)
	epilogue:
	__asm { //Epilogue, stub exit point
		pop ecx
		mov eax, target_image_base
        add eax, 0xCCDDEEFF     //Signature to be replaced by original entry point (OEP)
        mov esp, ebp
        mov [esp+0x5C], eax     //Store OEP
		mov edi, [esp+0x4]		//Restore fs:[0]
		add esp, 0xC
		pop ebp
		mov ebx ,[esp+0x4]
		mov edx, [esp+0x8]
		mov ecx, [esp+0xC]
		mov eax, [esp+0x12]
		pop esp
		mov fs:[0], edi
		pop esi
		pop edi
		add esp, 0x30
        ret                 //Jump to OEP
    }
	ExpHandle:
	__asm{
		call GetHAddr
		jmp RealHandler
		GetHAddr:
		pop esi
		ret
	}
	RealHandler:
	__asm{
		pushad
		push ebp
		mov ebp, esp
		sub esp, 0x200
	}
	DWORD i;
	EXCEPTION_RECORD* excrecord;
	CONTEXT* conrecord;
	DWORD start;
	DWORD stop;
	__asm {
		mov eax, [esp+0x228]
		mov excrecord, eax
		mov eax, [esp+0x230]
		mov conrecord, eax
	}

	i = *(DWORD*) conrecord->Esp;
	if(i==0)
	{
		BB(0x6A)
		BB(0x01)			//push 0x1
		BB(0xCD)
		BB(0x03)			// int 03
		BB(0x91)
		BB(0x64)
		BB(0x74)
		BB(0xEB)
		BB(0xFF)
		BB(0x90)
		BB(0x60)
		BB(0x61)
		BB(0xE9)
		BB(0x12)
		BB(0xCC)
		BB(0x90)
		BB(0xA4)
		BB(0x64)
		BB(0x64)
		BB(0x33)
		BB(0x21)
		BB(0xF0)
		BB(0xE8)
		__asm {
			call stub
		error :
			int 0x2
			push eax
			add ebx, 0x10
			push ebx
			call Checksum
			xor eax, eax		//Test
			test eax, eax
			jne error
		}
		__asm {
			call get_module_list    //Get PEB
			push 2
			push eax
			call get_dll_base       //Get kernel32.dll image base
			mov ecx, eax
			call stub
			rdtsc
			add eax, 0xF
			push eax
			mov ebx, eax
			push ecx
			call get_proc_address
			add ebx, 0x1D
			push ebx
			call eax
		}
	}
	if(i==0x55AA)
	{
		__asm{
			//TODO
		}
	}

	i = 0x13;
	__asm {
		call ExpHandle
		mov start, esi
		jmp HandleEnd
	}
	BB(0xEB)
	BB(0x74)			//Checksum Handle
	__asm{
	HandleEndback:
		pop edi
		mov stop, edi
	}
	i++;
	__asm{
		mov eax, start
		push eax
		mov eax, stop
		inc eax
		push eax
		call eax		//Check
		pop ebx
		pop ebx
		mov ebx, i
		add eax, ebx
		mov i, eax
	}

	if (excrecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
		conrecord->Eip ^= conrecord->Dr0;
		conrecord->Eip ^= conrecord->Dr1;
		conrecord->Eip ^= conrecord->Dr2;
		conrecord->Eip ^= conrecord->Dr3;
		conrecord->Eip += i;
		conrecord->Esp += 4;
		__asm {
			mov esp, ebp
			pop ebp
			popad
			mov eax, ExceptionContinueExecution
			ret
		}
	}
	else
	{
		if(excrecord->ExceptionCode == STATUS_ACCESS_VIOLATION && excrecord->ExceptionInformation[1] != 0xFFFFFFFF && excrecord->ExceptionInformation[0] !=0)
			conrecord->Eip += i + 0xC;
		__asm {
			mov esp, ebp
			pop ebp
			popad
			mov eax, ExceptionContinueSearch
			ret
		}
	}
	__asm{
	HandleEnd:
		call HandleEndback
	}
	BB(0xEB)
	Checksum:
	__asm {
		push ebp
		mov ebp, esp
		sub esp, 0x200
	}
	DWORD s;
	DWORD ed;
	DWORD counter;
	__asm{
		mov eax, [ebp+0x8]
		mov ed, eax
		mov eax, [ebp+0xC]
		mov s, eax
	}
	counter = ed - s;
	__asm{
		mov ecx, counter;
		inc ecx
		xor eax, eax
		mov edx, eax
		mov eax, s
		test edx, edx
		je checkloop
	}
	BB(0xE8)
	__asm{
	checkloop:
		mov bl, cs:[eax]
		xor dl, bl
		inc eax
		loop checkloop
		xor edx, edx	//for test
		cmp edx, ecx
		je loopdone
		pop eax
		pop ebx
		mov start, ebx
		inc eax
		push eax
		jmp HandleEndback
	}
	BB(0xEB)
	__asm{
		loopdone:
		mov esp, ebp
		pop ebp
		mov eax, edx
		ret
	}
    __asm {
    virtualprotect:
        call virtualprotectback
        BB(0xCA) BB(0x2D) BB(0x4E) BB(0x8E) BB(0xAE) BB(0x2C) BB(0x8D)
        BB(0x0A) BB(0x4E) BB(0xED) BB(0x8E) BB(0xAC) BB(0x6C) BB(0x8E) BB(0)
    rdata_name:
        call rdata_nameback
        BB(0xC5) BB(0x4E) BB(0x8C) BB(0x2C) BB(0x8E) BB(0x2C) BB(0)
    rsrc_name:
        call rsrc_nameback
        BB(0xC5) BB(0x4E) BB(0x6E) BB(0x4E) BB(0x6C) BB(0)
    section_name:
        call section_nameback
        BB(0xC5) BB(0x0E) BB(0xAC) BB(0x8C) BB(0x2D) BB(0x2F) BB(0)
        int 0x3                 //Function signature
        int 0x3
        int 0x3
        int 0x3
    }
}
#pragma code_seg()
#pragma comment(linker, "/SECTION:.pediy,re")

wchar_t *convert_to_unicode(char *str, unsigned int length) {
    wchar_t *wstr;
    int wstr_length = MultiByteToWideChar(CP_ACP, 0, str, (length + 1), NULL, 0);
    wstr = (wchar_t *)malloc(wstr_length * sizeof(wchar_t));
    wmemset(wstr, 0, wstr_length);
    if (wstr == NULL)
        return NULL;
    int written = MultiByteToWideChar(CP_ACP, 0, str, length, wstr, wstr_length);
    if(written > 0)
        return wstr;
    return NULL;
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        printf("Usage: ./%s <target>\n", argv[0]);
        return -1;
    }
    wchar_t *target_file_name = convert_to_unicode(argv[1], strlen(argv[1]));
    if(target_file_name == NULL) {
        printf("Could not convert %s to unicode\n", argv[1]);
        return -1;
    }

	CopyFile(target_file_name, L"packed.exe", FALSE);
	target_file_name = L"packed.exe";

    pfile_info target_file = file_info_create();
    void (*stub_addr)(void) = injection_stub;
    unsigned int stub_size = get_stub_size(stub_addr);
    unsigned int stub_size_aligned = 0;
    bool map_file_success = map_file(target_file_name, stub_size, false, target_file);
    if(map_file_success == false) {
        wprintf(L"Could not map target file\n");
        return -1;
    }
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)target_file->file_mem_buffer;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
    stub_size_aligned = align_to_boundary(stub_size, nt_headers->OptionalHeader.SectionAlignment);
    const char *section_name = ".pediy";
    file_info_destroy(target_file);
    target_file = file_info_create();
    (void)map_file(target_file_name, stub_size_aligned, true, target_file);
    PIMAGE_SECTION_HEADER new_section = add_section(section_name, stub_size_aligned, target_file->file_mem_buffer);
    if(new_section == NULL) {
        wprintf(L"Could not add new section to file");
        return -1;
    }
    write_stub_entry_point(nt_headers, stub_addr);
    copy_stub_instructions(new_section, target_file->file_mem_buffer, stub_addr);
    change_file_oep(nt_headers, new_section);
    encrypt_file(nt_headers, target_file, section_name);
    int flush_view_success = FlushViewOfFile(target_file->file_mem_buffer, 0);
    if(flush_view_success == 0)
        wprintf(L"Could not save changes to file");
    file_info_destroy(target_file);
    return 0;
}