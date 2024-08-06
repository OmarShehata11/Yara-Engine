#include <yara.h>
#include <stdio.h>
#include <wchar.h>
#include <assert.h>
#include <stdlib.h>
#include <vector>
#include <psapi.h>
#include <cctype>
#include <iostream>
#include <filesystem>
#include "../getopt_mb_uni_src_2022/getopt.h"

namespace fs = std::filesystem; // for the file system iterator

#define BUFFER_SIZE 200

// check the # of rule matched.
int ruleMatchedProc = 0;
int ruleMatchedFile = 0;

// Call-Back function for the Scanner
int YaraCallBack(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);

void Usage(wchar_t* procName);

// Function to convert memory protection constants to human-readable strings
const char* GetMemoryProtectionString(DWORD protection);


namespace YaraNS
{
	class YaraClass
	{

	private:
		YR_COMPILER* pYaraCompiler = nullptr;
		YR_RULES* pYaraRules = nullptr;
	public:
		YaraClass()
		{
			if ((yr_initialize()) != ERROR_SUCCESS)
				printf("\033[1;31m[-]\033[0m error while init the libyara\n");

			if ((yr_compiler_create(&pYaraCompiler) != ERROR_SUCCESS))
				printf("\033[1;31m[-]\033[0m error, while creating the compiler\n");

		}


		~YaraClass()
		{  // clean up everything.
			yr_compiler_destroy(pYaraCompiler);

			if ((yr_finalize()) != ERROR_SUCCESS)
				printf("\033[1;31m[-]\033[0m error while finalize the libyara\n");
		}

		int CompileRuleFile(const char* fileName)
		{
			FILE* yaraFile;

			fopen_s(&yaraFile, fileName, "r");

			if (yaraFile == nullptr)
			{
				printf("\033[1;31m[-]\033[0m error while openning the yara file, error code %d\n", GetLastError());
				return -1;
			}
			/* NOTE:
			   You can add a call back function in case if there's an error while compiling the yara file
			   and you want to know detailed errors about the compilation error. but I won't use it.
			*/

			// Now add the file:
			if ((yr_compiler_add_file(pYaraCompiler, yaraFile, NULL, NULL)) != 0)
			{
				printf("\033[1;31m[-]\033[0m error while compiling the yara file.\n");
				return -1;
			}

			/* BIG NOTE:
				If the 	yr_compiler_add_file() function failed, you can't use the compiler any more,
				neither for adding more rules (rules file) nor getting compiled rules.
			*/

			fclose(yaraFile);

			// now everything is good, let's return.
			return ERROR_SUCCESS;


		}

		bool AddRuleToCompiler()
		{
			if ((yr_compiler_get_rules(pYaraCompiler, &pYaraRules)) != ERROR_SUCCESS)
			{
				printf("\033[1;31m[-]\033[0m error while using yr_compiler_get_rules() function.\n");
				return false;
			}
			return true;
		}

		// scan a file :
		int ScanFile(const char* fileName)
		{

			if ((yr_rules_scan_file(pYaraRules, fileName, SCAN_FLAGS_REPORT_RULES_MATCHING, YaraCallBack, nullptr, 0)) != ERROR_SUCCESS)
			{
				printf("\033[1;31m[-]\033[0m error while scanning the target file. error code %d\n", GetLastError());
				return -1;
			}

			// now the scan is succedded, and the callback function is called. let's return.
			return ERROR_SUCCESS;
		}

		// scan a memory rather than a file:
		void ScanMemory(std::vector<byte> region, PMEMORY_BASIC_INFORMATION RegionInfoUserData)
		{
			const unsigned char* buffer = (unsigned char*)region.data();
			int bufferSize = region.size();

			if (strlen((char*)buffer) == 0)
				return;

			int ret = yr_rules_scan_mem(pYaraRules, buffer, bufferSize, SCAN_FLAGS_NO_TRYCATCH, YaraCallBack, RegionInfoUserData, 0);
		}

		// adding a list of yara files from a dir
		bool IterateDir(char* Dir)
		{
			int numOfYaraFile = 0;
			for (const auto& file : fs::recursive_directory_iterator(Dir))
			{
				if (file.path().extension() == ".yar" || file.path().extension() == ".yara")
				{
					if (CompileRuleFile(file.path().string().c_str()) != ERROR_SUCCESS)
					{
						printf("\033[1;31m[-]\033[0m error while adding the yara file : \033[34;5%s\033[0m\n", file.path().string().c_str());
						return false;
					}
					printf("\033[1;32m[+]\033[0m file \033[34;1m%s\033[0m has been added to the compiler...\n", file.path().string().c_str());
					numOfYaraFile++;

				}
			}

			if (numOfYaraFile)
			{
				printf("\033[1;32m[+]\033[0m Number of Yara files found : %d\n", numOfYaraFile);
				return true;
			}
			return false;
		}

	};



	/* inside the namespace, not the class. */

	std::vector<MEMORY_BASIC_INFORMATION> GetProcRegions(HANDLE hProcess)
	{
		std::vector<MEMORY_BASIC_INFORMATION> MemRegions;
		MEMORY_BASIC_INFORMATION MemInfo;
		LPVOID offset = 0;
		while (VirtualQueryEx(hProcess, offset, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			offset = (LPVOID)(reinterpret_cast<DWORD_PTR>(MemInfo.BaseAddress) + MemInfo.RegionSize); // update the offset to get the next regions

			// skip those regions at all :
			if (MemInfo.Protect == PAGE_NOACCESS)
				continue;

			MemRegions.push_back(MemInfo); // push the result to the vector
		}

		// check if it worked at all:
		if (MemRegions.size() == 0)
		{
			printf("\033[1;31m[-]\033[0m error: while using VirtualQueryEx. can't read\n");
			return std::vector<MEMORY_BASIC_INFORMATION>{};
		}

		// everyThing is ok
		return MemRegions;
	}


	// read memory
	std::vector<byte> ReadMemory(HANDLE hProcess, LPVOID baseAddress, DWORD sizeOfModule)
	{
		std::vector<byte> buffer(sizeOfModule);

		if (!(ReadProcessMemory(hProcess, baseAddress, buffer.data(), sizeOfModule, nullptr)) && (GetLastError() != 299))
		{
			printf("\033[1;31m[-]\033[0m error while reading the memory. error code %d\n", GetLastError());
			return std::vector<byte>{}; // return empty vector.
		}
		if (buffer.size() == 0)
			return std::vector<byte>{};

		return buffer;
	}


	// get the base address of a process
	TCHAR* GetProcName(HANDLE hProcess)
	{
		TCHAR lpImageFileName[BUFFER_SIZE];

		// get the module name :
		if (!GetModuleFileNameEx(hProcess, 0, lpImageFileName, BUFFER_SIZE))
		{
			printf("\033[1;31m[-]\033[0m error while getting the image file name. %d\n", GetLastError());
			return nullptr;
		}
		return lpImageFileName;
	}
}


int wmain(int argc, wchar_t* const* argv)
{
	if (argc == 1)
		Usage(argv[0]);

	int opt;
	bool fFlag = false;   /* for the scan of the file */
	bool pFlag = false;   /* for the scan of the process */
	bool yFlag = false;
	bool dFlag = false;
	size_t uselessVar;
	YaraNS::YaraClass yara;
	int procID;
	HANDLE hProcess;
	char* targetFile = (char*)malloc(BUFFER_SIZE);
	char* yaraFile = (char*)malloc(BUFFER_SIZE);
	char* dirPath = (char*)malloc(BUFFER_SIZE);
	std::vector<MEMORY_BASIC_INFORMATION> MemBasicInfo;

	// analyze the args
	while ((opt = getopt(argc, argv, L":f:p:y:d:h")) != -1)
	{
		switch (opt)
		{
		case 'f':
			fFlag = true;
			wcstombs_s(&uselessVar, targetFile, (size_t)BUFFER_SIZE, optarg, (size_t)BUFFER_SIZE - 1);
			break;

		case 'd':
			dFlag = true;
			wcstombs_s(&uselessVar, dirPath, (size_t)BUFFER_SIZE, optarg, (size_t)BUFFER_SIZE - 1);
			break;

		case 'p':
			pFlag = true;
			procID = _wtoi(optarg);
			break;

		case 'y':
			yFlag = true;
			wcstombs_s(&uselessVar, yaraFile, (size_t)BUFFER_SIZE, optarg, (size_t)BUFFER_SIZE - 1);
			break;

		case 'h':
			Usage(argv[0]);
			break;

		case '?':
			printf("\033[1;31m[-]\033[0m unknow arg : -%c\n", optopt);
			break;

		default:
			break;
		}
	}


	if (yFlag || dFlag)
	{
		// adding the yara file to be compiled.
		printf("\033[1;35m"); // Set text color to magenta (1;35)
		printf("**********************************************\n");
		printf("*                                            *\n");
		printf("*         STARTING THE YARA ENGINE!          *\n");
		printf("*                                            *\n");
		printf("**********************************************\n");
		printf("\033[0m"); // Reset text color

		if (yFlag)
			if ((yara.CompileRuleFile(yaraFile)) != ERROR_SUCCESS)
			{
				printf("\n\033[1;31m[-]\033[0m error while adding the yara rule file.\n");
				return -1;
			}

		if (dFlag)
			if (!(yara.IterateDir(dirPath)))
			{
				printf("\n\033[1;31m[-]\033[0m error while iterate inside the dir : %s\n", dirPath);
				return -1;
			}

		// add all rules now :
		if (!(yara.AddRuleToCompiler()))
		{
			printf("\n\033[1;31m[-]\033[0m error while adding the rules to the compiler.\n");
			return -1;
		}

		if (fFlag)
		{
			printf("\n\033[1;32m[+]\033[0m SCANNING of the file %s .\n", targetFile);
			// now scan the target file:
			if ((yara.ScanFile(targetFile)) != ERROR_SUCCESS)
				printf("\033[1;31m[-]\033[0m error while scanning the file\n");

			free(targetFile);

			if (ruleMatchedFile == 0)
				printf("\033[1;32m[+]\033[0m ************ the file is clean. ************\n");

		}
		if (pFlag)
		{
			// a try to use ReadProcessMemory() api::
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, procID);
			if (hProcess == NULL)
			{
				printf("\033[1;31m[-]\033[0m error while getting the process handle. error code %d\n", GetLastError());
				return -1;
			}

			printf("\n\033[1;32m[+]\033[0m SCANNING for the process %ls\n", YaraNS::GetProcName(hProcess));

			// read the memory
			MemBasicInfo = YaraNS::GetProcRegions(hProcess);

			printf("\n\033[1;32m[+]\033[0m Number of regions valid for reading : %I64u\n", MemBasicInfo.size());
			printf("\033[1;32m[+]\033[0m SCANNING ...\n\n");

			for (auto Inst : MemBasicInfo)
			{
				// read memory for every region
				std::vector<byte> buffer = YaraNS::ReadMemory(hProcess, Inst.BaseAddress, Inst.RegionSize);

				if (buffer.empty())
					continue;

				// now scan it:
				yara.ScanMemory(buffer, &Inst);
			}

			CloseHandle(hProcess);
			if (ruleMatchedProc == 0)
				printf("\033[1;32m[+]\033[0m ************ the process is clean. ************\n");
		}


		free(yaraFile);
		printf("\033[1;33m"); // Set text color to yellow (1;33)
		printf("*********************************************\n");
		printf("*   YARA ENGINE Console App - Version 1.0.0 *\n");
		printf("*********************************************\n");
		printf("\033[0m"); // Reset text color

		printf("\033[1;36m"); // Set text color to cyan (1;36)
		printf("*                  SUMMARY                  *\n");
		printf("* [+] Number of rules matched : %d         *\n", ruleMatchedProc + ruleMatchedFile);
		printf("\033[0m"); // Reset text color

		printf("\033[1;32m"); // Set text color to green (1;32)
		printf("*********************************************\n");
		printf("*         Have a great day! Goodbye!        *\n");
		printf("*********************************************\n");
		printf("\033[0m"); // Reset text color

	}

	else
	{
		printf("\033[32;2[-]\033[0m you should specify at least the yara rule file.\n");
		return -1;
	}

	// cleaning every thing up :


	return 0;
}



int YaraCallBack(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{

	YR_RULE* YRule = nullptr;
	YR_MODULE_IMPORT* yModule = nullptr;
	switch (message)
	{
	case CALLBACK_MSG_RULE_MATCHING:

		// increase the # of rule matched.

		YRule = (YR_RULE*)message_data;

		if (user_data != nullptr)
		{
			ruleMatchedProc++;

			PMEMORY_BASIC_INFORMATION RegInfo = (PMEMORY_BASIC_INFORMATION)user_data;


			// print the matched rules and details
			printf("\n\033[1;32m**>>\033[0m matshes for rule : %s\n", YRule->identifier);
			printf("--------------------------------------------------------\n");
			printf("| Page/Region Base address | Protection | Yara ID Found |\n");
			printf("--------------------------------------------------------\n");

			for (int i = 0; i < YRule->num_atoms; i++)
				printf("|0x%-20p ====> %-12s ====> %-15s\n", RegInfo->BaseAddress, GetMemoryProtectionString(RegInfo->Protect), YRule->strings[i].identifier);

			printf("--------------------------------------------------------\n");

		}

		else
		{
			ruleMatchedFile++;

			printf("\n\033[1;32m**>>\033[0m matshes for rule : %s, AND TAGS : %s\n", YRule->identifier, YRule->tags);

			printf("\n|ID FOUND:\n");

			// iterate for every string that matches
			for (int i = 0; i < YRule->num_atoms; i++)
				printf(" \033[1;35m\\%s\033[0m\n", YRule->strings[i].identifier);

		}

		printf("\033[36;3m<=========================================================================>\033[0m\n");
		break;

	case CALLBACK_MSG_IMPORT_MODULE:
		yModule = (YR_MODULE_IMPORT*)message_data;
		printf("\nImporting module : %s ...\n", yModule->module_name);
		break;

	case CALLBACK_MSG_MODULE_IMPORTED:
		printf("\033[1;32m[+]\033[0mSUCCESS\n");
		break;

	case CALLBACK_MSG_TOO_MANY_MATCHES:
		printf("the message is : CALLBACK_MSG_TOO_MANY_MATCHES\n");
		break;

	case CALLBACK_MSG_CONSOLE_LOG:
		printf("the message is : CALLBACK_MSG_CONSOLE_LOG\n");
		break;

	}


	return CALLBACK_CONTINUE;
}

// Function to convert memory protection constants to human-readable strings
const char* GetMemoryProtectionString(DWORD protection) {
	if (protection == 0) {
		return "No Access";
	}

	// Check for individual flags using bitwise operations
	std::string result;
	if (protection & PAGE_NOACCESS) result += "PAGE_NOACCESS | ";
	if (protection & PAGE_READONLY) result += "PAGE_READONLY | ";
	if (protection & PAGE_READWRITE) result += "PAGE_READWRITE | ";
	if (protection & PAGE_WRITECOPY) result += "PAGE_WRITECOPY | ";
	if (protection & PAGE_EXECUTE) result += "PAGE_EXECUTE | ";
	if (protection & PAGE_EXECUTE_READ) result += "PAGE_EXECUTE_READ | ";
	if (protection & PAGE_EXECUTE_READWRITE) result += "PAGE_EXECUTE_READWRITE | ";
	if (protection & PAGE_EXECUTE_WRITECOPY) result += "PAGE_EXECUTE_WRITECOPY | ";
	if (protection & PAGE_GUARD) result += "PAGE_GUARD | ";
	if (protection & PAGE_NOCACHE) result += "PAGE_NOCACHE | ";
	if (protection & PAGE_WRITECOMBINE) result += "PAGE_WRITECOMBINE | ";

	// Remove the trailing " | " if there are flags
	if (!result.empty()) {
		result.pop_back();
		result.pop_back();
	}

	return result.c_str();
}

void Usage(wchar_t* procName)
{
	printf("\n\033[0;36mUSAGE : %ls \033[0;33m[OPTION..]\nOPTIONS:\033[0m\
		 \n\t\033[0;33m-y <yaraFile>\033[0m\t specify a single YARA file to use.\
		 \n\t\033[0;33m-d DIR:      \033[0m\t specify DIR path that hold num of yara files.\
		 \n\t\033[0;33m-f FILE:     \033[0m\t specify the FILE to be scanned.\
		 \n\t\033[0;33m-p PID:      \033[0m\t specify the PID of the process to be scanned.\
		 \n\t\033[0;33m-h:          \033[0m\t print the help page.\
		 \n\n\033[0;36mAUTHORED BY:\033[0m OMAR SHEHATA\n", procName);
	exit(0);
}