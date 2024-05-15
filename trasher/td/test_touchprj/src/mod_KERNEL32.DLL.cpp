#include "touch.h"
//#!extraheaders_begin
#include <windows.h>
//#!extraheaders_end

//#!extralibs_begin
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")
//#!extralibs_end

void mod_KERNEL32() {
  //#!touchlist_begin
  TRASHER_TOUCH(GetCurrentThreadId);
  TRASHER_TOUCH(SetUnhandledExceptionFilter);
  TRASHER_TOUCH(GetCurrentProcessId);
  TRASHER_TOUCH(GetCurrentProcess);
  TRASHER_TOUCH(GetSystemTimeAsFileTime);
  TRASHER_TOUCH(QueryPerformanceCounter);
  TRASHER_TOUCH(UnhandledExceptionFilter);
  TRASHER_TOUCH(TerminateProcess);
  TRASHER_TOUCH(GetLastError);
  TRASHER_TOUCH(CloseHandle);
  TRASHER_TOUCH(GetModuleHandleW);
  TRASHER_TOUCH(GetProcAddress);
  TRASHER_TOUCH(DeleteCriticalSection);
  TRASHER_TOUCH(LeaveCriticalSection);
  TRASHER_TOUCH(EnterCriticalSection);
  TRASHER_TOUCH(Sleep);
  TRASHER_TOUCH(IsDebuggerPresent);
  TRASHER_TOUCH(FreeLibrary);
  TRASHER_TOUCH(MultiByteToWideChar);
  TRASHER_TOUCH(WideCharToMultiByte);
  TRASHER_TOUCH(SetLastError);
  TRASHER_TOUCH(IsProcessorFeaturePresent);
  TRASHER_TOUCH(GetTickCount);
  TRASHER_TOUCH(HeapFree);
  TRASHER_TOUCH(HeapAlloc);
  TRASHER_TOUCH(GetProcessHeap);
  TRASHER_TOUCH(CreateFileW);
  TRASHER_TOUCH(InitializeSListHead);
  //TRASHER_TOUCH(RtlLookupFunctionEntry); // cl
  TRASHER_TOUCH(RtlCaptureContext);
  //TRASHER_TOUCH(RtlVirtualUnwind); // cl
  TRASHER_TOUCH(GetModuleFileNameW);
  TRASHER_TOUCH(LocalFree);
  TRASHER_TOUCH(LoadLibraryExW);
  TRASHER_TOUCH(WriteFile);
  TRASHER_TOUCH(RaiseException);
  TRASHER_TOUCH(WaitForSingleObject);
  TRASHER_TOUCH(InitializeCriticalSectionAndSpinCount);
  TRASHER_TOUCH(InitializeCriticalSection);
  TRASHER_TOUCH(SetEvent);
  TRASHER_TOUCH(CreateEventW);
  TRASHER_TOUCH(FormatMessageW);
  TRASHER_TOUCH(DisableThreadLibraryCalls);
  TRASHER_TOUCH(FindClose);
  TRASHER_TOUCH(ReadFile);
  TRASHER_TOUCH(GetModuleHandleExW);
  TRASHER_TOUCH(TlsGetValue);
  TRASHER_TOUCH(HeapReAlloc);
  TRASHER_TOUCH(WaitForSingleObjectEx);
  TRASHER_TOUCH(EncodePointer);
  TRASHER_TOUCH(OutputDebugStringW);
  TRASHER_TOUCH(TlsSetValue);
  TRASHER_TOUCH(LoadLibraryW);
  TRASHER_TOUCH(TlsAlloc);
  TRASHER_TOUCH(GetStartupInfoW);
  TRASHER_TOUCH(FindNextFileW);
  TRASHER_TOUCH(GetFileType);
  TRASHER_TOUCH(TlsFree);
  TRASHER_TOUCH(ResetEvent);
  TRASHER_TOUCH(GetACP);
  TRASHER_TOUCH(GetModuleHandleA);
  TRASHER_TOUCH(GetStdHandle);
  TRASHER_TOUCH(GetFileAttributesW);
  TRASHER_TOUCH(GetModuleFileNameA);
  TRASHER_TOUCH(HeapSize);
  TRASHER_TOUCH(GetSystemInfo);
  TRASHER_TOUCH(DecodePointer);
  TRASHER_TOUCH(GetCommandLineW);
  TRASHER_TOUCH(VirtualQuery);
  TRASHER_TOUCH(FlushFileBuffers);
  TRASHER_TOUCH(GetConsoleMode);
  TRASHER_TOUCH(LoadResource);
  TRASHER_TOUCH(LCMapStringW);
  TRASHER_TOUCH(ExitProcess);
  TRASHER_TOUCH(CreateThread);
  TRASHER_TOUCH(VirtualProtect);
  TRASHER_TOUCH(VirtualAlloc);
  TRASHER_TOUCH(GetCPInfo);
  TRASHER_TOUCH(GetStringTypeW);
  TRASHER_TOUCH(UnmapViewOfFile);
  TRASHER_TOUCH(LocalAlloc);
  TRASHER_TOUCH(FindFirstFileW);
  TRASHER_TOUCH(DeleteFileW);
  TRASHER_TOUCH(GetEnvironmentStringsW);
  TRASHER_TOUCH(WriteConsoleW);
  TRASHER_TOUCH(FreeEnvironmentStringsW);
  TRASHER_TOUCH(VirtualFree);
  TRASHER_TOUCH(HeapDestroy);
  TRASHER_TOUCH(ReleaseMutex);
  TRASHER_TOUCH(SetFilePointer);
  TRASHER_TOUCH(GetFullPathNameW);
  TRASHER_TOUCH(SizeofResource);
  TRASHER_TOUCH(IsValidCodePage);
  TRASHER_TOUCH(SetStdHandle);
  TRASHER_TOUCH(OutputDebugStringA);
  TRASHER_TOUCH(GetOEMCP);
  TRASHER_TOUCH(LoadLibraryExA);
  TRASHER_TOUCH(GetCommandLineA);
  TRASHER_TOUCH(SetFilePointerEx);
  TRASHER_TOUCH(GetFileSize);
  TRASHER_TOUCH(MapViewOfFile);
  TRASHER_TOUCH(CompareStringW);
  TRASHER_TOUCH(GetEnvironmentVariableW);
  TRASHER_TOUCH(InitializeCriticalSectionEx);
  TRASHER_TOUCH(GetVersionExW);
  TRASHER_TOUCH(ReleaseSRWLockExclusive);
  TRASHER_TOUCH(AcquireSRWLockExclusive);
  TRASHER_TOUCH(LockResource);
  TRASHER_TOUCH(SetEndOfFile);
  TRASHER_TOUCH(LoadLibraryA);
  TRASHER_TOUCH(ExpandEnvironmentStringsW);
  TRASHER_TOUCH(ReleaseSemaphore);
  TRASHER_TOUCH(GetCurrentThread);
  TRASHER_TOUCH(CreateFileMappingW);
  TRASHER_TOUCH(FindResourceExW);
  TRASHER_TOUCH(DebugBreak);
  TRASHER_TOUCH(CreateDirectoryW);
  TRASHER_TOUCH(GetFileSizeEx);
  TRASHER_TOUCH(lstrcmpiW);
  TRASHER_TOUCH(CreateProcessW);
  TRASHER_TOUCH(GetConsoleOutputCP);
  TRASHER_TOUCH(CreateFileA);
  TRASHER_TOUCH(GetSystemDirectoryW);
  TRASHER_TOUCH(HeapSetInformation);
  TRASHER_TOUCH(DuplicateHandle);
  TRASHER_TOUCH(QueryPerformanceFrequency);
  TRASHER_TOUCH(GetTempPathW);
  TRASHER_TOUCH(lstrlenW);
  TRASHER_TOUCH(FindResourceW);
  TRASHER_TOUCH(GetLocaleInfoW);
  TRASHER_TOUCH(RtlUnwind);
  TRASHER_TOUCH(GetConsoleCP);
  TRASHER_TOUCH(InterlockedFlushSList);
  TRASHER_TOUCH(WaitForMultipleObjects);
  TRASHER_TOUCH(FileTimeToSystemTime);
  TRASHER_TOUCH(CreateMutexW);
  TRASHER_TOUCH(FindFirstFileExW);
  TRASHER_TOUCH(SetEnvironmentVariableW);
  //TRASHER_TOUCH(RtlUnwindEx); //cl
  TRASHER_TOUCH(FormatMessageA);
  TRASHER_TOUCH(GetCurrentDirectoryW);
  TRASHER_TOUCH(OpenProcess);
  TRASHER_TOUCH(GetFileAttributesExW);
  TRASHER_TOUCH(HeapCreate);
  TRASHER_TOUCH(SetFileAttributesW);
  TRASHER_TOUCH(SystemTimeToFileTime);
  TRASHER_TOUCH(GetExitCodeProcess);
  TRASHER_TOUCH(DeviceIoControl);
  TRASHER_TOUCH(CopyFileW);
  TRASHER_TOUCH(ReadConsoleW);
  TRASHER_TOUCH(CreateSemaphoreExW);
  TRASHER_TOUCH(GlobalAlloc);
  TRASHER_TOUCH(WakeAllConditionVariable);
  TRASHER_TOUCH(GlobalFree);
  TRASHER_TOUCH(GetUserDefaultLCID);
  TRASHER_TOUCH(ReleaseSRWLockShared);
  TRASHER_TOUCH(GetVersionExA);
  TRASHER_TOUCH(AcquireSRWLockShared);
  TRASHER_TOUCH(GetSystemTime);
  TRASHER_TOUCH(RtlPcToFileHeader);
  TRASHER_TOUCH(GetLocalTime);
  TRASHER_TOUCH(InterlockedPushEntrySList);
  TRASHER_TOUCH(GetFileInformationByHandle);
  TRASHER_TOUCH(OpenSemaphoreW);
  TRASHER_TOUCH(SleepConditionVariableSRW);
  TRASHER_TOUCH(CreateMutexExW);
  TRASHER_TOUCH(GetVersion);
  TRASHER_TOUCH(GlobalUnlock);
  TRASHER_TOUCH(SwitchToThread);
  TRASHER_TOUCH(GlobalLock);
  TRASHER_TOUCH(GetDriveTypeW);
  TRASHER_TOUCH(GetDateFormatW);
  TRASHER_TOUCH(lstrlenA);
  TRASHER_TOUCH(GetTimeFormatW);
  TRASHER_TOUCH(lstrcmpW);
  TRASHER_TOUCH(VerifyVersionInfoW);
  TRASHER_TOUCH(MoveFileExW);
  TRASHER_TOUCH(ResumeThread);
  TRASHER_TOUCH(SetErrorMode);
  TRASHER_TOUCH(CreateEventA);
  TRASHER_TOUCH(VerSetConditionMask);
  TRASHER_TOUCH(GetUserDefaultUILanguage);
  TRASHER_TOUCH(GetThreadLocale);
  TRASHER_TOUCH(RemoveDirectoryW);
  TRASHER_TOUCH(CreateFileMappingA);
  TRASHER_TOUCH(GetTickCount64);
  TRASHER_TOUCH(SetConsoleCtrlHandler);
  TRASHER_TOUCH(GetTimeZoneInformation);
  TRASHER_TOUCH(GetTempFileNameW);
  TRASHER_TOUCH(MulDiv);
  TRASHER_TOUCH(SetFileTime);
  TRASHER_TOUCH(TryEnterCriticalSection);
  TRASHER_TOUCH(SetThreadPriority);
  TRASHER_TOUCH(IsValidLocale);
  TRASHER_TOUCH(InitializeSRWLock);
  TRASHER_TOUCH(MapViewOfFileEx);
  TRASHER_TOUCH(FindNextFileA);
  TRASHER_TOUCH(FileTimeToLocalFileTime);
  TRASHER_TOUCH(SetThreadpoolTimer);
  TRASHER_TOUCH(FreeLibraryAndExitThread);
  TRASHER_TOUCH(CreateThreadpoolTimer);
  TRASHER_TOUCH(CloseThreadpoolTimer);
  TRASHER_TOUCH(ExitThread);
  TRASHER_TOUCH(IsWow64Process);
  TRASHER_TOUCH(FlsSetValue);
  TRASHER_TOUCH(WaitForThreadpoolTimerCallbacks);
  TRASHER_TOUCH(FlsAlloc);
  TRASHER_TOUCH(InterlockedPopEntrySList);
  TRASHER_TOUCH(FlsGetValue);
  TRASHER_TOUCH(EnumSystemLocalesW);
  TRASHER_TOUCH(FlsFree);
  TRASHER_TOUCH(GetWindowsDirectoryW);
  TRASHER_TOUCH(CompareStringOrdinal);
  TRASHER_TOUCH(CompareFileTime);
  TRASHER_TOUCH(GetNativeSystemInfo);
  TRASHER_TOUCH(CreateSemaphoreW);
  TRASHER_TOUCH(GetOverlappedResult);
  TRASHER_TOUCH(GetComputerNameW);
  TRASHER_TOUCH(GetFileTime);
  TRASHER_TOUCH(GetExitCodeThread);
  TRASHER_TOUCH(SearchPathW);
  TRASHER_TOUCH(SleepEx);
  TRASHER_TOUCH(OpenEventW);
  TRASHER_TOUCH(GetLocaleInfoA);
  TRASHER_TOUCH(GetFileAttributesA);
  TRASHER_TOUCH(lstrcmpiA);
  TRASHER_TOUCH(MoveFileW);
  TRASHER_TOUCH(GetEnvironmentVariableA);
  TRASHER_TOUCH(FlushInstructionCache);
  TRASHER_TOUCH(WaitForMultipleObjectsEx);
  TRASHER_TOUCH(InitOnceBeginInitialize);
  TRASHER_TOUCH(DeleteFileA);
  TRASHER_TOUCH(InitOnceComplete);
  TRASHER_TOUCH(CreateActCtxW);
  TRASHER_TOUCH(AreFileApisANSI);
  TRASHER_TOUCH(SystemTimeToTzSpecificLocalTime);
  TRASHER_TOUCH(ActivateActCtx);
  TRASHER_TOUCH(GetLongPathNameW);
  TRASHER_TOUCH(DeactivateActCtx);
  TRASHER_TOUCH(SetCurrentDirectoryW);
  TRASHER_TOUCH(SetConsoleMode);
  TRASHER_TOUCH(GetVolumeInformationW);
  TRASHER_TOUCH(GetDiskFreeSpaceExW);
  TRASHER_TOUCH(GetFinalPathNameByHandleW);
  TRASHER_TOUCH(SetThreadLocale);
  TRASHER_TOUCH(GetSystemDirectoryA);
  TRASHER_TOUCH(GetTempPathA);
  TRASHER_TOUCH(GetFullPathNameA);
  TRASHER_TOUCH(CompareStringA);
  TRASHER_TOUCH(IsDBCSLeadByte);
  TRASHER_TOUCH(InitOnceExecuteOnce);
  TRASHER_TOUCH(HeapValidate);
  TRASHER_TOUCH(PeekNamedPipe);
  TRASHER_TOUCH(GetConsoleScreenBufferInfo);
  TRASHER_TOUCH(GlobalMemoryStatusEx);
  TRASHER_TOUCH(GetPrivateProfileStringW);
  TRASHER_TOUCH(GetProcessAffinityMask);
  TRASHER_TOUCH(GetThreadPriority);
  TRASHER_TOUCH(LCMapStringEx);
  TRASHER_TOUCH(GetStartupInfoA);
  TRASHER_TOUCH(GetFileInformationByHandleEx);
  TRASHER_TOUCH(FindFirstFileExA);
  TRASHER_TOUCH(GetSystemWindowsDirectoryW);
  TRASHER_TOUCH(UnregisterWaitEx);
  TRASHER_TOUCH(GetProcessTimes);
  TRASHER_TOUCH(CreateProcessA);
  TRASHER_TOUCH(GetShortPathNameW);
  TRASHER_TOUCH(GetComputerNameExW);
  TRASHER_TOUCH(FindFirstFileA);
  TRASHER_TOUCH(RegisterWaitForSingleObject);
  TRASHER_TOUCH(SetHandleCount);
  TRASHER_TOUCH(SetEnvironmentVariableA);
  TRASHER_TOUCH(ReleaseActCtx);
  TRASHER_TOUCH(ConnectNamedPipe);
  TRASHER_TOUCH(GetProcessId);
  TRASHER_TOUCH(InitializeConditionVariable);
  TRASHER_TOUCH(CreateMutexA);
  TRASHER_TOUCH(ProcessIdToSessionId);
  TRASHER_TOUCH(GetVolumePathNameW);
  TRASHER_TOUCH(WakeConditionVariable);
  TRASHER_TOUCH(QueueUserWorkItem);
  TRASHER_TOUCH(CreateNamedPipeW);
  TRASHER_TOUCH(FlushViewOfFile);
  TRASHER_TOUCH(lstrcmpA);
  TRASHER_TOUCH(ExpandEnvironmentStringsA);
  TRASHER_TOUCH(SetNamedPipeHandleState);
  TRASHER_TOUCH(CreateTimerQueueTimer);
  TRASHER_TOUCH(SetConsoleOutputCP);
  TRASHER_TOUCH(SetConsoleTextAttribute);
  TRASHER_TOUCH(RtlCaptureStackBackTrace);
  TRASHER_TOUCH(CreateHardLinkW);
  TRASHER_TOUCH(DeleteTimerQueueTimer);
  TRASHER_TOUCH(CreatePipe);
  TRASHER_TOUCH(SetFileInformationByHandle);
  TRASHER_TOUCH(GetTempFileNameA);
  TRASHER_TOUCH(FindResourceA);
  TRASHER_TOUCH(CreateSemaphoreA);
  TRASHER_TOUCH(GetLocaleInfoEx);
  TRASHER_TOUCH(LCMapStringA);
  TRASHER_TOUCH(SuspendThread);
  TRASHER_TOUCH(LocalFileTimeToFileTime);
  TRASHER_TOUCH(TerminateThread);
  TRASHER_TOUCH(FreeResource);
  TRASHER_TOUCH(ReadProcessMemory);
  TRASHER_TOUCH(OpenFileMappingW);
  TRASHER_TOUCH(CopyFileExW);
  TRASHER_TOUCH(SetThreadAffinityMask);
  TRASHER_TOUCH(DisconnectNamedPipe);
  TRASHER_TOUCH(IsDBCSLeadByteEx);
  TRASHER_TOUCH(GetSystemDefaultLCID);
  TRASHER_TOUCH(SubmitThreadpoolWork);
  TRASHER_TOUCH(CreateThreadpoolWork);
  TRASHER_TOUCH(FreeEnvironmentStringsA);
  TRASHER_TOUCH(FindVolumeClose);
  TRASHER_TOUCH(OpenMutexW);
  TRASHER_TOUCH(SetWaitableTimer);
  TRASHER_TOUCH(CreateIoCompletionPort);
  TRASHER_TOUCH(WaitNamedPipeW);
  TRASHER_TOUCH(FindFirstVolumeW);
  TRASHER_TOUCH(FindNextVolumeW);
  TRASHER_TOUCH(GlobalSize);
  TRASHER_TOUCH(CreateEventExW);
  TRASHER_TOUCH(GetEnvironmentStrings);
  TRASHER_TOUCH(GetSystemDefaultUILanguage);
  TRASHER_TOUCH(SleepConditionVariableCS);
  TRASHER_TOUCH(GetLogicalProcessorInformation);
  TRASHER_TOUCH(OpenThread);
  TRASHER_TOUCH(GetStringTypeA);
  TRASHER_TOUCH(PostQueuedCompletionStatus);
  TRASHER_TOUCH(UnregisterWait);
  TRASHER_TOUCH(WritePrivateProfileStringW);
  TRASHER_TOUCH(CreateDirectoryA);
  TRASHER_TOUCH(CloseThreadpoolWork);
  TRASHER_TOUCH(GetDiskFreeSpaceW);
  TRASHER_TOUCH(SignalObjectAndWait);
  TRASHER_TOUCH(CompareStringEx);
  TRASHER_TOUCH(GetQueuedCompletionStatus);
  TRASHER_TOUCH(GetThreadContext);
  TRASHER_TOUCH(QueryDepthSList);
  TRASHER_TOUCH(LocalReAlloc);
  TRASHER_TOUCH(InitializeProcThreadAttributeList);
  TRASHER_TOUCH(DeleteProcThreadAttributeList);
  TRASHER_TOUCH(UpdateProcThreadAttribute);
  TRASHER_TOUCH(LockFileEx);
  TRASHER_TOUCH(GetCurrentDirectoryA);
  TRASHER_TOUCH(GetVolumeNameForVolumeMountPointW);
  TRASHER_TOUCH(GetUserDefaultLangID);
  TRASHER_TOUCH(QueryDosDeviceW);
  TRASHER_TOUCH(DosDateTimeToFileTime);
  TRASHER_TOUCH(GetSystemDefaultLangID);
  TRASHER_TOUCH(SetHandleInformation);
  TRASHER_TOUCH(GetThreadTimes);
  TRASHER_TOUCH(UnlockFileEx);
  TRASHER_TOUCH(UnlockFile);
  TRASHER_TOUCH(CreateTimerQueue);
  TRASHER_TOUCH(GetStringTypeExW);
  TRASHER_TOUCH(lstrcpynW);
  TRASHER_TOUCH(LockFile);
  TRASHER_TOUCH(SetThreadExecutionState);
  TRASHER_TOUCH(GetProductInfo);
  TRASHER_TOUCH(WriteConsoleA);
  TRASHER_TOUCH(CancelIoEx);
  TRASHER_TOUCH(CreateSymbolicLinkW);
  TRASHER_TOUCH(QueryActCtxW);
  TRASHER_TOUCH(GetPrivateProfileIntW);
  TRASHER_TOUCH(GlobalReAlloc);
  TRASHER_TOUCH(ReadConsoleA);
  TRASHER_TOUCH(lstrcpyW);
  TRASHER_TOUCH(GetHandleInformation);
  TRASHER_TOUCH(GetModuleHandleExA);
  TRASHER_TOUCH(ChangeTimerQueueTimer);
  TRASHER_TOUCH(CreateRemoteThread);
  TRASHER_TOUCH(AssignProcessToJobObject);
  TRASHER_TOUCH(CancelIo);
  TRASHER_TOUCH(SetThreadUILanguage);
  TRASHER_TOUCH(SetDllDirectoryW);
  TRASHER_TOUCH(GlobalHandle);
  TRASHER_TOUCH(RaiseFailFastException);
  TRASHER_TOUCH(GetNumberOfConsoleInputEvents);
  TRASHER_TOUCH(GetDriveTypeA);
  TRASHER_TOUCH(GetDiskFreeSpaceA);
  TRASHER_TOUCH(GlobalMemoryStatus);
  TRASHER_TOUCH(QueryFullProcessImageNameW);
  TRASHER_TOUCH(ReadDirectoryChangesW);
  TRASHER_TOUCH(GetLogicalDrives);
  TRASHER_TOUCH(GetWindowsDirectoryA);
  TRASHER_TOUCH(GetNumaHighestNodeNumber);
  //TRASHER_TOUCH(__C_specific_handler); //cl
  TRASHER_TOUCH(WriteProcessMemory);
  TRASHER_TOUCH(TryAcquireSRWLockExclusive);
  TRASHER_TOUCH(SetThreadContext);
  TRASHER_TOUCH(PeekConsoleInputA);
  TRASHER_TOUCH(OpenEventA);
  TRASHER_TOUCH(SetThreadStackGuarantee);
  TRASHER_TOUCH(FindActCtxSectionStringW);
  TRASHER_TOUCH(RemoveDirectoryA);
  TRASHER_TOUCH(SetInformationJobObject);
  TRASHER_TOUCH(WTSGetActiveConsoleSessionId);
  TRASHER_TOUCH(GetVolumePathNamesForVolumeNameW);
  TRASHER_TOUCH(MoveFileA);
  TRASHER_TOUCH(FreeConsole);
  TRASHER_TOUCH(SetPriorityClass);
  TRASHER_TOUCH(GetShortPathNameA);
  TRASHER_TOUCH(GlobalDeleteAtom);
  TRASHER_TOUCH(GetPrivateProfileStringA);
  TRASHER_TOUCH(HeapCompact);
  TRASHER_TOUCH(VirtualQueryEx);
  TRASHER_TOUCH(GetPrivateProfileSectionW);
  TRASHER_TOUCH(CreateWaitableTimerW);
  TRASHER_TOUCH(QueueUserAPC);
  TRASHER_TOUCH(RegisterApplicationRestart);
  TRASHER_TOUCH(WaitForThreadpoolWorkCallbacks);
  TRASHER_TOUCH(SetThreadpoolWait);
  TRASHER_TOUCH(CloseThreadpoolWait);
  TRASHER_TOUCH(CreateThreadpoolWait);
  TRASHER_TOUCH(VirtualAllocEx);
  TRASHER_TOUCH(HeapQueryInformation);
  TRASHER_TOUCH(GetDateFormatA);
  TRASHER_TOUCH(IsBadReadPtr);
  TRASHER_TOUCH(GetLogicalDriveStringsW);
  TRASHER_TOUCH(SetProcessAffinityMask);
  TRASHER_TOUCH(SetFileAttributesA);
  TRASHER_TOUCH(GetTimeFormatA);
  TRASHER_TOUCH(LocaleNameToLCID);
  TRASHER_TOUCH(LCIDToLocaleName);
  TRASHER_TOUCH(FillConsoleOutputCharacterA);
  TRASHER_TOUCH(CopyFileA);
  TRASHER_TOUCH(QueryInformationJobObject);
  TRASHER_TOUCH(FindAtomW);
  TRASHER_TOUCH(GlobalAddAtomW);
  TRASHER_TOUCH(EnumSystemLocalesA);
  TRASHER_TOUCH(FileTimeToDosDateTime);
  TRASHER_TOUCH(Wow64RevertWow64FsRedirection);
  TRASHER_TOUCH(LocalLock);
  TRASHER_TOUCH(OpenFileMappingA);
  TRASHER_TOUCH(LocalUnlock);
  TRASHER_TOUCH(SetCurrentDirectoryA);
  TRASHER_TOUCH(SearchPathA);
  TRASHER_TOUCH(ReplaceFileW);
  TRASHER_TOUCH(GetComputerNameA);
  TRASHER_TOUCH(GetProcessMitigationPolicy);
  TRASHER_TOUCH(Wow64DisableWow64FsRedirection);
  TRASHER_TOUCH(GetThreadId);
  TRASHER_TOUCH(SetThreadPreferredUILanguages);
  TRASHER_TOUCH(GenerateConsoleCtrlEvent);
  TRASHER_TOUCH(GetCurrentProcessorNumber);
  TRASHER_TOUCH(GetConsoleWindow);
  TRASHER_TOUCH(GetUserGeoID);
  TRASHER_TOUCH(HeapWalk);
  TRASHER_TOUCH(IsBadWritePtr);
  TRASHER_TOUCH(GetSystemWow64DirectoryW);
  TRASHER_TOUCH(VirtualProtectEx);
  TRASHER_TOUCH(TzSpecificLocalTimeToSystemTime);
  TRASHER_TOUCH(GetNumberFormatW);
  TRASHER_TOUCH(GetDateFormatEx);
  TRASHER_TOUCH(CreateWaitableTimerA);
  TRASHER_TOUCH(AddVectoredExceptionHandler);
  TRASHER_TOUCH(GetTimeFormatEx);
  TRASHER_TOUCH(VerifyVersionInfoA);
  TRASHER_TOUCH(CreateJobObjectW);
  //TRASHER_TOUCH(RtlAddFunctionTable); //cl
  TRASHER_TOUCH(GetPrivateProfileIntA);
  TRASHER_TOUCH(EnumResourceLanguagesW);
  TRASHER_TOUCH(DeleteFiber);
  TRASHER_TOUCH(GetVolumeInformationA);
  TRASHER_TOUCH(QueryThreadCycleTime);
  TRASHER_TOUCH(AllocConsole);
  TRASHER_TOUCH(VirtualUnlock);
  TRASHER_TOUCH(GetUserDefaultLocaleName);
  TRASHER_TOUCH(GetSystemPowerStatus);
  TRASHER_TOUCH(FindResourceExA);
  TRASHER_TOUCH(VirtualLock);
  TRASHER_TOUCH(GetFileAttributesExA);
  TRASHER_TOUCH(ReadConsoleInputW);
  TRASHER_TOUCH(SwitchToFiber);
  TRASHER_TOUCH(CreateJobObjectA);
  TRASHER_TOUCH(CloseThreadpool);
  TRASHER_TOUCH(CreateThreadpool);
  TRASHER_TOUCH(LocalSize);
  TRASHER_TOUCH(ConvertDefaultLocale);
  TRASHER_TOUCH(GetStringTypeExA);
  TRASHER_TOUCH(FlushProcessWriteBuffers);
  TRASHER_TOUCH(GlobalFlags);
  TRASHER_TOUCH(SetProcessShutdownParameters);
  TRASHER_TOUCH(CreateThreadpoolCleanupGroup);
  TRASHER_TOUCH(GetUserPreferredUILanguages);
  TRASHER_TOUCH(GetProfileIntA);
  TRASHER_TOUCH(FreeLibraryWhenCallbackReturns);
  TRASHER_TOUCH(CloseThreadpoolCleanupGroupMembers);
  TRASHER_TOUCH(CreateNamedPipeA);
  TRASHER_TOUCH(ConvertThreadToFiber);
  TRASHER_TOUCH(CancelWaitableTimer);
  TRASHER_TOUCH(WaitNamedPipeA);
  TRASHER_TOUCH(OpenMutexA);
  TRASHER_TOUCH(Beep);
  TRASHER_TOUCH(EnumResourceNamesW);
  TRASHER_TOUCH(GetSystemFirmwareTable);
  TRASHER_TOUCH(WritePrivateProfileStringA);
  TRASHER_TOUCH(GlobalFindAtomW);
  TRASHER_TOUCH(AddAtomW);
  TRASHER_TOUCH(SetThreadpoolThreadMaximum);
  TRASHER_TOUCH(WaitForThreadpoolWaitCallbacks);
  TRASHER_TOUCH(lstrcpyA);
  TRASHER_TOUCH(VirtualFreeEx);
  TRASHER_TOUCH(GetThreadPreferredUILanguages);
  TRASHER_TOUCH(CreateFiber);
  TRASHER_TOUCH(FindStringOrdinal);
  TRASHER_TOUCH(GetDllDirectoryW);
  TRASHER_TOUCH(SetProcessWorkingSetSize);
  TRASHER_TOUCH(ConvertFiberToThread);
  TRASHER_TOUCH(GetPriorityClass);
  TRASHER_TOUCH(CloseThreadpoolCleanupGroup);
  TRASHER_TOUCH(FatalExit);
  TRASHER_TOUCH(CancelSynchronousIo);
  TRASHER_TOUCH(TransactNamedPipe);
  TRASHER_TOUCH(IsBadCodePtr);
  TRASHER_TOUCH(lstrcatW);
  TRASHER_TOUCH(SetThreadpoolThreadMinimum);
  TRASHER_TOUCH(SetConsoleCursorPosition);
  TRASHER_TOUCH(DeleteTimerQueueEx);
  TRASHER_TOUCH(ReadConsoleInputA);
  TRASHER_TOUCH(TryAcquireSRWLockShared);
  TRASHER_TOUCH(GetSystemTimeAdjustment);
  TRASHER_TOUCH(MoveFileExA);
  TRASHER_TOUCH(ResolveLocaleName);
  TRASHER_TOUCH(EnumUILanguagesW);
  TRASHER_TOUCH(RegCloseKey);
  TRASHER_TOUCH(SetThreadErrorMode);
  TRASHER_TOUCH(GetGeoInfoW);
  TRASHER_TOUCH(ReadFileEx);
  TRASHER_TOUCH(CreateWaitableTimerExW);
  TRASHER_TOUCH(GetProfileIntW);
  TRASHER_TOUCH(FindFirstChangeNotificationW);
  TRASHER_TOUCH(HeapLock);
  TRASHER_TOUCH(HeapUnlock);
  TRASHER_TOUCH(RegQueryValueExW);
  TRASHER_TOUCH(FindCloseChangeNotification);
  TRASHER_TOUCH(DeleteAtom);
  TRASHER_TOUCH(GetVolumeInformationByHandleW);
  TRASHER_TOUCH(RegOpenKeyExW);
  TRASHER_TOUCH(GlobalGetAtomNameW);
  TRASHER_TOUCH(IsProcessInJob);
  TRASHER_TOUCH(_lclose);
  TRASHER_TOUCH(SetConsoleTitleW);
  TRASHER_TOUCH(GetErrorMode);
  TRASHER_TOUCH(GetBinaryTypeW);
  TRASHER_TOUCH(DeleteVolumeMountPointW);
  TRASHER_TOUCH(RemoveVectoredExceptionHandler);
  TRASHER_TOUCH(lstrcpynA);
  TRASHER_TOUCH(WaitForDebugEvent);
  TRASHER_TOUCH(GetCompressedFileSizeW);
  TRASHER_TOUCH(ContinueDebugEvent);
  TRASHER_TOUCH(FatalAppExitA);
  TRASHER_TOUCH(InitOnceInitialize);
  TRASHER_TOUCH(GetSystemTimes);
  TRASHER_TOUCH(TrySubmitThreadpoolCallback);
  TRASHER_TOUCH(PowerCreateRequest);
  TRASHER_TOUCH(BeginUpdateResourceW);
  TRASHER_TOUCH(FindNextChangeNotification);
  TRASHER_TOUCH(_llseek);
  TRASHER_TOUCH(UpdateResourceW);
  TRASHER_TOUCH(_lread);
  TRASHER_TOUCH(RegCreateKeyExW);
  TRASHER_TOUCH(WriteFileEx);
  TRASHER_TOUCH(GlobalAddAtomA);
  TRASHER_TOUCH(GetProfileStringW);
  TRASHER_TOUCH(GetQueuedCompletionStatusEx);
  TRASHER_TOUCH(WinExec);
  TRASHER_TOUCH(GetAtomNameW);
  TRASHER_TOUCH(PowerSetRequest);
  TRASHER_TOUCH(_lwrite);
  TRASHER_TOUCH(SetThreadIdealProcessor);
  TRASHER_TOUCH(OpenSemaphoreA);
  TRASHER_TOUCH(DebugActiveProcess);
  TRASHER_TOUCH(FillConsoleOutputAttribute);
  TRASHER_TOUCH(GetNamedPipeClientProcessId);
  TRASHER_TOUCH(GetThreadUILanguage);
  TRASHER_TOUCH(CreateDirectoryExW);
  TRASHER_TOUCH(SetLocalTime);
  TRASHER_TOUCH(RegSetValueExW);
  TRASHER_TOUCH(OpenFileById);
  TRASHER_TOUCH(CheckRemoteDebuggerPresent);
  TRASHER_TOUCH(AttachConsole);
  TRASHER_TOUCH(GetDynamicTimeZoneInformation);
  TRASHER_TOUCH(OpenFile);
  TRASHER_TOUCH(WritePrivateProfileSectionW);
  TRASHER_TOUCH(FoldStringW);
  TRASHER_TOUCH(GetCommState);
  TRASHER_TOUCH(GetNumberFormatA);
  TRASHER_TOUCH(PulseEvent);
  TRASHER_TOUCH(PowerClearRequest);
  TRASHER_TOUCH(GetConsoleCursorInfo);
  TRASHER_TOUCH(PurgeComm);
  TRASHER_TOUCH(SetCommTimeouts);
  TRASHER_TOUCH(ClearCommError);
  TRASHER_TOUCH(RegGetValueW);
  //TRASHER_TOUCH(RtlCompareMemory);
  TRASHER_TOUCH(EndUpdateResourceW);
  TRASHER_TOUCH(EscapeCommFunction);
  TRASHER_TOUCH(SetConsoleCursorInfo);
  TRASHER_TOUCH(SetConsoleScreenBufferSize);
  TRASHER_TOUCH(FlushConsoleInputBuffer);
  TRASHER_TOUCH(GetSystemTimePreciseAsFileTime);
  TRASHER_TOUCH(SetThreadGroupAffinity);
  TRASHER_TOUCH(GetSystemPreferredUILanguages);
  TRASHER_TOUCH(SetProcessMitigationPolicy);
  TRASHER_TOUCH(FindFirstFileNameW);
  TRASHER_TOUCH(ResetWriteWatch);
  TRASHER_TOUCH(GetWriteWatch);
  TRASHER_TOUCH(GetLogicalProcessorInformationEx);
  TRASHER_TOUCH(RegDeleteValueW);
  TRASHER_TOUCH(SetCommState);
  TRASHER_TOUCH(GetActiveProcessorCount);
  TRASHER_TOUCH(SetVolumeMountPointW);
  TRASHER_TOUCH(CreateFile2);
  TRASHER_TOUCH(EnumSystemLocalesEx);
  TRASHER_TOUCH(FindNLSStringEx);
  TRASHER_TOUCH(IsBadStringPtrA);
  TRASHER_TOUCH(GetProfileStringA);
  TRASHER_TOUCH(FillConsoleOutputCharacterW);
  TRASHER_TOUCH(GetProcessHandleCount);
  TRASHER_TOUCH(TerminateJobObject);
  TRASHER_TOUCH(GetConsoleTitleW);
  TRASHER_TOUCH(WriteProfileStringW);
  TRASHER_TOUCH(SetConsoleWindowInfo);
  TRASHER_TOUCH(GlobalGetAtomNameA);
  TRASHER_TOUCH(CallbackMayRunLong);
  TRASHER_TOUCH(GetNamedPipeInfo);
  TRASHER_TOUCH(GetPrivateProfileSectionNamesW);
  TRASHER_TOUCH(StartThreadpoolIo);
  TRASHER_TOUCH(CancelThreadpoolIo);
  TRASHER_TOUCH(RegOpenKeyExA);
  //TRASHER_TOUCH(RtlDeleteFunctionTable); //cl
  TRASHER_TOUCH(DefineDosDeviceW);
  TRASHER_TOUCH(GlobalFindAtomA);
  TRASHER_TOUCH(GetNumberFormatEx);
  TRASHER_TOUCH(GetProcessIoCounters);
  TRASHER_TOUCH(IsValidLocaleName);
  TRASHER_TOUCH(CreateMemoryResourceNotification);
  TRASHER_TOUCH(CreateThreadpoolIo);
  TRASHER_TOUCH(GetSystemDefaultLocaleName);
  TRASHER_TOUCH(EnumCalendarInfoW);
  TRASHER_TOUCH(ReOpenFile);
  TRASHER_TOUCH(RegEnumValueW);
  TRASHER_TOUCH(SetProcessPriorityBoost);
  TRASHER_TOUCH(GetCommModemStatus);
  TRASHER_TOUCH(GetCurrentProcessorNumberEx);
  TRASHER_TOUCH(SetFileCompletionNotificationModes);
  TRASHER_TOUCH(EnumResourceLanguagesA);
  TRASHER_TOUCH(RegEnumKeyExW);
  TRASHER_TOUCH(WriteConsoleInputW);
  TRASHER_TOUCH(WriteProfileStringA);
  TRASHER_TOUCH(GetThreadGroupAffinity);
  TRASHER_TOUCH(lstrcatA);
  TRASHER_TOUCH(GetProcessHeaps);
  TRASHER_TOUCH(GetPrivateProfileSectionA);
  TRASHER_TOUCH(GetCurrencyFormatW);
  TRASHER_TOUCH(GetDiskFreeSpaceExA);
  TRASHER_TOUCH(GetAtomNameA);
  TRASHER_TOUCH(GetSystemWindowsDirectoryA);
  TRASHER_TOUCH(OpenJobObjectW);
  TRASHER_TOUCH(SetCommMask);
  TRASHER_TOUCH(GetNamedPipeHandleStateA);
  TRASHER_TOUCH(_lopen);
  TRASHER_TOUCH(FindVolumeMountPointClose);
  TRASHER_TOUCH(FindNextVolumeMountPointW);
  TRASHER_TOUCH(FindFirstVolumeMountPointW);
  TRASHER_TOUCH(RegQueryValueExA);
  //#!touchlist_end

}

