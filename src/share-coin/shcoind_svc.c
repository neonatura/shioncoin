
/*
 * @copyright
 *
 *  Copyright 2017 Neo Natura
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#pragma	warning (disable: 4001 4201 4214 )
#include <windows.h>

#include <pthread.h>

#include <signal.h>

#include "shcoind_svc.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#pragma comment(linker, "/subsystem:console")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

//
// User-supplied functions
//
int SRV_MAIN_FUNCTION(int argc, char **argv, char **envp);
#if defined(SRV_USAGE_FUNCTION)
void SRV_USAGE_FUNCTION(void);
#endif
#if defined(SRV_CLEANUP_FUNCTION)
void SRV_CLEANUP_FUNCTION(void);
#endif

static int SrvInstallService(void);
static int SrvRemoveService(void);
static void SrvDebugService(int argc, char **argv, char **envp);

static void SrvMain(DWORD dwArgc, LPTSTR *lpszArgv);
static void WINAPI SrvCtrl(DWORD dwCtrlCode);
static void SrvPrepMain(void);
static void SrvStop(void);
static BOOL WINAPI SrvConCtrlHdlr(DWORD dwCtrlType);
static BOOL SrvReportToSCMgr(DWORD dwCurrentState, DWORD dwWin32ExitCode,
		DWORD dwWaitHint);
static LPSTR SrvGetLastErrorText(LPSTR lpszBuf, DWORD dwSize);

static void SrvUsage(void);
static BOOL SrvUnsecureProcess(void);
static void SrvMessage(const char *fmt, ...);
static void change_core_directory(void);

static BOOL			bService = TRUE;
static BOOL			bQuiet = FALSE;
static BOOL			bVerbose = FALSE;
static BOOL			bUseCommandLineArgs = FALSE;
static pid_t			ServicePid = 0;

static SERVICE_STATUS		ssStatus;
static SERVICE_STATUS_HANDLE	sshStatusHandle;
static DWORD			dwSrvState = SERVICE_START_PENDING;

static char			SrvProgName[PATH_MAX];
static int			SrvArgc;
static char			**SrvArgv;
static char			**SrvEnvp;
static pthread_t		SrvThread;
static pthread_mutex_t		SrvNotifyMutex = PTHREAD_MUTEX_INITIALIZER;

static SERVICE_TABLE_ENTRY	dispatchTable[] =
{
	{ SRV_NAME, (LPSERVICE_MAIN_FUNCTION)SrvMain },
	{ NULL, NULL }
};

//
// For WinNT service registration
//
#define SRV_DESC_DLL		"ADVAPI32.DLL"
#define SRV_DESC_SYM		"ChangeServiceConfig2A"
typedef WINADVAPI BOOL		(WINAPI *ChgSrvCfg2_t)(SC_HANDLE hService,
		DWORD dwInfOLevel,
		LPVOID lpInfo);

//
// For Win95 service registration
//
typedef DWORD			(*rsp_func)(DWORD, DWORD);
#define RSP_FUNC		"RegisterServiceProcess"
#ifndef RSP_SIMPLE_SERVICE
# define RSP_SIMPLE_SERVICE	0x00000001
# define RSP_UNREGISTER_SERVICE	0x00000000
#endif




/*
 *	Service main function. Does some basic argument processing, to handle
 *	install/uninstall & debug mode.  Then starts the service, by connecting
 *	with the Service Control Manager on Windows.
 */
int main(int argc, char **argv, char **envp)
{
	int	args = 0;
	BOOL	bDone = FALSE;
	BOOL	bInstall = FALSE;
	BOOL	bRemove = FALSE;
	BOOL	bDebug = FALSE;
	BOOL	bUsage = FALSE;
	int	ii;
	char	*p;

	// Let us initialize the service process id which 
	// will be used to distinguish us from our children.
	ServicePid = getpid();

	// Save the program name
	p = strrchr(argv[0], '/');
	if (p == NULL)
	{
		p = strrchr(argv[0], '\\');
	}
	if (p == NULL)
	{
		strcpy(SrvProgName, argv[0]);
	}
	else
	{
		strcpy(SrvProgName, p+1);
	}


	// remove 'NT' security
	SrvUnsecureProcess();

	// Parse argument list for our arguments.
	ii = 1;
	while (!bDone)
	{
		if (ii >= argc)
		{
			bDone = TRUE;
		}
		else if ((argv[ii][0] == '-') || (argv[ii][0] == '/'))
		{
			if (strcasecmp("install", &argv[ii][1]) == 0 ||
			strcasecmp("-install", &argv[ii][1]) == 0)
			{
				args++;
				bInstall = TRUE;
			}
			else if (strcasecmp("remove", &argv[ii][1]) == 0 ||
			strcasecmp("-remove", &argv[ii][1]) == 0)
			{
				args++;
				bRemove = TRUE;
			}
      else if (strcasecmp("debug", &argv[ii][1]) == 0 ||
          strcasecmp("-debug", &argv[ii][1]) == 0 ||
          strcasecmp("nf", &argv[ii][1]) == 0 ||
          strcasecmp("-no-fork", &argv[ii][1]) == 0)
			{
				args++;
				bDebug = TRUE;
			}
			else if (
					(strcasecmp("help", &argv[ii][1]) == 0) ||
					(strcasecmp("-help", &argv[ii][1]) == 0) ||
					(strcasecmp("usage", &argv[ii][1]) == 0) ||
					(strcasecmp("-usage", &argv[ii][1]) == 0) ||
					(strcasecmp("h", &argv[ii][1]) == 0) ||
					(strcasecmp("?", &argv[ii][1]) == 0))
			{
				args++;
				bUsage = TRUE;
			}
			else
			{
				bDone = TRUE;
			}
		}
		else
		{
			bDone = TRUE;
		}
		ii++;
	}

	// Adjust argv for arguments we've handled.
	if (args > 0) {
		bUseCommandLineArgs = TRUE;
		argc -= args;
		for (ii = 1; ii < argc; ii++)
		{
			argv[ii] = argv[ii+args];
		}
	} else {
		args = argc;
	} 

	// Handle arguments
	if (bUsage)
	{
		SrvUsage();
	}
	else if (bInstall)
	{
		exit(SrvInstallService());
	}
	else if (bRemove)
	{
		exit(SrvRemoveService());
	}
	else if (bDebug)
	{
    change_core_directory();
		SrvDebugService(argc, argv, envp);
		exit(0);
	}

	// Now run the service.  For Win95, we register as a service and
	// then run the service directly.  For WinNT, we connect to the
	// Service Control Manager and let it spin up the service thread.
	{
		sigset_t	set;
		sigset_t	old_mask;

		//
		// Block all signals in this thread
		//
		sigfillset(&set);
		pthread_sigmask(SIG_BLOCK, &set, &old_mask);

		//
		// Save the user arguments
		//
		SrvArgc = args;
		SrvArgv = argv;
		SrvEnvp = envp;

		//
		// Now have the SCM spin up the actual user thread
		//
		if (!StartServiceCtrlDispatcher(dispatchTable))
		{
			switch (GetLastError())
			{
				case ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
				case ERROR_CALL_NOT_IMPLEMENTED:
					bUseCommandLineArgs = TRUE;
					pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
          change_core_directory();
					SrvDebugService(args, argv, envp);
					break;
				default:
					break;
			}
		}
		else
		{
			pthread_exit(0);
		}
	}

	return 0;
}

/**
 * This is the actual service main function for Windows NT.  This thread
 *	is created to perform the service work, while the main thread remains
 *	in communication with the Service Control Manager
 */
static void SrvMain(
		DWORD	dwArgc,
		LPTSTR	*lpszArgv)
{

	// If we are actually running as a service, we need to tell the
	// Service Control Manager that we're running.
	if (bService)
	{
		//
		// Register our service control handler:
		//
		sshStatusHandle = RegisterServiceCtrlHandler(SRV_NAME, SrvCtrl);
		if (!sshStatusHandle)
		{
			goto cleanup;
		}

		//
		// Report the status to Service Control Manager.
		//
		if (!SrvReportToSCMgr(
					SERVICE_START_PENDING,	// service state
					NO_ERROR,		// exit code
					0))			// wait hint
		{
			goto cleanup;
		}
		if (!SrvReportToSCMgr(
					SERVICE_RUNNING,	// service state
					NO_ERROR,		// exit code
					0))			// wait hint
		{
			goto cleanup;
		}
	}

	// Prepare to call the user's main function
	SrvPrepMain();

	change_core_directory();

	// Now invoke the actual service function
	if (bUseCommandLineArgs == TRUE) {
		SRV_MAIN_FUNCTION(SrvArgc, SrvArgv, SrvEnvp);
	} else {
		SRV_MAIN_FUNCTION(dwArgc, lpszArgv, SrvEnvp);
	}

cleanup:
	// Try to report the stopped status to the service control manager.
	// Do it only if we are the actual process running as a service.

	if(ServicePid == getpid())
	{
		if (sshStatusHandle != 0)
		{
			SrvReportToSCMgr(
					SERVICE_STOPPED,
					GetLastError(),
					0);
		}
	}
	else
	{
		//
		// We must have been a child of the service process.
		// Let us exit from here, as returning from here will
		// not exit us.
		//
		exit(0);
	}

	return;
}

//	This function is invoked by the Service Control Manager when it needs
//	to communicate with the service.
static void WINAPI SrvCtrl(
		DWORD	dwCtrlCode)
{
	//
	// Handle the requested control code.
	//
	switch (dwCtrlCode)
	{
		//
		// Stop the service.
		//
		case SERVICE_CONTROL_SHUTDOWN:
		case SERVICE_CONTROL_STOP:
			dwSrvState = SERVICE_STOP_PENDING;
			SrvReportToSCMgr(
					dwSrvState,	// current state
					NO_ERROR,	// exit code
					5000);		// waithint

			//
			// Now actually stop the service.
			//
			SrvStop();
			return;

			//
			// Update the service status.
			//
		case SERVICE_CONTROL_INTERROGATE:
			break;

			//
			// Invalid control code
			//
		default:
			break;
	}

	//
	// Send a status response.
	//
	SrvReportToSCMgr(dwSrvState, NO_ERROR, 0);
}

//	Print a usage mesage.  Since the service is a Windows-subsystem
//	program, we need to attach a console to it in which the message
//	can be displayed.
static void SrvUsage(void)
{
	char	buf[3];

#if 0
	//
	// Connect the console
	//
	freopen("/dev/tty", "wt", stdout);
	freopen("/dev/tty", "wt", stderr);
	freopen("/dev/tty", "rt", stdin);
#endif

#if 0
	printf("%s --install	Install the service\n", SrvProgName);
	printf("%s --remove	Remove the service\n", SrvProgName);
	printf("%s --debug 	Run as a command-line app\n", SrvProgName);
#endif

#if defined(SRV_USAGE_FUNCTION)
	printf("\n");
	SRV_USAGE_FUNCTION();
#endif

	//
	// Now we need to block for input, so the console doesn't go 'blip'
	//
//	printf("\nPress <Enter> to continue:"); fgets(buf, 2, stdin);

	exit(0);
}

//
//  SrvUnsecureProcess() --
//	This function removes security from the current process, so the
//	service, which is running as System, can be accessed.
//
//	This function is not used on Windows 95.
//
static BOOL SrvUnsecureProcess(void)
{
	SECURITY_DESCRIPTOR	security;

	if (!InitializeSecurityDescriptor(
				&security,
				SECURITY_DESCRIPTOR_REVISION))
	{
		return FALSE;
	}

	if (!SetSecurityDescriptorDacl(
				&security,
				TRUE,	/* replace security */
				NULL,	/* security removed */
				FALSE))	/* not defaulted */
	{
		return FALSE;
	}

	if (!SetKernelObjectSecurity(
				GetCurrentProcess(),
				DACL_SECURITY_INFORMATION,
				&security))
	{
		return FALSE;
	}

	return TRUE;
}

//  SrvReportToSCMgr() --
//	This function is used to report status to the Service Control Manager
//	during startup and shutdown.
//
//	This function is not used on Windows 95.
static BOOL SrvReportToSCMgr(
		DWORD		dwCurrentState,
		DWORD		dwWin32ExitCode,
		DWORD		dwWaitHint)
{
	sigset_t	set;
	sigset_t	oset;
	BOOL		bResult;
	static DWORD	dwCheckPoint = 1;

	//
	// Block signals while we are in here
	//
	sigfillset(&set);
	pthread_sigmask(SIG_BLOCK, &set, &oset);


	//
	// Don't let anyone else in
	//
	pthread_mutex_lock(&SrvNotifyMutex);
	if (dwSrvState == SERVICE_STOPPED)
	{
		//
		// If we've said we're done, just bail
		//
		pthread_mutex_unlock(&SrvNotifyMutex);
		pthread_sigmask(SIG_SETMASK, &oset, NULL);
		return TRUE;
	}

	//
	// Disable control requests until the service is started.
	//
	if (dwCurrentState == SERVICE_START_PENDING)
	{
		ssStatus.dwControlsAccepted = 0;
	}
	else
	{
		ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	}

	//
	// These SERVICE_STATUS members are set from parameters.
	//
	ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ssStatus.dwServiceSpecificExitCode = 0;
	ssStatus.dwCurrentState = dwCurrentState;
	ssStatus.dwWin32ExitCode = dwWin32ExitCode;
	if ((dwCurrentState == SERVICE_RUNNING) ||
			(dwCurrentState == SERVICE_STOPPED))
	{
		ssStatus.dwCheckPoint = 0;
	}
	else
	{
		ssStatus.dwCheckPoint = dwCheckPoint++;
	}
	ssStatus.dwWaitHint = dwWaitHint;

	//
	// Report the status of the service to the service control manager.
	//
	if (!(bResult = SetServiceStatus(
					sshStatusHandle,	// service reference handle
					&ssStatus)))		// SERVICE_STATUS structure
	{
		//
		// If an error occurs, stop the service.
		//
		SrvStop();
	}
	else
	{
		dwSrvState = dwCurrentState;
	}

	pthread_mutex_unlock(&SrvNotifyMutex);
	pthread_sigmask(SIG_SETMASK, &oset, NULL);
	return bResult;
}


//	This function is used to display a message to the user.  In quiet
//	mode, the message is written to stdout, which goes nowhere with a
//	windows-subsystem app, unless the user redirects output.  If we're
//	not in quiet mode, we pop up a message box.
#define MSG_BUF	4096
static void SrvMessage(
		const char	*fmt,
		...)
{
	va_list		args;
	char		buf[MSG_BUF];

	va_start(args, fmt);
	vsprintf(buf, fmt, args);
	va_end(args);

	if (bQuiet)
	{
		printf("%s\n", buf);
	}
	else
	{
		HWND	hWnd;

		hWnd = GetActiveWindow();
		if (hWnd == NULL)
		{
			hWnd = GetFocus();
		}
		if (hWnd == NULL)
		{
			hWnd = GetDesktopWindow();
		}
		if (hWnd != NULL)
		{
			MessageBox(hWnd, buf, SRV_DISPLAY_NAME,
					(MB_ICONINFORMATION |
					 MB_SETFOREGROUND |
					 MB_OK));
		}
		else
		{
			printf("%s\n", buf);
		}
	}
}

//	On Windows NT, registers the service with the Service Control Manager.
static int SrvInstallService(void)
{
	SC_HANDLE	schService;
	SC_HANDLE	schSCManager;
	char		szPath[PATH_MAX];
	char		szErr[PATH_MAX];
	char		szDepend[640];
	HKEY		hKey;
	int		ret = 0;

	memset(szDepend, 0, sizeof(szDepend));
#ifdef SRV_DEPENDENCIES
	memcpy(szDepend, SRV_DEPENDENCIES, sizeof(SRV_DEPENDENCIES));
#endif

	//
	// Get the name of this executable, so we can install ourselves.
	//
	if (GetModuleFileName(NULL, szPath, PATH_MAX) == 0)
	{
		SrvMessage("Unable to install %s - %s",
				SRV_DISPLAY_NAME,
				SrvGetLastErrorText(szErr, PATH_MAX));
		return 1;
	}


	//
	// Connect to the Service Control Manager, then create the service
	//
	schSCManager = OpenSCManager(
			NULL,			// machine (NULL == local)
			NULL,			// database (NULL == default)
			SC_MANAGER_ALL_ACCESS	// access required
			);
	if (schSCManager == NULL)
	{
		SrvMessage("OpenSCManager failed - %s",
				SrvGetLastErrorText(szErr,PATH_MAX));
		return 1;
	}

	schService = CreateService(
			schSCManager,			// SCManager database
			SRV_NAME,			// name of service
			SRV_DISPLAY_NAME,		// name to display
			SERVICE_ALL_ACCESS,		// desired access
			SERVICE_WIN32_OWN_PROCESS,	// service type
			SRV_START_TYPE,			// start type
			SERVICE_ERROR_NORMAL,		// error control type
			szPath,				// service's binary
			NULL,				// no load ordering grp
			NULL,				// no tag identifier
			szDepend,			// dependencies
			NULL,				// LocalSystem account
			NULL);				// no password

	if (schService != NULL)
	{
#if defined(SRV_DESCRIPTION)		/* { */
		HINSTANCE		hDll;
		ChgSrvCfg2_t		ChgSrvCfg2;
		SERVICE_DESCRIPTION	SrvDesc;

		hDll = LoadLibrary(SRV_DESC_DLL);
		if (hDll != NULL)
		{
			ChgSrvCfg2 = (ChgSrvCfg2_t)GetProcAddress(hDll,
					SRV_DESC_SYM);
			if (ChgSrvCfg2 != NULL)
			{
				SrvDesc.lpDescription = SRV_DESCRIPTION;
				ChgSrvCfg2(schService,
						SERVICE_CONFIG_DESCRIPTION,
						&SrvDesc);
			}
			FreeLibrary(hDll);
		}
#endif /* SRV_DESCRIPTION */		/* } */

		if (bVerbose)
		{
			SrvMessage("%s installed.", SRV_DISPLAY_NAME);
		}
		CloseServiceHandle(schService);
	}
	else
	{
		SrvMessage("CreateService failed - %s",
				SrvGetLastErrorText(szErr, PATH_MAX));
		ret = 1;
	}
	CloseServiceHandle(schSCManager);

	return ret;
}

//	On Windows NT, stops the service, the unregisters it from the Service
//	Control Manager.  On Windows 95, removes the service from the
//	RunServices registry key.
static int SrvRemoveService(void)
{
	SC_HANDLE	schService;
	SC_HANDLE	schSCManager;
	char		szErr[PATH_MAX];
	int		ret = 0;

	//
	// Connect to the Service Control Manager, then stop the service
	// and remove it.
	//
	schSCManager = OpenSCManager(
			NULL,			// machine (NULL == local)
			NULL,			// database (NULL == default)
			SC_MANAGER_ALL_ACCESS	// access required
			);
	if (schSCManager != NULL)
	{
		schService = OpenService(schSCManager, SRV_NAME,
				SERVICE_ALL_ACCESS);

		if (schService != NULL)
		{
			//
			// Try to stop the service
			if (ControlService(schService,
						SERVICE_CONTROL_STOP,
						&ssStatus))
			{
				int ii = 0;

				if (bVerbose)
				{
					SrvMessage("Stopping %s.",
							SRV_DISPLAY_NAME);
				}
				sleep(1);

				while (QueryServiceStatus(schService,
							&ssStatus))
				{
					if (ssStatus.dwCurrentState == 
							SERVICE_STOP_PENDING)
					{
						sleep(1);
					}
					else
					{
						break;
					}
					if (++ii == SRV_MAX_STOP_TIME)
					{
						break;
					}
				}

				if (ssStatus.dwCurrentState == SERVICE_STOPPED)
				{
					if (bVerbose)
					{
						SrvMessage("%s stopped",
								SRV_DISPLAY_NAME);
					}
				}
				else
				{
					SrvMessage("%s failed to stop.",
							SRV_DISPLAY_NAME);
				}
			}

			//
			// Now remove the service
			//
			if(DeleteService(schService))
			{
				if (bVerbose)
				{
					SrvMessage("%s removed.",
							SRV_DISPLAY_NAME);
				}
			}
			else
			{
				SrvMessage("DeleteService failed - %s",
						SrvGetLastErrorText(szErr,PATH_MAX));
				ret = 1;
			}

			CloseServiceHandle(schService);
		}
		else
		{
			SrvMessage("OpenService failed - %s",
					SrvGetLastErrorText(szErr,PATH_MAX));
			ret = 1;
		}
		CloseServiceHandle(schSCManager);
	}
	else
	{
		SrvMessage("OpenSCManager failed - %s",
				SrvGetLastErrorText(szErr,PATH_MAX));
		ret = 1;
	}
	return ret;
}

//  SrvDebugService() --
//	Run the service as a console-mode application so it can be run under
//	the debugger.
static void SrvDebugService(
		int	argc,
		char	**argv,
		char	**envp)
{

#if 0
	//
	// Attach the console
	//
	freopen("/dev/tty", "wt", stdout);
	freopen("/dev/tty", "wt", stderr);
	freopen("/dev/tty", "rt", stdin);
	printf("Running as an exe.\n");
#endif

	bService = FALSE;
	{
		SetConsoleCtrlHandler(SrvConCtrlHdlr, TRUE);

		SrvArgc = argc;
		SrvArgv = argv;
		SrvEnvp = envp;
		SrvMain(1, NULL);
	}

}

//  SrvGetLastErrorText() --
//	Convert the last Win32 error code to a displayable string.
static LPSTR SrvGetLastErrorText(
		LPSTR	lpszBuf,
		DWORD	dwSize)
{
	DWORD	dwRet;
	LPSTR	lpszTemp = NULL;

	dwRet = FormatMessage((FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_ARGUMENT_ARRAY), NULL,
			GetLastError(), LANG_NEUTRAL, (LPTSTR)&lpszTemp,
			0, NULL);

	//
	// Supplied buffer is not long enough
	//
	if ( (!dwRet) || ((long)dwSize < (long)dwRet+14 ))
	{
		lpszBuf[0] = '\0';
	}
	else
	{
		lpszTemp[strlen(lpszTemp)-2] = '\0';
		sprintf(lpszBuf, "%s (0x%x)", lpszTemp, GetLastError());
	}

	if (lpszTemp != NULL)
	{
		LocalFree((HLOCAL)lpszTemp);
	}

	return lpszBuf;
}

//  SrvConCtrlHdlr() --
//	Handle console events when running as a console-mode program.
static BOOL WINAPI SrvConCtrlHdlr(
		DWORD	dwCtrlType)
{
	switch(dwCtrlType)
	{
		case CTRL_BREAK_EVENT:	// use Ctrl+C or Ctrl+Break to simulate
		case CTRL_C_EVENT:	// SERVICE_CONTROL_STOP in debug mode
			SrvStop();
			return TRUE;
	}
	return FALSE;
}

//  SrvSigHdlr() --
//	Signal handler used to interrupt and shut down the user thread when
//	the service is told to stop.  If the user has installed a signal
//	handler, it will override this, which is just fine.
static void SrvSigHdlr(
		int		sig)
{
	static long int SrvDone = -1;

	//
	// Brute-force way to ensure we only do this once.
	//
	if (InterlockedIncrement(&SrvDone) > 0)
	{
		return;
	}

	//
	// Call the user's cleanup function if one has been defined.
	//
#if defined SRV_CLEANUP_FUNCTION
	if(ServicePid == getpid())
	{
		SRV_CLEANUP_FUNCTION();
	}
#endif

	//
	// Exit the process.
	//
	exit(0);
}

//  SrvAtExitHdlr() --
//	Tell the Service Control Manager that the service has stopped.
static void SrvAtExitHdlr(void)
{
	if (bService && (ServicePid == getpid()))
	{
		SrvReportToSCMgr(SERVICE_STOPPED, NO_ERROR, 0);
	}
}

//
//  SrvPrepMain() --
//	Prepare to call the user's service main.  Save the thread ID of the
//	service thread, then set up signal handlers and atexit handlers
//	so the service will shut down properly.
//
static void SrvPrepMain(void)
{
	struct sigaction	act;

	SrvThread = pthread_self();

	act.sa_handler = SrvSigHdlr;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SRV_STOP_SIGNAL, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);

	atexit(SrvAtExitHdlr);
}

//
//  SrvWaiter() --
//	Wait for the service thread to go away (which will be indicated by
//	the process exiting).  Keep tickling the Service Control Manager
//	as we wait.  If we reach the end of the loop, just go away, whether
//	or not the user's thread is done.
//
static void *SrvWaiter(void *_unused_)
{
	sigset_t	set;
	int		ii;

	sigfillset(&set);
	sigdelset(&set, SIGSEGV);
	sigdelset(&set, SIGABRT);
	sigaddset(&set, SRV_STOP_SIGNAL);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	SrvReportToSCMgr(SERVICE_STOP_PENDING, NO_ERROR, 3000);
	for (ii = 0; ii < SRV_MAX_STOP_TIME; ii++) {
		sleep(1);
		SrvReportToSCMgr(SERVICE_STOP_PENDING, NO_ERROR, 3000);
	}

	exit(0);

	return (_unused_); /* semantics */
}

//
//  SrvStop() --
//	Kill the user thread, then spin up a thread to wait for it to go
//	away.
//
static void SrvStop(void)
{
	pthread_t wait_thread;

	memset(&wait_thread, 0, sizeof(wait_thread));

	pthread_kill(SrvThread, SRV_STOP_SIGNAL);

	if (bService)
	{
		pthread_create(&wait_thread, NULL, SrvWaiter, NULL);
	}

	/* the pthread_kill() above isn't being handled properly.. (accidently blocked via inherited code?). a more forceful approach. note SrvWaiter will ignore this signal. */
	raise(SRV_STOP_SIGNAL);
}

static void change_core_directory(void) 
{
	char path[PATH_MAX+1];
	char *str;

  str = getenv("ProgramData");
  if (!str)
	  str = "C:\\ProgramData";

  sprintf(path, "%s\\share\\", str);
  mkdir(path, 0777);
  strcat(path, "blockchain\\");
  mkdir(path, 0777);
	SetCurrentDirectory(path);

  strcat(path, "database\\");
  mkdir(path, 0777);

  /* quash stdin/stdout confusoin */
  (void)open(".tmp-1", O_RDWR | O_CREAT, 0777);
  (void)open(".tmp-2", O_RDWR | O_CREAT, 0777);
  (void)open(".tmp-3", O_RDWR | O_CREAT, 0777);

}

