
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

#include <Windows.h>

#pragma comment(lib, "winapi.lib")

#define SVCNAME TEXT("ShareCoin")

SERVICE_STATUS          gSvcStatus; 
SERVICE_STATUS_HANDLE   gSvcStatusHandle; 
HANDLE                  ghSvcStopEvent = NULL;

extern int svc_main(int argc, char **argv);


VOID SvcInit( DWORD dwArgc, LPTSTR *lpszArgv)
{

  // TO_DO: Declare and set any required variables.
  //   Be sure to periodically call ReportSvcStatus() with 
  //   SERVICE_START_PENDING. If initialization fails, call
  //   ReportSvcStatus with SERVICE_STOPPED.

  // Create an event. The control handler function, SvcCtrlHandler,
  // signals this event when it receives the stop control code.

  ghSvcStopEvent = CreateEvent(
      NULL,    // default security attributes
      TRUE,    // manual reset event
      FALSE,   // not signaled
      NULL);   // no name

  if ( ghSvcStopEvent == NULL)
  {
    /* console application */
    (void)svc_main(dwArgc, lpszArgv);
    //ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
    return;
  }

  ReportSvcStatus( SERVICE_RUNNING, NO_ERROR, 0 );

  (void)svc_main(dwArgc, lpszArgv);

  while(1) { /* check whether to stop the service. */
    WaitForSingleObject(ghSvcStopEvent, INFINITE);
    ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
    return;
  }

}

/**
 * Sets the current service status and reports it to the SCM.
 *
 * Parameters:
 *   dwCurrentState - The current state (see SERVICE_STATUS)
 *   dwWin32ExitCode - The system error code
 *   dwWaitHint - Estimated time for pending operation, 
 *     in milliseconds
 */
VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
  static DWORD dwCheckPoint = 1;

  // Fill in the SERVICE_STATUS structure.

  gSvcStatus.dwCurrentState = dwCurrentState;
  gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
  gSvcStatus.dwWaitHint = dwWaitHint;

  if (dwCurrentState == SERVICE_START_PENDING)
    gSvcStatus.dwControlsAccepted = 0;
  else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

  if ( (dwCurrentState == SERVICE_RUNNING) ||
      (dwCurrentState == SERVICE_STOPPED) )
    gSvcStatus.dwCheckPoint = 0;
  else gSvcStatus.dwCheckPoint = dwCheckPoint++;

  // Report the status of the service to the SCM.
  SetServiceStatus( gSvcStatusHandle, &gSvcStatus );
}

