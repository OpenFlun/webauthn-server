On Error Resume Next
Const PROCESS_NAME = "CredentialUIBroker.exe"
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.SendKeys "%"
WScript.Sleep 50

Function GetProcessId(processName)
    Dim objWMIService, colItems, objItem
    Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
    If Err.Number <> 0 Then Exit Function
    Set colItems = objWMIService.ExecQuery("Select ProcessId from Win32_Process Where Name='" & processName & "'")
    For Each objItem In colItems
        GetProcessId = objItem.ProcessId
        Exit Function
    Next
    GetProcessId = 0
End Function

pid = GetProcessId(PROCESS_NAME)
If pid <> 0 Then
    WshShell.AppActivate(pid)
    WScript.Echo "OK"
End If