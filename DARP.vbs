' ╔══════════════════════════════════════════════╗
' ║   DARP v8  —  Launcher (NO CMD WINDOW)      ║
' ╚══════════════════════════════════════════════╝
Option Explicit
Dim oShell, oFSO, sDir, sPy, sPyDir
Set oShell = CreateObject("WScript.Shell")
Set oFSO   = CreateObject("Scripting.FileSystemObject")

' Рабочая папка = папка скрипта
sDir = oFSO.GetParentFolderName(WScript.ScriptFullName)
oShell.CurrentDirectory = sDir

' ── Поиск Python ───────────────────────────────
Dim candidates(20), i, found
candidates(0)  = oShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Programs\Python\Python313\pythonw.exe")
candidates(1)  = oShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe")
candidates(2)  = oShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Programs\Python\Python311\pythonw.exe")
candidates(3)  = oShell.ExpandEnvironmentStrings("%LOCALAPPDATA%\Programs\Python\Python310\pythonw.exe")
candidates(4)  = oShell.ExpandEnvironmentStrings("%APPDATA%\Python\Python313\Scripts\pythonw.exe")
candidates(5)  = oShell.ExpandEnvironmentStrings("%APPDATA%\Python\Python312\Scripts\pythonw.exe")
candidates(6)  = "C:\Python313\pythonw.exe"
candidates(7)  = "C:\Python312\pythonw.exe"
candidates(8)  = "C:\Python311\pythonw.exe"
candidates(9)  = "C:\Python310\pythonw.exe"
candidates(10) = "C:\Python39\pythonw.exe"
candidates(11) = oShell.ExpandEnvironmentStrings("%PROGRAMFILES%\Python313\pythonw.exe")
candidates(12) = oShell.ExpandEnvironmentStrings("%PROGRAMFILES%\Python312\pythonw.exe")
candidates(13) = oShell.ExpandEnvironmentStrings("%PROGRAMFILES(X86)%\Python313\pythonw.exe")
candidates(14) = oShell.ExpandEnvironmentStrings("%PROGRAMFILES(X86)%\Python312\pythonw.exe")
candidates(15) = oShell.ExpandEnvironmentStrings("%USERPROFILE%\AppData\Local\Programs\Python\Python313\pythonw.exe")
candidates(16) = oShell.ExpandEnvironmentStrings("%USERPROFILE%\AppData\Local\Programs\Python\Python312\pythonw.exe")
candidates(17) = oShell.ExpandEnvironmentStrings("%USERPROFILE%\AppData\Local\Programs\Python\Python311\pythonw.exe")
candidates(18) = oShell.ExpandEnvironmentStrings("%WINDIR%\py.exe")
candidates(19) = ""
candidates(20) = ""

found = ""
For i = 0 To 18
    If candidates(i) <> "" Then
        If oFSO.FileExists(candidates(i)) Then
            found = Chr(34) & candidates(i) & Chr(34)
            Exit For
        End If
    End If
Next

' Если не нашли — пробуем через where
If found = "" Then
    Dim oExec, sLine
    On Error Resume Next
    Set oExec = oShell.Exec("where pythonw.exe")
    If Err.Number = 0 Then
        sLine = oExec.StdOut.ReadLine()
        If sLine <> "" And oFSO.FileExists(Trim(sLine)) Then
            found = Chr(34) & Trim(sLine) & Chr(34)
        End If
    End If
    On Error GoTo 0
End If

' Если вообще не нашли Python — сообщаем и выходим
If found = "" Then
    MsgBox "Python не найден!" & vbCrLf & vbCrLf & _
           "Установите Python 3.10+ с сайта:" & vbCrLf & _
           "https://www.python.org/downloads/" & vbCrLf & vbCrLf & _
           "При установке включите 'Add Python to PATH'", _
           vbCritical + vbOKOnly, "DARP v8 — Ошибка запуска"
    WScript.Quit 1
End If

' ── Запуск без окна (0 = скрыто, False = не ждём) ─
oShell.Run found & " """ & sDir & "\run.py""", 0, False
