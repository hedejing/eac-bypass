## Build Commands

### Building Drivers
```powershell
# Build IOCTL Driver
msbuild "cr3 - Ioctl Driver/cr3 - Ioctl Driver/IoctlDriver.vcxproj" /p:Configuration=Debug /p:Platform=x64

# Build CR3 Ready Driver  
msbuild "Cr3 Ready Driver/Cr3ReadyDriver.vcxproj" /p:Configuration=Debug /p:Platform=x64
```

### Building Clients
```powershell
# Build IOCTL Client (registry-based communication)
msbuild "IoctlClient.vcxproj" /p:Configuration=Release /p:Platform=x64

# Build CR3 Client (API hijacking)
msbuild "Cr3Client.vcxproj" /p:Configuration=Release /p:Platform=x64
```

### Driver Loading and Testing
```powershell
# Load IOCTL Driver (requires admin privileges)
sc.exe create IoctlDriver binPath= "C:\path\to\cr3 - Ioctl Driver\cr3 - Ioctl Driver\x64\Debug\IoctlDriver.sys" type= kernel
sc.exe start IoctlDriver

# For unsigned drivers, may need test signing:
bcdedit /set testsigning on  # Requires Secure Boot disabled
```
