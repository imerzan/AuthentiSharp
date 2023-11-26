# AuthentiSharp
C# Library for validating File Authenticode Signatures in Windows.

## Examples
```csharp
using AuthentiSharp;

namespace Example
{
    public static void Example1()
    {
        try
        {
            if (!Authenticode.Verify(Process.GetCurrentProcess().MainModule.FileName)) // Only checks authenticode signature
                throw new Exception();
        }
        catch
        {
            Environment.FailFast("Assembly Tampering Detected!");
        }
    }

    public static void Example2()
    {
        try
        {
            if (!Authenticode.VerifyFull(Process.GetCurrentProcess().MainModule.FileName,
            (cert, chain) => // Also checks certificate validity via custom callback
            {
                chain.ChainPolicy = new()
                {
                    RevocationMode = X509RevocationMode.Online,
                    RevocationFlag = X509RevocationFlag.ExcludeRoot
                };
                if (!chain.Build(cert))
                    return false;
                if (!cert.Thumbprint.Equals("YourExpectedThumbprint", StringComparison.OrdinalIgnoreCase))
                    return false;
                return true;
            }))
                throw new Exception();
        }
        catch
        {
            Environment.FailFast("Assembly Tampering Detected!");
        }
    }
}
```

## Install via Nuget
[![AuthentiSharp](https://img.shields.io/badge/AuthentiSharp-1.1.0-123)](https://www.nuget.org/packages/AuthentiSharp/)
