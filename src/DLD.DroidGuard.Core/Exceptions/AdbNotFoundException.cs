namespace DLD.DroidGuard.Core.Exceptions;

/// <summary>
/// Thrown when the ADB executable cannot be found on the host machine.
/// The application must handle this gracefully — no crash allowed.
/// </summary>
public sealed class AdbNotFoundException : Exception
{
    public AdbNotFoundException()
        : base("ADB executable (adb.exe) was not found. "
               + "Please install Android Platform Tools or configure the ADB path.") { }

    public AdbNotFoundException(string message)
        : base(message) { }

    public AdbNotFoundException(string message, Exception inner)
        : base(message, inner) { }
}
