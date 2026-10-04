using System.Text.RegularExpressions;

namespace DLD.DroidGuard.Adb;

/// <summary>
/// Centralized command builder and safety validator for ADB process executions.
/// Enforces strict allow-list validation on device serials and package names to prevent shell injection.
/// </summary>
public static class SafeAdbCommandBuilder
{
    // Allows alphanumerics, underscores, dots, hyphens, and colons (for network ADB serials like 192.168.1.100:5555)
    private static readonly Regex SafeIdentifierRegex = new(@"^[a-zA-Z0-9_.:-]+$", RegexOptions.Compiled);

    /// <summary>
    /// Checks if a string contains only valid Android package name or serial characters.
    /// Prohibits metacharacters (; &amp; | $ ` &gt; &lt; \ " ' space newline).
    /// </summary>
    public static bool IsSafeIdentifier(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        return SafeIdentifierRegex.IsMatch(value.Trim());
    }

    /// <summary>
    /// Validates an identifier string. Throws ArgumentException if prohibited characters are detected.
    /// </summary>
    public static void ValidateIdentifier(string? value, string paramName)
    {
        if (!IsSafeIdentifier(value))
        {
            throw new ArgumentException($"Unsafe or invalid identifier string for parameter '{paramName}'. Prohibited characters detected.", paramName);
        }
    }
}
