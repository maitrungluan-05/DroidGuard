using System.Text.RegularExpressions;

namespace DLD.DroidGuard.Adb;

/// <summary>
/// Parses launcher activity query output (cmd package query-activities or pm query-intent-activities).
/// </summary>
public sealed class LauncherQueryParser
{
    // Matches component names like "com.example.app/com.example.app.MainActivity" or "com.example.app/.MainActivity"
    private static readonly Regex ComponentRegex = new(
        @"([a-zA-Z0-9_.]+)\/([a-zA-Z0-9_.$]+)",
        RegexOptions.Compiled);

    /// <summary>
    /// Extracts a set of package names that possess a launcher activity.
    /// Returns null if the query output indicates the command was unsupported or invalid.
    /// </summary>
    public HashSet<string>? Parse(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return null;

        // Check for unsupported command output signs
        if (output.Contains("Unknown command", StringComparison.OrdinalIgnoreCase) ||
            output.Contains("Error:", StringComparison.OrdinalIgnoreCase) ||
            output.Contains("java.lang.", StringComparison.OrdinalIgnoreCase) ||
            output.Contains("invalid command", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match match in ComponentRegex.Matches(output))
        {
            var pkgName = match.Groups[1].Value.Trim();
            if (!string.IsNullOrEmpty(pkgName))
            {
                result.Add(pkgName);
            }
        }

        return result;
    }
}
