using System.Text.RegularExpressions;
using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Adb;

public sealed record RawPackageEntry(string PackageName, string? ApkPath);

/// <summary>
/// Parses "pm list packages -f" output into package names and APK paths.
/// </summary>
public sealed class PackageListParser
{
    // Matches "package:/path/to/app.apk=com.example.app"
    private static readonly Regex PackagePathRegex = new(
        @"^package:(.+)=([a-zA-Z0-9_.]+)\s*$",
        RegexOptions.Compiled);

    // Matches simple "package:com.example.app"
    private static readonly Regex SimplePackageRegex = new(
        @"^package:([a-zA-Z0-9_.]+)\s*$",
        RegexOptions.Compiled);

    /// <summary>
    /// Parses output lines from "pm list packages -f" (or "pm list packages").
    /// </summary>
    public IReadOnlyList<RawPackageEntry> Parse(string output)
    {
        var result = new List<RawPackageEntry>();
        if (string.IsNullOrWhiteSpace(output))
            return result;

        foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed))
                continue;

            // Try matching package:path=name first
            var matchPath = PackagePathRegex.Match(trimmed);
            if (matchPath.Success)
            {
                var apkPath = matchPath.Groups[1].Value.Trim();
                var pkgName = matchPath.Groups[2].Value.Trim();
                result.Add(new RawPackageEntry(pkgName, apkPath));
                continue;
            }

            // Try simple package:name
            var matchSimple = SimplePackageRegex.Match(trimmed);
            if (matchSimple.Success)
            {
                var pkgName = matchSimple.Groups[1].Value.Trim();
                result.Add(new RawPackageEntry(pkgName, null));
            }
        }

        return result;
    }
}
