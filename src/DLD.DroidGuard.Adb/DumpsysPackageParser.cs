using System.Globalization;
using System.Text.RegularExpressions;
using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Adb;

public sealed record ParsedPackageMeta(
    string PackageName,
    string? VersionName,
    long? VersionCode,
    int? Uid,
    string? ApkPath,
    AppOrigin Origin,
    bool? IsEnabled,
    string? InstallerPackage,
    DateTimeOffset? FirstInstallTime,
    DateTimeOffset? LastUpdateTime,
    IReadOnlyList<string> RequestedPermissions,
    string? SharedUserId = null,
    int? TargetSdk = null,
    int? MinSdk = null,
    bool? IsDebuggable = null,
    bool? AllowBackup = null,
    IReadOnlyList<string>? Signatures = null
);

/// <summary>
/// Parses bulk or single-package "dumpsys package" output.
/// </summary>
public sealed class DumpsysPackageParser
{
    private static readonly Regex PackageBlockHeaderRegex = new(
        @"Package\s+\[([a-zA-Z0-9_.]+)\]",
        RegexOptions.Compiled);

    private static readonly Regex VersionNameRegex = new(
        @"versionName=([^\r\n]+)",
        RegexOptions.Compiled);

    private static readonly Regex VersionCodeRegex = new(
        @"versionCode=(\d+)",
        RegexOptions.Compiled);

    private static readonly Regex UidRegex = new(
        @"(?:userId|appId|uid)=(\d+)",
        RegexOptions.Compiled);

    private static readonly Regex CodePathRegex = new(
        @"(?:codePath|resourcePath)=([^\r\n]+)",
        RegexOptions.Compiled);

    private static readonly Regex PkgFlagsRegex = new(
        @"(?:pkgFlags|flags)=\[\s*([^\]]+)\s*\]",
        RegexOptions.Compiled);

    private static readonly Regex EnabledStateRegex = new(
        @"(?:enabled|enabledSetting)=([0-4]|DEFAULT|ENABLED|DISABLED|DISABLED_USER|DISABLED_UNTIL_USED)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex InstallerRegex = new(
        @"installerPackageName=([a-zA-Z0-9_.]+)",
        RegexOptions.Compiled);

    private static readonly Regex FirstInstallTimeRegex = new(
        @"firstInstallTime=([^\r\n]+)",
        RegexOptions.Compiled);

    private static readonly Regex LastUpdateTimeRegex = new(
        @"lastUpdateTime=([^\r\n]+)",
        RegexOptions.Compiled);

    private static readonly Regex TargetSdkRegex = new(
        @"targetSdk=(\d+)",
        RegexOptions.Compiled);

    private static readonly Regex MinSdkRegex = new(
        @"minSdk=(\d+)",
        RegexOptions.Compiled);

    private static readonly Regex SharedUserIdRegex = new(
        @"(?:sharedUser|sharedUserId)=(?:SharedUserSetting\{[^}]+\s+)?([a-zA-Z0-9_.]+)",
        RegexOptions.Compiled);

    private static readonly Regex SignatureDigestRegex = new(
        @"(?:signatures|PackageSignatures)\{[^}]*\[\s*([0-9a-fA-F]+)",
        RegexOptions.Compiled);

    /// <summary>
    /// Parses dumpsys package text and returns a dictionary of package metadata by package name.
    /// </summary>
    public IReadOnlyDictionary<string, ParsedPackageMeta> Parse(string dumpsysOutput)
    {
        var result = new Dictionary<string, ParsedPackageMeta>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(dumpsysOutput))
            return result;

        // Split text into Package blocks
        var matches = PackageBlockHeaderRegex.Matches(dumpsysOutput);
        for (int i = 0; i < matches.Count; i++)
        {
            var match = matches[i];
            var pkgName = match.Groups[1].Value;

            int startIndex = match.Index;
            int endIndex = (i + 1 < matches.Count) ? matches[i + 1].Index : dumpsysOutput.Length;

            var blockText = dumpsysOutput.Substring(startIndex, endIndex - startIndex);

            var meta = ParseBlock(pkgName, blockText);
            result[pkgName] = meta;
        }

        return result;
    }

    /// <summary>
    /// Parses a single package block string.
    /// </summary>
    public ParsedPackageMeta ParseBlock(string packageName, string blockText)
    {
        string? versionName = null;
        var vnMatch = VersionNameRegex.Match(blockText);
        if (vnMatch.Success)
        {
            var raw = vnMatch.Groups[1].Value.Trim();
            if (!string.Equals(raw, "null", StringComparison.OrdinalIgnoreCase))
                versionName = raw;
        }

        long? versionCode = null;
        var vcMatch = VersionCodeRegex.Match(blockText);
        if (vcMatch.Success && long.TryParse(vcMatch.Groups[1].Value, out var vc))
        {
            versionCode = vc;
        }

        int? uid = null;
        var uidMatch = UidRegex.Match(blockText);
        if (uidMatch.Success && int.TryParse(uidMatch.Groups[1].Value, out var u))
        {
            uid = u;
        }

        string? apkPath = null;
        var pathMatch = CodePathRegex.Match(blockText);
        if (pathMatch.Success)
        {
            var raw = pathMatch.Groups[1].Value.Trim();
            if (!string.IsNullOrEmpty(raw))
                apkPath = raw;
        }

        // Determine AppOrigin, Debuggable, AllowBackup from pkgFlags
        var origin = AppOrigin.Unknown;
        bool? isDebuggable = null;
        bool? allowBackup = null;

        var flagsMatch = PkgFlagsRegex.Match(blockText);
        if (flagsMatch.Success)
        {
            var flagsStr = flagsMatch.Groups[1].Value;
            if (flagsStr.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                flagsStr.Contains("FLAG_SYSTEM", StringComparison.OrdinalIgnoreCase))
            {
                origin = AppOrigin.System;
            }
            else
            {
                origin = AppOrigin.User;
            }

            isDebuggable = flagsStr.Contains("DEBUGGABLE", StringComparison.OrdinalIgnoreCase);
            allowBackup = flagsStr.Contains("ALLOW_BACKUP", StringComparison.OrdinalIgnoreCase);
        }

        // Determine Enabled state
        bool? isEnabled = null;
        var enabledMatch = EnabledStateRegex.Match(blockText);
        if (enabledMatch.Success)
        {
            var token = enabledMatch.Groups[1].Value.ToUpperInvariant();
            isEnabled = token switch
            {
                "0" => true,       // COMPONENT_ENABLED_STATE_DEFAULT
                "1" => true,       // COMPONENT_ENABLED_STATE_ENABLED
                "DEFAULT" => true,
                "ENABLED" => true,
                "2" => false,      // COMPONENT_ENABLED_STATE_DISABLED
                "3" => false,      // COMPONENT_ENABLED_STATE_DISABLED_USER
                "4" => false,      // COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED
                "DISABLED" => false,
                "DISABLED_USER" => false,
                "DISABLED_UNTIL_USED" => false,
                _ => null
            };
        }

        string? installerPackage = null;
        var instMatch = InstallerRegex.Match(blockText);
        if (instMatch.Success)
        {
            var raw = instMatch.Groups[1].Value.Trim();
            if (!string.Equals(raw, "null", StringComparison.OrdinalIgnoreCase))
                installerPackage = raw;
        }

        DateTimeOffset? firstInstallTime = null;
        var fitMatch = FirstInstallTimeRegex.Match(blockText);
        if (fitMatch.Success)
        {
            firstInstallTime = ParseDateTimeOffset(fitMatch.Groups[1].Value.Trim());
        }

        DateTimeOffset? lastUpdateTime = null;
        var lutMatch = LastUpdateTimeRegex.Match(blockText);
        if (lutMatch.Success)
        {
            lastUpdateTime = ParseDateTimeOffset(lutMatch.Groups[1].Value.Trim());
        }

        int? targetSdk = null;
        var tsMatch = TargetSdkRegex.Match(blockText);
        if (tsMatch.Success && int.TryParse(tsMatch.Groups[1].Value, out var ts))
        {
            targetSdk = ts;
        }

        int? minSdk = null;
        var msMatch = MinSdkRegex.Match(blockText);
        if (msMatch.Success && int.TryParse(msMatch.Groups[1].Value, out var ms))
        {
            minSdk = ms;
        }

        string? sharedUserId = null;
        var suMatch = SharedUserIdRegex.Match(blockText);
        if (suMatch.Success)
        {
            sharedUserId = suMatch.Groups[1].Value.Trim();
        }

        List<string>? signatures = null;
        var sigMatch = SignatureDigestRegex.Match(blockText);
        if (sigMatch.Success)
        {
            signatures = new List<string> { sigMatch.Groups[1].Value };
        }

        var requestedPermissions = ParseRequestedPermissions(blockText);

        return new ParsedPackageMeta(
            PackageName: packageName,
            VersionName: versionName,
            VersionCode: versionCode,
            Uid: uid,
            ApkPath: apkPath,
            Origin: origin,
            IsEnabled: isEnabled,
            InstallerPackage: installerPackage,
            FirstInstallTime: firstInstallTime,
            LastUpdateTime: lastUpdateTime,
            RequestedPermissions: requestedPermissions,
            SharedUserId: sharedUserId,
            TargetSdk: targetSdk,
            MinSdk: minSdk,
            IsDebuggable: isDebuggable,
            AllowBackup: allowBackup,
            Signatures: signatures
        );
    }

    private static IReadOnlyList<string> ParseRequestedPermissions(string blockText)
    {
        var result = new List<string>();
        int index = blockText.IndexOf("requested permissions:", StringComparison.OrdinalIgnoreCase);
        if (index < 0) return result;

        var lines = blockText.Substring(index).Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        // Skip header line "requested permissions:"
        for (int i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;

            // Section stops when encountering next top-level or unindented header
            if (line.StartsWith("  install permissions:", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("  User ", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("  Queries:", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("  Dexopt state:", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("  declared permissions:", StringComparison.OrdinalIgnoreCase) ||
                !line.StartsWith("    "))
            {
                break;
            }

            if (trimmed.StartsWith("android.permission.") || trimmed.Contains(".permission."))
            {
                // Strip colon or trailing state if any
                var permName = trimmed.Split(':')[0].Trim();
                result.Add(permName);
            }
        }

        return result;
    }

    private static DateTimeOffset? ParseDateTimeOffset(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || string.Equals(raw, "null", StringComparison.OrdinalIgnoreCase))
            return null;

        // Try ISO 8601 or Android dumpsys standard formats (e.g. "2023-05-12 10:20:30" or "2023-05-12T10:20:30Z")
        var formats = new[]
        {
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd HH:mm:ss.fff",
            "yyyy-MM-ddTHH:mm:ssZ",
            "yyyy-MM-ddTHH:mm:ss.fffZ",
            "yyyy-MM-ddTHH:mm:sszzz",
            "yyyy-MM-dd"
        };

        if (DateTimeOffset.TryParseExact(raw, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var resultExact))
        {
            return resultExact;
        }

        if (DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var resultGeneral))
        {
            return resultGeneral;
        }

        // Try unix timestamp milliseconds
        if (long.TryParse(raw, out var millis))
        {
            try
            {
                return DateTimeOffset.FromUnixTimeMilliseconds(millis);
            }
            catch
            {
                return null;
            }
        }

        return null;
    }
}
