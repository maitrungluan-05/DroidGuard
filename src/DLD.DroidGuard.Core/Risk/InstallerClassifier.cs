namespace DLD.DroidGuard.Core.Risk;

public enum InstallerCategory
{
    GooglePlay,
    KnownTrusted,
    SystemInstaller,
    UnknownSideload
}

/// <summary>
/// Classifies application installer source packages.
/// </summary>
public static class InstallerClassifier
{
    private static readonly HashSet<string> GooglePlayInstallers = new(StringComparer.OrdinalIgnoreCase)
    {
        "com.android.vending",
        "com.google.android.feedback"
    };

    private static readonly HashSet<string> KnownTrustedInstallers = new(StringComparer.OrdinalIgnoreCase)
    {
        "com.sec.android.app.samsungapps",
        "com.huawei.appmarket",
        "com.xiaomi.mipick",
        "com.oppo.market",
        "com.vivo.market",
        "com.amazon.venezia"
    };

    private static readonly HashSet<string> SystemInstallers = new(StringComparer.OrdinalIgnoreCase)
    {
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.google.android.pm"
    };

    public static InstallerCategory Classify(string? installerPackage)
    {
        if (string.IsNullOrWhiteSpace(installerPackage))
            return InstallerCategory.UnknownSideload;

        if (GooglePlayInstallers.Contains(installerPackage))
            return InstallerCategory.GooglePlay;

        if (KnownTrustedInstallers.Contains(installerPackage))
            return InstallerCategory.KnownTrusted;

        if (SystemInstallers.Contains(installerPackage))
            return InstallerCategory.SystemInstaller;

        return InstallerCategory.UnknownSideload;
    }
}
