namespace DLD.DroidGuard.Core.Risk;

public enum PermissionCategory
{
    Normal,
    Sensitive,
    HighRisk,
    SpecialAccess
}

/// <summary>
/// Classifies Android permissions into security categories and evaluates permission risk points.
/// Handles permission normalization, duplicate removal, and safe fallback for unknown permissions.
/// </summary>
public static class PermissionClassifier
{
    private static readonly HashSet<string> SensitivePermissions = new(StringComparer.OrdinalIgnoreCase)
    {
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.GET_ACCOUNTS",
        "android.permission.MANAGE_EXTERNAL_STORAGE"
    };

    private static readonly HashSet<string> HighRiskPermissions = new(StringComparer.OrdinalIgnoreCase)
    {
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE"
    };

    private static readonly HashSet<string> SpecialAccessPermissions = new(StringComparer.OrdinalIgnoreCase)
    {
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
    };

    /// <summary>
    /// Normalizes permission strings (trims whitespace, adds android.permission. prefix if missing).
    /// </summary>
    public static string NormalizePermission(string rawPermission)
    {
        if (string.IsNullOrWhiteSpace(rawPermission))
            return string.Empty;

        var trimmed = rawPermission.Trim();
        if (!trimmed.Contains('.'))
        {
            return $"android.permission.{trimmed}";
        }

        return trimmed;
    }

    public static PermissionCategory GetCategory(string permissionName)
    {
        var normalized = NormalizePermission(permissionName);
        if (string.IsNullOrEmpty(normalized))
            return PermissionCategory.Normal;

        if (SpecialAccessPermissions.Contains(normalized))
            return PermissionCategory.SpecialAccess;

        if (HighRiskPermissions.Contains(normalized))
            return PermissionCategory.HighRisk;

        if (SensitivePermissions.Contains(normalized))
            return PermissionCategory.Sensitive;

        // Safe fallback for unknown/unrecognized permissions -> Normal category (0 risk points)
        return PermissionCategory.Normal;
    }

    /// <summary>
    /// Calculates individual permission risk points.
    /// Deduplicates permissions to prevent double-counting duplicate declarations.
    /// </summary>
    public static int EvaluatePermissionPoints(IEnumerable<string> permissions, out List<string> requestedHighRisk)
    {
        requestedHighRisk = new List<string>();
        if (permissions == null) return 0;

        // Deduplicate and normalize permissions
        var uniquePerms = permissions
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(NormalizePermission)
            .Distinct(StringComparer.OrdinalIgnoreCase);

        int points = 0;
        foreach (var perm in uniquePerms)
        {
            var cat = GetCategory(perm);
            switch (cat)
            {
                case PermissionCategory.SpecialAccess:
                    points += 10;
                    requestedHighRisk.Add(perm);
                    break;
                case PermissionCategory.HighRisk:
                    points += 5;
                    requestedHighRisk.Add(perm);
                    break;
                case PermissionCategory.Sensitive:
                    points += 2;
                    break;
            }
        }

        // Cap raw permission points to 30
        return Math.Min(points, 30);
    }

    /// <summary>
    /// Evaluates dangerous permission combination risk points.
    /// Deduplicates input permissions.
    /// </summary>
    public static int EvaluatePermissionCombinationPoints(IEnumerable<string> permissions, out List<string> matchedCombinations)
    {
        matchedCombinations = new List<string>();
        if (permissions == null) return 0;

        var uniquePerms = permissions
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(NormalizePermission);

        var set = new HashSet<string>(uniquePerms, StringComparer.OrdinalIgnoreCase);
        int points = 0;

        // Combination 1: Accessibility + Overlay (Classic banking trojan / adware combination)
        bool hasAccessibility = set.Contains("android.permission.BIND_ACCESSIBILITY_SERVICE");
        bool hasOverlay = set.Contains("android.permission.SYSTEM_ALERT_WINDOW");
        if (hasAccessibility && hasOverlay)
        {
            points += 20;
            matchedCombinations.Add("Accessibility Service + Display Overlay (High risk UI manipulation)");
        }

        // Combination 2: SMS + Contacts + Background execution (Classic spyware / info-stealer)
        bool hasSms = set.Contains("android.permission.READ_SMS") || set.Contains("android.permission.RECEIVE_SMS") || set.Contains("android.permission.SEND_SMS");
        bool hasContacts = set.Contains("android.permission.READ_CONTACTS");
        bool hasBoot = set.Contains("android.permission.RECEIVE_BOOT_COMPLETED");
        if (hasSms && hasContacts && hasBoot)
        {
            points += 20;
            matchedCombinations.Add("SMS + Contacts + Boot Auto-start (Information stealer / Spyware pattern)");
        }
        else if (hasSms && hasContacts)
        {
            points += 10;
            matchedCombinations.Add("SMS + Contacts (Message & Contact access)");
        }

        // Combination 3: Camera + Microphone + Location (Surveillance pattern)
        bool hasCamera = set.Contains("android.permission.CAMERA");
        bool hasMic = set.Contains("android.permission.RECORD_AUDIO");
        bool hasLocation = set.Contains("android.permission.ACCESS_FINE_LOCATION");
        if (hasCamera && hasMic && hasLocation)
        {
            points += 15;
            matchedCombinations.Add("Camera + Microphone + Fine Location (Surveillance pattern)");
        }

        // Combination 4: Package Installation + Overlay
        bool hasInstall = set.Contains("android.permission.REQUEST_INSTALL_PACKAGES");
        if (hasInstall && hasOverlay)
        {
            points += 15;
            matchedCombinations.Add("Package Installation + Display Overlay (Dropper / Silent installer pattern)");
        }

        return Math.Min(points, 35);
    }
}
