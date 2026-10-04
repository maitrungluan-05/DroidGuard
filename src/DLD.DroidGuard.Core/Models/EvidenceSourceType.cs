namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Source origin of risk evidence items.
/// </summary>
public enum EvidenceSourceType
{
    PackageMetadata,
    Permission,
    Installer,
    Launcher,
    Runtime,
    Apk,
    Signature
}
