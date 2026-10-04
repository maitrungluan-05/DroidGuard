using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.App.ViewModels;

/// <summary>
/// ViewModel representing a single Android device in the device list.
/// </summary>
public sealed class AndroidDeviceViewModel : ViewModelBase
{
    private bool _isSelected;

    public AndroidDevice Device { get; }

    public string Serial   => Device.Serial;
    public string StateDisplay => Device.State switch
    {
        AdbDeviceState.Device        => "Connected",
        AdbDeviceState.Offline       => "Offline",
        AdbDeviceState.Unauthorized  => "Unauthorized",
        AdbDeviceState.Bootloader    => "Bootloader",
        AdbDeviceState.NoPermissions => "No Permissions",
        AdbDeviceState.Recovery      => "Recovery",
        AdbDeviceState.Sideload      => "Sideload",
        _                            => "Unknown",
    };

    public string? Model   => Device.Model;
    public string? Product => Device.Product;

    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }

    public AndroidDeviceViewModel(AndroidDevice device)
    {
        Device = device ?? throw new ArgumentNullException(nameof(device));
    }
}
