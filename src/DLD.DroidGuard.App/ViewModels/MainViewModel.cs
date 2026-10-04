using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Exceptions;
using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Core.Risk;
using Microsoft.Extensions.Logging;

namespace DLD.DroidGuard.App.ViewModels;

/// <summary>
/// Main ViewModel for DLD DroidGuard Desktop Security Suite.
/// Manages Quick Scan, Risk Engine V2, Deep Analysis (Forensic + Runtime + Behavioral Correlation), Remediation (Safety & Dry Run), Filtering, and JSON Report Export.
/// </summary>
public sealed class MainViewModel : ViewModelBase
{
    private readonly IAdbClient _adbClient;
    private readonly IDeviceInfoService _deviceInfoService;
    private readonly IPackageScanner _packageScanner;
    private readonly IRiskEngine _riskEngine;
    private readonly IAdbLocator _adbLocator;
    private readonly IAppForensicsAnalyzer _forensicsAnalyzer;
    private readonly IRuntimeAppAnalyzer _runtimeAnalyzer;
    private readonly IBehaviorAnalyzer _behaviorAnalyzer;
    private readonly IAppRemediationService _remediationService;
    private readonly IScanReportExporter _reportExporter;
    private readonly ILogger<MainViewModel> _logger;

    // --- ADB status ---
    private bool _isAdbAvailable;
    private string _adbStatusText = "Checking...";
    private string _adbVersion = string.Empty;

    // --- Device list ---
    private ObservableCollection<AndroidDeviceViewModel> _devices = new();
    private AndroidDeviceViewModel? _selectedDevice;
    private string _deviceListStatus = string.Empty;

    // --- Device info ---
    private string? _infoManufacturer;
    private string? _infoModel;
    private string? _infoAndroid;
    private string? _infoSdk;
    private string? _infoSecurityPatch;
    private string _deviceInfoStatus = string.Empty;

    // --- Package scan ---
    private PackageScanResult? _lastScanResult;
    private ScanSession? _currentSession;
    private string _packageScanStatus = string.Empty;
    private ObservableCollection<AndroidApp> _allScannedApps = new();
    private ObservableCollection<AndroidApp> _filteredApps = new();
    private AndroidApp? _selectedApp;

    // --- Filters & Search ---
    private string _searchText = string.Empty;
    private string _selectedFilterCategory = "All";

    // --- Deep Analysis & Remediation ---
    private bool _isDeepAnalysisRunning;
    private RemediationResult? _remediationPreview;
    private bool _showRemediationModal;

    // --- Metrics ---
    private int _totalAppsCount;
    private int _userAppsCount;
    private int _systemAppsCount;
    private int _safeCount;
    private int _lowCount;
    private int _mediumCount;
    private int _highCount;
    private int _criticalCount;
    private int _hiddenDetectionsCount;
    private int _adwareDetectionsCount;
    private int _sideloadDetectionsCount;

    // --- Busy / Error ---
    private bool _isBusy;
    private string _statusMessage = string.Empty;

    public bool IsAdbAvailable
    {
        get => _isAdbAvailable;
        private set => SetProperty(ref _isAdbAvailable, value);
    }

    public string AdbStatusText
    {
        get => _adbStatusText;
        private set => SetProperty(ref _adbStatusText, value);
    }

    public string AdbVersion
    {
        get => _adbVersion;
        private set => SetProperty(ref _adbVersion, value);
    }

    public ObservableCollection<AndroidDeviceViewModel> Devices
    {
        get => _devices;
        private set => SetProperty(ref _devices, value);
    }

    public AndroidDeviceViewModel? SelectedDevice
    {
        get => _selectedDevice;
        set
        {
            SetProperty(ref _selectedDevice, value);
            OnPropertyChanged(nameof(HasSelectedDevice));
            OnPropertyChanged(nameof(SelectedDeviceStatusMessage));
        }
    }

    public bool HasSelectedDevice => _selectedDevice is not null;

    public string SelectedDeviceStatusMessage => _selectedDevice?.Device.State switch
    {
        AdbDeviceState.Unauthorized =>
            "Device detected but USB debugging authorization is required on the Android device.",
        AdbDeviceState.Offline =>
            "Device is offline. Check USB connection.",
        AdbDeviceState.NoPermissions =>
            "No permissions to communicate with device. Check USB permissions.",
        _ => string.Empty,
    };

    public string DeviceListStatus
    {
        get => _deviceListStatus;
        private set => SetProperty(ref _deviceListStatus, value);
    }

    // --- Device info properties ---
    public string? InfoManufacturer
    {
        get => _infoManufacturer;
        private set => SetProperty(ref _infoManufacturer, value);
    }

    public string? InfoModel
    {
        get => _infoModel;
        private set => SetProperty(ref _infoModel, value);
    }

    public string? InfoAndroid
    {
        get => _infoAndroid;
        private set => SetProperty(ref _infoAndroid, value);
    }

    public string? InfoSdk
    {
        get => _infoSdk;
        private set => SetProperty(ref _infoSdk, value);
    }

    public string? InfoSecurityPatch
    {
        get => _infoSecurityPatch;
        private set => SetProperty(ref _infoSecurityPatch, value);
    }

    public string DeviceInfoStatus
    {
        get => _deviceInfoStatus;
        private set => SetProperty(ref _deviceInfoStatus, value);
    }

    // --- Package Scan & Risk Analysis properties ---
    public PackageScanResult? LastScanResult
    {
        get => _lastScanResult;
        private set => SetProperty(ref _lastScanResult, value);
    }

    public ScanSession? CurrentSession
    {
        get => _currentSession;
        private set => SetProperty(ref _currentSession, value);
    }

    public string PackageScanStatus
    {
        get => _packageScanStatus;
        private set => SetProperty(ref _packageScanStatus, value);
    }

    public ObservableCollection<AndroidApp> FilteredApps
    {
        get => _filteredApps;
        private set => SetProperty(ref _filteredApps, value);
    }

    public AndroidApp? SelectedApp
    {
        get => _selectedApp;
        set
        {
            SetProperty(ref _selectedApp, value);
            OnPropertyChanged(nameof(HasSelectedApp));
        }
    }

    public bool HasSelectedApp => _selectedApp is not null;

    // --- Filters & Search ---
    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value))
            {
                ApplyFilters();
            }
        }
    }

    public string SelectedFilterCategory
    {
        get => _selectedFilterCategory;
        set
        {
            if (SetProperty(ref _selectedFilterCategory, value))
            {
                ApplyFilters();
            }
        }
    }

    // --- Deep Analysis & Remediation Modal ---
    public bool IsDeepAnalysisRunning
    {
        get => _isDeepAnalysisRunning;
        private set => SetProperty(ref _isDeepAnalysisRunning, value);
    }

    public RemediationResult? RemediationPreview
    {
        get => _remediationPreview;
        private set => SetProperty(ref _remediationPreview, value);
    }

    public bool ShowRemediationModal
    {
        get => _showRemediationModal;
        set => SetProperty(ref _showRemediationModal, value);
    }

    // --- Dashboard Metrics ---
    public int TotalAppsCount { get => _totalAppsCount; private set => SetProperty(ref _totalAppsCount, value); }
    public int UserAppsCount { get => _userAppsCount; private set => SetProperty(ref _userAppsCount, value); }
    public int SystemAppsCount { get => _systemAppsCount; private set => SetProperty(ref _systemAppsCount, value); }
    public int SafeCount { get => _safeCount; private set => SetProperty(ref _safeCount, value); }
    public int LowCount { get => _lowCount; private set => SetProperty(ref _lowCount, value); }
    public int MediumCount { get => _mediumCount; private set => SetProperty(ref _mediumCount, value); }
    public int HighCount { get => _highCount; private set => SetProperty(ref _highCount, value); }
    public int CriticalCount { get => _criticalCount; private set => SetProperty(ref _criticalCount, value); }
    public int HiddenDetectionsCount { get => _hiddenDetectionsCount; private set => SetProperty(ref _hiddenDetectionsCount, value); }
    public int AdwareDetectionsCount { get => _adwareDetectionsCount; private set => SetProperty(ref _adwareDetectionsCount, value); }
    public int SideloadDetectionsCount { get => _sideloadDetectionsCount; private set => SetProperty(ref _sideloadDetectionsCount, value); }

    public bool IsBusy
    {
        get => _isBusy;
        private set => SetProperty(ref _isBusy, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetProperty(ref _statusMessage, value);
    }

    // --- Commands ---
    public ICommand RefreshDevicesCommand { get; }
    public ICommand RefreshDeviceInfoCommand { get; }
    public ICommand ScanPackagesCommand { get; }
    public ICommand RunDeepAnalysisCommand { get; }
    public ICommand DryRunRemediationCommand { get; }
    public ICommand ConfirmRemediationCommand { get; }
    public ICommand CancelRemediationCommand { get; }
    public ICommand ExportReportCommand { get; }

    public MainViewModel(
        IAdbClient adbClient,
        IDeviceInfoService deviceInfoService,
        IPackageScanner packageScanner,
        IRiskEngine riskEngine,
        IAdbLocator adbLocator,
        IAppForensicsAnalyzer forensicsAnalyzer,
        IRuntimeAppAnalyzer runtimeAnalyzer,
        IBehaviorAnalyzer behaviorAnalyzer,
        IAppRemediationService remediationService,
        IScanReportExporter reportExporter,
        ILogger<MainViewModel> logger)
    {
        _adbClient = adbClient ?? throw new ArgumentNullException(nameof(adbClient));
        _deviceInfoService = deviceInfoService ?? throw new ArgumentNullException(nameof(deviceInfoService));
        _packageScanner = packageScanner ?? throw new ArgumentNullException(nameof(packageScanner));
        _riskEngine = riskEngine ?? throw new ArgumentNullException(nameof(riskEngine));
        _adbLocator = adbLocator ?? throw new ArgumentNullException(nameof(adbLocator));
        _forensicsAnalyzer = forensicsAnalyzer ?? throw new ArgumentNullException(nameof(forensicsAnalyzer));
        _runtimeAnalyzer = runtimeAnalyzer ?? throw new ArgumentNullException(nameof(runtimeAnalyzer));
        _behaviorAnalyzer = behaviorAnalyzer ?? throw new ArgumentNullException(nameof(behaviorAnalyzer));
        _remediationService = remediationService ?? throw new ArgumentNullException(nameof(remediationService));
        _reportExporter = reportExporter ?? throw new ArgumentNullException(nameof(reportExporter));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        RefreshDevicesCommand = new AsyncRelayCommand(RefreshDevicesAsync);
        RefreshDeviceInfoCommand = new AsyncRelayCommand(
            RefreshDeviceInfoAsync,
            canExecute: () => SelectedDevice?.Device.State == AdbDeviceState.Device);
        ScanPackagesCommand = new AsyncRelayCommand(
            ScanPackagesAsync,
            canExecute: () => SelectedDevice?.Device.State == AdbDeviceState.Device);
        RunDeepAnalysisCommand = new AsyncRelayCommand(
            RunDeepAnalysisAsync,
            canExecute: () => SelectedApp != null && SelectedDevice?.Device.State == AdbDeviceState.Device);
        DryRunRemediationCommand = new AsyncRelayCommand(
            (actionStr, ct) => DryRunRemediationAsync(actionStr as string, ct),
            canExecute: () => SelectedApp != null);
        ConfirmRemediationCommand = new AsyncRelayCommand(ConfirmRemediationAsync);
        CancelRemediationCommand = new AsyncRelayCommand(ct => { ShowRemediationModal = false; return Task.CompletedTask; });
        ExportReportCommand = new AsyncRelayCommand((path, ct) => ExportReportAsync(path as string, ct), canExecute: () => CurrentSession != null);
    }

    public async Task InitialiseAsync(CancellationToken cancellationToken = default)
    {
        await CheckAdbAsync(cancellationToken);
        if (IsAdbAvailable)
            await RefreshDevicesAsync(cancellationToken);
    }

    private async Task CheckAdbAsync(CancellationToken cancellationToken)
    {
        var path = _adbLocator.TryLocate();
        if (path is null)
        {
            IsAdbAvailable = false;
            AdbStatusText = "Not Found";
            AdbVersion = string.Empty;
            StatusMessage = "ADB not found. Install Android Platform Tools.";
            return;
        }

        try
        {
            var version = await _adbClient.GetVersionAsync(cancellationToken);
            IsAdbAvailable = true;
            AdbVersion = version;
            AdbStatusText = $"Connected  (v{version})";
        }
        catch (Exception ex)
        {
            IsAdbAvailable = false;
            AdbStatusText = "Error";
            StatusMessage = $"Failed to query ADB version: {ex.Message}";
        }
    }

    private async Task RefreshDevicesAsync(CancellationToken cancellationToken)
    {
        if (!IsAdbAvailable)
        {
            await CheckAdbAsync(cancellationToken);
            if (!IsAdbAvailable) return;
        }

        IsBusy = true;
        StatusMessage = "Scanning for devices...";
        DeviceListStatus = string.Empty;

        try
        {
            var devices = await _adbClient.GetDevicesAsync(cancellationToken);
            var vms = devices.Select(d => new AndroidDeviceViewModel(d)).ToList();
            Devices = new ObservableCollection<AndroidDeviceViewModel>(vms);

            if (devices.Count == 0)
            {
                DeviceListStatus = "No Android device detected.\nEnable USB Debugging and authorize this computer.";
                SelectedDevice = null;
                ClearDeviceInfo();
            }
            else
            {
                DeviceListStatus = string.Empty;
                SelectedDevice = Devices.FirstOrDefault();
            }

            StatusMessage = devices.Count == 0
                ? "No devices found."
                : $"{devices.Count} device(s) detected.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error scanning devices: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RefreshDeviceInfoAsync(CancellationToken cancellationToken)
    {
        var device = SelectedDevice;
        if (device is null || device.Device.State != AdbDeviceState.Device) return;

        IsBusy = true;
        DeviceInfoStatus = "Reading device information...";

        try
        {
            var info = await _deviceInfoService.GetDeviceInfoAsync(device.Serial, cancellationToken);
            InfoManufacturer  = info.Manufacturer  ?? "—";
            InfoModel         = info.Model         ?? "—";
            InfoAndroid       = info.AndroidVersion ?? "—";
            InfoSdk           = info.SdkVersion    ?? "—";
            InfoSecurityPatch = info.SecurityPatch  ?? "—";
            DeviceInfoStatus  = string.Empty;
            StatusMessage = "Device info refreshed.";
        }
        catch (Exception ex)
        {
            DeviceInfoStatus = "Failed to read device info.";
            StatusMessage = $"Error reading device info: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ScanPackagesAsync(CancellationToken cancellationToken)
    {
        var device = SelectedDevice;
        if (device is null || device.Device.State != AdbDeviceState.Device)
        {
            PackageScanStatus = "No connected device selected for package scan.";
            return;
        }

        IsBusy = true;
        var startedAt = DateTimeOffset.UtcNow;
        PackageScanStatus = "Quick scanning packages and running Risk Engine...";
        StatusMessage = $"Quick scanning packages for {device.Serial}...";

        try
        {
            var scanResult = await _packageScanner.ScanAsync(device.Serial, cancellationToken);
            LastScanResult = scanResult;

            // In-Memory Quick Scan Risk Analysis
            var analyzedApps = _riskEngine.AnalyzeAll(scanResult.Apps)
                .OrderByDescending(a => a.RiskAnalysis?.RiskScore ?? 0)
                .ThenBy(a => a.PackageName)
                .ToList();

            _allScannedApps = new ObservableCollection<AndroidApp>(analyzedApps);
            ApplyFilters();
            SelectedApp = FilteredApps.FirstOrDefault();

            // Calculate Metrics
            TotalAppsCount = analyzedApps.Count;
            UserAppsCount = analyzedApps.Count(a => a.Origin == AppOrigin.User);
            SystemAppsCount = analyzedApps.Count(a => a.Origin == AppOrigin.System);

            SafeCount = analyzedApps.Count(a => a.RiskAnalysis?.RiskLevel == RiskLevel.Safe);
            LowCount = analyzedApps.Count(a => a.RiskAnalysis?.RiskLevel == RiskLevel.Low);
            MediumCount = analyzedApps.Count(a => a.RiskAnalysis?.RiskLevel == RiskLevel.Medium);
            HighCount = analyzedApps.Count(a => a.RiskAnalysis?.RiskLevel == RiskLevel.High);
            CriticalCount = analyzedApps.Count(a => a.RiskAnalysis?.RiskLevel == RiskLevel.Critical);

            var detections = analyzedApps.SelectMany(a => a.RiskAnalysis?.Detections ?? Array.Empty<DetectionResult>()).ToList();
            HiddenDetectionsCount = detections.Count(d => d.Type == DetectionType.HiddenApp);
            AdwareDetectionsCount = detections.Count(d => d.Type == DetectionType.AdwareSuspicion);
            SideloadDetectionsCount = detections.Count(d => d.Type == DetectionType.SuspiciousSideload);

            var dist = new Dictionary<RiskLevel, int>
            {
                [RiskLevel.Safe] = SafeCount,
                [RiskLevel.Low] = LowCount,
                [RiskLevel.Medium] = MediumCount,
                [RiskLevel.High] = HighCount,
                [RiskLevel.Critical] = CriticalCount
            };

            CurrentSession = new ScanSession(
                SessionId: Guid.NewGuid(),
                DeviceSerial: device.Serial,
                DeviceModel: InfoModel ?? device.Model ?? "Android Device",
                AndroidVersion: InfoAndroid ?? "Unknown",
                ScanStartedAt: startedAt,
                ScanCompletedAt: DateTimeOffset.UtcNow,
                PackageCount: TotalAppsCount,
                RiskDistribution: dist,
                DetectionCount: detections.Count,
                Apps: analyzedApps
            );

            PackageScanStatus = $"Scanned {TotalAppsCount} packages ({UserAppsCount} User, {SystemAppsCount} System). High/Critical Risk: {HighCount + CriticalCount}.";
            StatusMessage = "Quick Scan & Risk Analysis complete.";
        }
        catch (Exception ex)
        {
            PackageScanStatus = "Package scan failed.";
            StatusMessage = $"Error during package scan: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RunDeepAnalysisAsync(CancellationToken cancellationToken)
    {
        var app = SelectedApp;
        var device = SelectedDevice;
        if (app == null || device == null || device.Device.State != AdbDeviceState.Device) return;

        IsDeepAnalysisRunning = true;
        StatusMessage = $"Running Deep Analysis (APK Forensics + Runtime Visibility + Behavior Correlation) for {app.PackageName}...";

        try
        {
            var forensicTask = _forensicsAnalyzer.AnalyzeAsync(device.Serial, app, cancellationToken);
            var runtimeTask = _runtimeAnalyzer.AnalyzeRuntimeAsync(device.Serial, app, cancellationToken);
            var behaviorTask = _behaviorAnalyzer.AnalyzeAsync(device.Serial, app, cancellationToken);

            await Task.WhenAll(forensicTask, runtimeTask, behaviorTask).ConfigureAwait(true);

            var forensicReport = await forensicTask;
            var runtimeReport = await runtimeTask;
            var behaviorReport = await behaviorTask;

            // Correlate static risk, forensic, and dynamic behavior
            var correlatedAssessment = BehaviorCorrelationEngine.Assess(app, app.RiskAnalysis, behaviorReport, forensicReport);

            var updatedAnalysis = app.RiskAnalysis != null
                ? app.RiskAnalysis with
                {
                    RiskScore = correlatedAssessment.FinalRiskScore,
                    RiskLevel = correlatedAssessment.RiskLevel,
                    Evidences = correlatedAssessment.Evidences,
                    Confidence = correlatedAssessment.Confidence,
                    EvidenceQuality = correlatedAssessment.EvidenceQuality
                }
                : null;

            var updatedApp = app with
            {
                ForensicReport = forensicReport,
                RuntimeReport = runtimeReport,
                BehaviorReport = behaviorReport,
                CorrelatedAssessment = correlatedAssessment,
                RiskAnalysis = updatedAnalysis
            };

            int index = _allScannedApps.IndexOf(app);
            if (index >= 0)
            {
                _allScannedApps[index] = updatedApp;
            }
            ApplyFilters();
            SelectedApp = updatedApp;

            StatusMessage = $"Deep Analysis & Behavior Correlation complete for {app.PackageName}.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Deep Analysis failed: {ex.Message}";
        }
        finally
        {
            IsDeepAnalysisRunning = false;
        }
    }

    private async Task DryRunRemediationAsync(string? actionStr, CancellationToken cancellationToken)
    {
        if (SelectedApp == null || string.IsNullOrWhiteSpace(actionStr)) return;
        if (!Enum.TryParse<RemediationAction>(actionStr, true, out var action)) return;

        var deviceSerial = SelectedDevice?.Serial ?? "emulator-5554";

        var result = await _remediationService.ExecuteActionAsync(deviceSerial, SelectedApp, action, dryRun: true, cancellationToken);
        RemediationPreview = result;
        ShowRemediationModal = true;
    }

    private async Task ConfirmRemediationAsync(CancellationToken cancellationToken)
    {
        if (RemediationPreview == null || SelectedApp == null || SelectedDevice == null)
        {
            ShowRemediationModal = false;
            return;
        }

        ShowRemediationModal = false;
        IsBusy = true;
        StatusMessage = $"Executing remediation {RemediationPreview.Action} on {SelectedApp.PackageName}...";

        try
        {
            var actualResult = await _remediationService.ExecuteActionAsync(
                SelectedDevice.Serial,
                SelectedApp,
                RemediationPreview.Action,
                dryRun: false,
                cancellationToken);

            RemediationPreview = actualResult;
            if (actualResult.Success)
            {
                StatusMessage = $"Remediation SUCCESS: {actualResult.Action} completed for {actualResult.PackageName}.";
                await ScanPackagesAsync(cancellationToken);
            }
            else
            {
                StatusMessage = $"Remediation FAILED: {actualResult.Error}";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Remediation execution error: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task ExportReportAsync(string? destinationFilePath, CancellationToken cancellationToken)
    {
        if (CurrentSession == null) return;
        var filePath = destinationFilePath;
        if (string.IsNullOrWhiteSpace(filePath))
        {
            filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"DroidGuard_Report_{CurrentSession.DeviceSerial}_{DateTime.Now:yyyyMMdd_HHmmss}.json");
        }

        try
        {
            await _reportExporter.ExportJsonAsync(CurrentSession, filePath, cancellationToken);
            StatusMessage = $"Report successfully exported to {filePath}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to export report: {ex.Message}";
        }
    }

    private void ApplyFilters()
    {
        IEnumerable<AndroidApp> query = _allScannedApps;

        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var search = SearchText.Trim();
            query = query.Where(a =>
                a.PackageName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                (a.Label != null && a.Label.Contains(search, StringComparison.OrdinalIgnoreCase)));
        }

        query = SelectedFilterCategory switch
        {
            "User" => query.Where(a => a.Origin == AppOrigin.User),
            "System" => query.Where(a => a.Origin == AppOrigin.System),
            "Safe" => query.Where(a => a.RiskAnalysis?.RiskLevel == RiskLevel.Safe),
            "Low" => query.Where(a => a.RiskAnalysis?.RiskLevel == RiskLevel.Low),
            "Medium" => query.Where(a => a.RiskAnalysis?.RiskLevel == RiskLevel.Medium),
            "High" => query.Where(a => a.RiskAnalysis?.RiskLevel == RiskLevel.High),
            "Critical" => query.Where(a => a.RiskAnalysis?.RiskLevel == RiskLevel.Critical),
            "Hidden" => query.Where(a => a.RiskAnalysis?.Detections.Any(d => d.Type == DetectionType.HiddenApp) == true),
            "Adware" => query.Where(a => a.RiskAnalysis?.Detections.Any(d => d.Type == DetectionType.AdwareSuspicion) == true),
            "Sideload" => query.Where(a => a.RiskAnalysis?.Evidences.Any(e => e.FactorId == "SIDELOAD_UNKNOWN_INSTALLER") == true),
            _ => query
        };

        FilteredApps = new ObservableCollection<AndroidApp>(query);
        if (SelectedApp != null && !FilteredApps.Contains(SelectedApp))
        {
            SelectedApp = FilteredApps.FirstOrDefault();
        }
    }

    private void ClearDeviceInfo()
    {
        InfoManufacturer  = null;
        InfoModel         = null;
        InfoAndroid       = null;
        InfoSdk           = null;
        InfoSecurityPatch = null;
        DeviceInfoStatus  = string.Empty;
        LastScanResult    = null;
        CurrentSession    = null;
        PackageScanStatus = string.Empty;
        _allScannedApps.Clear();
        FilteredApps.Clear();
        SelectedApp       = null;
    }
}
