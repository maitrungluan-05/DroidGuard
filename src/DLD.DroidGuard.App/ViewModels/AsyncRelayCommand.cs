using System.Windows.Input;

namespace DLD.DroidGuard.App.ViewModels;

/// <summary>
/// ICommand implementation for async operations.
/// Prevents re-entrant execution while a command is running.
/// </summary>
public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<object?, CancellationToken, Task> _execute;
    private readonly Func<bool>? _canExecute;
    private CancellationTokenSource? _cts;
    private bool _isExecuting;

    public AsyncRelayCommand(
        Func<CancellationToken, Task> execute,
        Func<bool>? canExecute = null)
        : this((_, ct) => execute(ct), canExecute)
    {
    }

    public AsyncRelayCommand(
        Func<object?, CancellationToken, Task> execute,
        Func<bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter)
        => !_isExecuting && (_canExecute?.Invoke() ?? true);

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter)) return;

        _isExecuting = true;
        RaiseCanExecuteChanged();

        _cts = new CancellationTokenSource();
        try
        {
            await _execute(parameter, _cts.Token);
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            _isExecuting = false;
            RaiseCanExecuteChanged();
        }
    }

    public void Cancel() => _cts?.Cancel();

    public void RaiseCanExecuteChanged()
        => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
