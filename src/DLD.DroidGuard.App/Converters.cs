using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace DLD.DroidGuard.App;

/// <summary>
/// Central converter registry. Static singletons used in XAML bindings.
/// </summary>
public static class Converters
{
    public static readonly EmptyStringToVisibilityConverter EmptyStringToHiddenConverter
        = new(Visibility.Hidden);

    public static readonly EmptyStringToVisibilityConverter EmptyStringToVisibleConverter
        = new(Visibility.Visible, invert: true);

    public static readonly BoolToVisibilityConverter BoolToVisibleConverter
        = new(Visibility.Visible, Visibility.Collapsed);

    public static readonly NotNullToVisibilityConverter NotNullToVisibleConverter
        = new();

    public static readonly NotNullToBoolConverter NotNullToBoolConverter
        = new();
}

/// <summary>
/// Converts boolean to Visibility.
/// </summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    private readonly Visibility _whenTrue;
    private readonly Visibility _whenFalse;

    public BoolToVisibilityConverter(Visibility whenTrue = Visibility.Visible, Visibility whenFalse = Visibility.Collapsed)
    {
        _whenTrue = whenTrue;
        _whenFalse = whenFalse;
    }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool b)
        {
            return b ? _whenTrue : _whenFalse;
        }
        return _whenFalse;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Returns Visible when value is not null, Collapsed when null.
/// </summary>
public sealed class NotNullToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value != null ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Returns true when value is not null, false when null.
/// </summary>
public sealed class NotNullToBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value != null;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Returns one Visibility when a string is non-empty, another when empty.
/// </summary>
public sealed class EmptyStringToVisibilityConverter : IValueConverter
{
    private readonly Visibility _whenNonEmpty;
    private readonly Visibility _whenEmpty;

    public EmptyStringToVisibilityConverter(Visibility whenNonEmpty, bool invert = false)
    {
        if (!invert)
        {
            _whenNonEmpty = whenNonEmpty;
            _whenEmpty    = Visibility.Collapsed;
        }
        else
        {
            // Invert: show when empty, hide when non-empty
            _whenNonEmpty = Visibility.Collapsed;
            _whenEmpty    = whenNonEmpty;
        }
    }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value == null) return _whenEmpty;
        var str = value as string;
        return string.IsNullOrEmpty(str) ? _whenEmpty : _whenNonEmpty;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
