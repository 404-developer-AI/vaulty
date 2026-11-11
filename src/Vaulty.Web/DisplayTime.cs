using System.Globalization;
using Vaulty.Infrastructure.Platform;
using Vaulty.Infrastructure.Storage;

namespace Vaulty.Web;

/// <summary>
/// Times as the interface shows them: in the organization's display time zone, relative ("2 min ago") within 24 hours and
/// absolute after that. Snapshot names always carry the absolute date and time.
/// </summary>
public sealed class DisplayTime(PlatformSettings settings, TimeProvider clock)
{
    private TimeZoneInfo? _zone;

    public async Task<DisplayTime> LoadAsync()
    {
        if (_zone is not null) return this;
        var display = await settings.GetAsync<DisplaySettings>(DisplaySettings.SettingKey) ?? DisplaySettings.Default;
        _zone = TimeZones.Resolve(display.TimeZone);
        return this;
    }

    private DateTimeOffset Local(DateTimeOffset value) => TimeZoneInfo.ConvertTime(value, _zone ?? TimeZoneInfo.Utc);

    /// <summary>"9 Nov 2026, 14:00".</summary>
    public string Absolute(DateTimeOffset? value) =>
        value is { } v ? Local(v).ToString("d MMM yyyy, HH:mm", CultureInfo.InvariantCulture) : "";

    /// <summary>A moment ahead, such as an expected finish: "14:35" today, "12 Nov, 02:10" on another day.</summary>
    public string Ahead(DateTimeOffset value)
    {
        var local = Local(value);
        return local.Date == Local(clock.GetUtcNow()).Date
            ? local.ToString("HH:mm", CultureInfo.InvariantCulture)
            : local.ToString("d MMM, HH:mm", CultureInfo.InvariantCulture);
    }

    public string Relative(DateTimeOffset? value)
    {
        if (value is not { } v) return "";
        var age = clock.GetUtcNow() - v;
        if (age < TimeSpan.Zero || age >= TimeSpan.FromHours(24)) return Absolute(v);
        if (age < TimeSpan.FromMinutes(1)) return "just now";
        if (age < TimeSpan.FromHours(1)) return $"{(int)age.TotalMinutes} min ago";
        return $"{(int)age.TotalHours} h ago";
    }
}
