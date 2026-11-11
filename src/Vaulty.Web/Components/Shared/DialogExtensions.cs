using MudBlazor;

namespace Vaulty.Web.Components.Shared;

public static class DialogExtensions
{
    /// <summary>Asks for confirmation with <see cref="ConfirmDialog"/>; true only when the user confirmed.</summary>
    public static async Task<bool> ConfirmAsync(this IDialogService dialogs, string title, string message, string confirmText,
        bool danger = false, bool stepUp = false, string? typeToConfirm = null, IReadOnlyList<string>? details = null, string cancelText = "Cancel")
    {
        ArgumentNullException.ThrowIfNull(dialogs);
        var parameters = new DialogParameters<ConfirmDialog>
        {
            { d => d.Title, title },
            { d => d.Message, message },
            { d => d.ConfirmText, confirmText },
            { d => d.CancelText, cancelText },
            { d => d.Danger, danger },
            { d => d.StepUp, stepUp },
            { d => d.TypeToConfirm, typeToConfirm },
            { d => d.Details, details },
        };
        var dialog = await dialogs.ShowAsync<ConfirmDialog>(title, parameters,
            new DialogOptions { MaxWidth = MaxWidth.Small, CloseOnEscapeKey = true, NoHeader = false, CloseButton = false });
        var result = await dialog.Result;
        return result is { Canceled: false, Data: true };
    }
}
