using System.ComponentModel;
using System.Windows;

namespace Trowser;

/// <summary>
/// Owned modeless dialogs: Windows keeps an owned window above its owner (and only its owner), so
/// do not set <see cref="Window.Topmost"/> — that would float the dialog over other applications.
/// When an active owned window is destroyed, Windows may hand the foreground to another
/// application; activating the owner while the dialog still exists keeps focus in Trowser.
/// </summary>
internal static class ModelessDialogFocus
{
    public static void WireOwnerFocusRestore(Window dialog)
    {
        dialog.Closing += (_, e) => ActivateOwnerIfActive(dialog, e);
    }

    private static void ActivateOwnerIfActive(Window dialog, CancelEventArgs e)
    {
        if (e.Cancel || !dialog.IsActive)
            return;

        var owner = dialog.Owner;
        if (owner is { IsVisible: true })
            owner.Activate();
    }
}
