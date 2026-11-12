using System.Windows;
using System.Windows.Threading;

namespace Trowser;

/// <summary>
/// Keeps keyboard focus in Trowser when a modeless owned dialog closes.
/// Without this, Alt+Tab away and back then closing the dialog can return focus to the other app.
/// </summary>
internal static class ModelessDialogFocus
{
    public static void WireOwnerFocusRestore(Window dialog)
    {
        dialog.Closed += (_, _) =>
        {
            var owner = dialog.Owner;
            if (owner == null)
                return;

            owner.Dispatcher.BeginInvoke(() =>
            {
                if (owner.IsVisible)
                    owner.Activate();
            }, DispatcherPriority.Input);
        };
    }
}
