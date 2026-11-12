namespace Trowser.Pointers;

/// <summary>A rectangle in plain doubles, deliberately free of any WPF dependency so the mapping
/// math stays unit-testable without a UI thread. The WPF layer converts to <c>System.Windows.Rect</c>
/// at the boundary.</summary>
public readonly record struct MapRect(double X, double Y, double Width, double Height);

/// <summary>
/// P2 spike: the whole risk of the live pointer overlay is mapping page CSS pixels to screen DIPs
/// across WebView2 <c>ZoomFactor</c>, monitor DPI, the control's offset within the window, and scroll.
/// This isolates that math as pure functions so it can be proven in tests before the overlay window
/// is wired up.
///
/// Coordinate facts this relies on:
/// <list type="bullet">
/// <item><c>getBoundingClientRect()</c> returns CSS px relative to the viewport (already scroll-adjusted).</item>
/// <item>At <c>ZoomFactor == 1</c>, 1 CSS px renders as 1 WPF DIP regardless of monitor DPI — WebView2
/// applies the OS scale to physical pixels, but layout px equal DIPs. So CSS px × zoom = DIPs.</item>
/// <item>WPF <c>Visual.PointToScreen</c> returns physical device pixels; dividing by
/// <c>DpiScale.PixelsPerDip</c> yields DIPs, the same space as <c>Window.Left/Top</c>.</item>
/// </list>
/// </summary>
public static class PointerCoordinateMapper
{
    /// <summary>Convert a device-pixel measure to DIPs.</summary>
    public static double DeviceToDip(double devicePx, double pixelsPerDip) =>
        pixelsPerDip <= 0 ? devicePx : devicePx / pixelsPerDip;

    /// <summary>
    /// Map a viewport-relative page rect (CSS px) into the overlay window's local DIP space, where the
    /// overlay window is positioned exactly over the WebView host control. Only the zoom factor applies.
    /// </summary>
    public static MapRect PageToOverlay(MapRect pageCss, double zoomFactor)
    {
        var z = zoomFactor <= 0 ? 1.0 : zoomFactor;
        return new MapRect(pageCss.X * z, pageCss.Y * z, pageCss.Width * z, pageCss.Height * z);
    }

    /// <summary>
    /// Full composition to absolute screen DIPs: host control origin (device px) → DIPs, plus the
    /// zoom-scaled page rect. Kept for reference and for testing the end-to-end mapping; the overlay
    /// itself prefers <see cref="PageToOverlay"/> because it positions the window at the host origin.
    /// </summary>
    public static MapRect PageToScreenDips(
        double hostOriginDeviceX, double hostOriginDeviceY, double pixelsPerDip, double zoomFactor, MapRect pageCss)
    {
        var ox = DeviceToDip(hostOriginDeviceX, pixelsPerDip);
        var oy = DeviceToDip(hostOriginDeviceY, pixelsPerDip);
        var local = PageToOverlay(pageCss, zoomFactor);
        return new MapRect(ox + local.X, oy + local.Y, local.Width, local.Height);
    }

    /// <summary>
    /// True when a mapped rect has any part inside the host viewport (width×height in DIPs). Used to
    /// decide whether a pointer is on-screen or should be parked as an off-screen/stale marker.
    /// </summary>
    public static bool IntersectsViewport(MapRect overlayLocal, double viewportWidthDip, double viewportHeightDip) =>
        overlayLocal.X + overlayLocal.Width > 0
        && overlayLocal.Y + overlayLocal.Height > 0
        && overlayLocal.X < viewportWidthDip
        && overlayLocal.Y < viewportHeightDip;
}
