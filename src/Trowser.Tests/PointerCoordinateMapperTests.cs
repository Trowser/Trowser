using Trowser.Pointers;
using Xunit;

namespace Trowser.Tests;

public class PointerCoordinateMapperTests
{
    [Fact]
    public void device_to_dip_divides_by_scale()
    {
        Assert.Equal(100, PointerCoordinateMapper.DeviceToDip(150, 1.5), 3);
        Assert.Equal(200, PointerCoordinateMapper.DeviceToDip(200, 1.0), 3);
    }

    [Fact]
    public void device_to_dip_guards_zero_scale()
    {
        Assert.Equal(150, PointerCoordinateMapper.DeviceToDip(150, 0), 3);
    }

    [Fact]
    public void page_to_overlay_is_identity_at_zoom_one()
    {
        var r = PointerCoordinateMapper.PageToOverlay(new MapRect(10, 20, 30, 40), 1.0);
        Assert.Equal(new MapRect(10, 20, 30, 40), r);
    }

    [Fact]
    public void page_to_overlay_scales_by_zoom()
    {
        var r = PointerCoordinateMapper.PageToOverlay(new MapRect(10, 20, 30, 40), 1.5);
        Assert.Equal(new MapRect(15, 30, 45, 60), r);
    }

    [Fact]
    public void page_to_overlay_guards_nonpositive_zoom()
    {
        var r = PointerCoordinateMapper.PageToOverlay(new MapRect(10, 20, 30, 40), 0);
        Assert.Equal(new MapRect(10, 20, 30, 40), r);
    }

    [Fact]
    public void page_to_screen_composes_origin_zoom_and_dpi()
    {
        // Host control's top-left is 300 device px right, 150 device px down; monitor at 150% DPI
        // means origin is (200,100) DIPs. A page rect at CSS (10,20) with zoom 1.5 lands at
        // (200 + 15, 100 + 30) = (215, 130), sized 45×60.
        var r = PointerCoordinateMapper.PageToScreenDips(
            hostOriginDeviceX: 300, hostOriginDeviceY: 150,
            pixelsPerDip: 1.5, zoomFactor: 1.5,
            pageCss: new MapRect(10, 20, 30, 40));

        Assert.Equal(215, r.X, 3);
        Assert.Equal(130, r.Y, 3);
        Assert.Equal(45, r.Width, 3);
        Assert.Equal(60, r.Height, 3);
    }

    [Fact]
    public void intersects_viewport_true_when_on_screen()
    {
        Assert.True(PointerCoordinateMapper.IntersectsViewport(new MapRect(10, 10, 50, 50), 800, 600));
    }

    [Fact]
    public void intersects_viewport_false_when_scrolled_above()
    {
        // Element fully above the viewport (negative Y beyond its height).
        Assert.False(PointerCoordinateMapper.IntersectsViewport(new MapRect(10, -80, 50, 50), 800, 600));
    }

    [Fact]
    public void intersects_viewport_false_when_below()
    {
        Assert.False(PointerCoordinateMapper.IntersectsViewport(new MapRect(10, 700, 50, 50), 800, 600));
    }

    [Fact]
    public void intersects_viewport_true_when_partially_visible()
    {
        // Straddles the top edge — still partly visible.
        Assert.True(PointerCoordinateMapper.IntersectsViewport(new MapRect(10, -20, 50, 50), 800, 600));
    }
}
