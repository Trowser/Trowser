using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace Trowser.Automation;

/// <summary>
/// Pixel-level image comparison for visual regression testing.
/// Uses WPF imaging — all public methods must run on the WPF dispatcher (STA thread).
/// </summary>
public static class ImageComparer
{
    public record CompareResult(
        byte[] DiffImagePng,
        double DiffPercent,
        int ChangedPixels,
        int TotalPixels,
        int Width,
        int Height
    );

    /// <summary>
    /// Compare two images pixel-by-pixel. Generates a diff image where changed pixels
    /// are highlighted in red and unchanged pixels are dimmed.
    /// </summary>
    /// <param name="beforeBytes">PNG or JPEG bytes of the "before" image.</param>
    /// <param name="afterBytes">PNG or JPEG bytes of the "after" image.</param>
    /// <param name="threshold">Per-channel difference threshold (0-255). Lower = more sensitive.</param>
    public static CompareResult Compare(byte[] beforeBytes, byte[] afterBytes, int threshold = 30)
    {
        var (px1, w1, h1) = DecodeToBgra32(beforeBytes);
        var (px2, w2, h2) = DecodeToBgra32(afterBytes);

        int w = Math.Max(w1, w2);
        int h = Math.Max(h1, h2);

        var diff = new byte[w * h * 4];
        int changed = 0;

        int minX = w, minY = h, maxX = 0, maxY = 0;

        for (int y = 0; y < h; y++)
        {
            for (int x = 0; x < w; x++)
            {
                int di = (y * w + x) * 4;

                GetPixel(px1, w1, h1, x, y, out var b1, out var g1, out var r1, out var a1);
                GetPixel(px2, w2, h2, x, y, out var b2, out var g2, out var r2, out var a2);

                bool isDiff = Math.Abs(r1 - r2) > threshold ||
                              Math.Abs(g1 - g2) > threshold ||
                              Math.Abs(b1 - b2) > threshold;

                if (isDiff)
                {
                    // Red-tinted highlight on the "after" pixel
                    diff[di]     = (byte)(b2 / 4);
                    diff[di + 1] = (byte)(g2 / 4);
                    diff[di + 2] = (byte)Math.Min(255, r2 / 3 + 180);
                    diff[di + 3] = 255;
                    changed++;

                    if (x < minX) minX = x;
                    if (y < minY) minY = y;
                    if (x > maxX) maxX = x;
                    if (y > maxY) maxY = y;
                }
                else
                {
                    // Dimmed unchanged pixel from "after" image
                    diff[di]     = (byte)(b2 * 6 / 10);
                    diff[di + 1] = (byte)(g2 * 6 / 10);
                    diff[di + 2] = (byte)(r2 * 6 / 10);
                    diff[di + 3] = a2;
                }
            }
        }

        var diffPng = EncodePng(diff, w, h);
        int total = w * h;
        double percent = total > 0 ? Math.Round((double)changed / total * 100, 2) : 0;

        return new CompareResult(diffPng, percent, changed, total, w, h);
    }

    /// <summary>Resize an image to fit within maxWidth, preserving aspect ratio.</summary>
    public static byte[] Resize(byte[] imageBytes, int maxWidth, string outputFormat = "png", int jpegQuality = 80)
    {
        var (pixels, w, h) = DecodeToBgra32(imageBytes);
        if (w <= maxWidth)
            return outputFormat == "jpeg" ? EncodeJpeg(pixels, w, h, jpegQuality) : imageBytes;

        double scale = (double)maxWidth / w;
        int newW = maxWidth;
        int newH = (int)(h * scale);

        var source = BitmapSource.Create(w, h, 96, 96, PixelFormats.Bgra32, null, pixels, w * 4);
        var scaled = new TransformedBitmap(source, new ScaleTransform(scale, scale));
        var frame = BitmapFrame.Create(scaled);

        if (outputFormat == "jpeg")
        {
            var encoder = new JpegBitmapEncoder { QualityLevel = jpegQuality };
            encoder.Frames.Add(frame);
            using var ms = new MemoryStream();
            encoder.Save(ms);
            return ms.ToArray();
        }
        else
        {
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(frame);
            using var ms = new MemoryStream();
            encoder.Save(ms);
            return ms.ToArray();
        }
    }

    private static (byte[] pixels, int width, int height) DecodeToBgra32(byte[] imageBytes)
    {
        using var ms = new MemoryStream(imageBytes);
        var decoder = BitmapDecoder.Create(ms, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
        var frame = decoder.Frames[0];

        BitmapSource source;
        if (frame.Format != PixelFormats.Bgra32)
            source = new FormatConvertedBitmap(frame, PixelFormats.Bgra32, null, 0);
        else
            source = frame;

        int stride = source.PixelWidth * 4;
        var pixels = new byte[stride * source.PixelHeight];
        source.CopyPixels(pixels, stride, 0);
        return (pixels, source.PixelWidth, source.PixelHeight);
    }

    private static void GetPixel(byte[] pixels, int w, int h, int x, int y,
        out byte b, out byte g, out byte r, out byte a)
    {
        if (x >= w || y >= h) { b = g = r = a = 0; return; }
        int i = (y * w + x) * 4;
        b = pixels[i]; g = pixels[i + 1]; r = pixels[i + 2]; a = pixels[i + 3];
    }

    private static byte[] EncodePng(byte[] bgra32, int width, int height)
    {
        var bmp = BitmapSource.Create(width, height, 96, 96, PixelFormats.Bgra32, null, bgra32, width * 4);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bmp));
        using var ms = new MemoryStream();
        encoder.Save(ms);
        return ms.ToArray();
    }

    private static byte[] EncodeJpeg(byte[] bgra32, int width, int height, int quality)
    {
        var bmp = BitmapSource.Create(width, height, 96, 96, PixelFormats.Bgra32, null, bgra32, width * 4);
        var encoder = new JpegBitmapEncoder { QualityLevel = quality };
        encoder.Frames.Add(BitmapFrame.Create(bmp));
        using var ms = new MemoryStream();
        encoder.Save(ms);
        return ms.ToArray();
    }
}
