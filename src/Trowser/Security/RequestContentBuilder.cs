using System.Net.Http;
using System.Text;

namespace Trowser.Security;

/// <summary>
/// Builds an HTTP body. An explicit empty <c>Content-Type</c> means "send no Content-Type header"
/// (parser-differential tests). A missing header uses <c>fallbackMediaType</c>.
/// </summary>
internal static class RequestContentBuilder
{
    public static HttpContent FromText(string body, string? contentType, string? fallbackMediaType)
    {
        if (IsExplicitlyEmpty(contentType))
            return new ByteArrayContent(Encoding.UTF8.GetBytes(body));

        var chosen = string.IsNullOrWhiteSpace(contentType) ? fallbackMediaType : contentType;
        if (string.IsNullOrWhiteSpace(chosen))
            return new ByteArrayContent(Encoding.UTF8.GetBytes(body));

        var mediaType = chosen.Split(';')[0].Trim();
        if (mediaType.Length == 0)
            return new ByteArrayContent(Encoding.UTF8.GetBytes(body));

        return new StringContent(body, Encoding.UTF8, mediaType);
    }

    /// <summary>True when the caller set Content-Type and the media type is blank.</summary>
    public static bool IsExplicitlyEmpty(string? contentType) =>
        contentType != null && contentType.Split(';')[0].Trim().Length == 0;
}
