using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Windows.Threading;
using System.Xml.Linq;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Orchestration.Rendering;
using Trowser.Security.Workflow;
using Trowser.Security.WebSocket;
using Trowser.Seo;
using Trowser.SessionLog;

namespace Trowser.Api;

/// <summary>
/// JSON request/response helpers shared by the REST handlers.
/// </summary>
public partial class TrowserApiServer
{
    #region JSON Helpers

    private static bool GetAnonymousBool(object o, string propertyName)
    {
        var prop = o.GetType().GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance);
        return prop?.GetValue(o) is true;
    }

    private static Dictionary<string, object?> SeoStructuredDataItemForApi(SeoJsonLdBlock b)
    {
        if (b.Valid)
        {
            object? dataObj = b.Data.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null
                ? null
                : JsonSerializer.Deserialize<object>(b.Data.GetRawText());
            return new Dictionary<string, object?>
            {
                ["valid"] = true,
                ["data"] = dataObj,
                ["raw"] = null,
                ["error"] = null
            };
        }

        return new Dictionary<string, object?>
        {
            ["valid"] = false,
            ["data"] = null,
            ["raw"] = b.Raw,
            ["error"] = b.Error
        };
    }

    private static bool IsAuditModuleCancelled(object result) =>
        result.GetType().GetProperty("cancelled")?.GetValue(result) is true;

    private static object AuditModuleSkipped() => new { skipped = true, isClean = (bool?)null };

    /// <summary>Runs a sub-audit, returning an error payload if it throws.</summary>
    private async Task<object> SafeRunAuditAsync(
        Func<Task<object>> audit,
        string auditName,
        List<object>? moduleTimings = null)
    {
        _context.OperationCancellation.ThrowIfCancellationRequested();
        var sw = Stopwatch.StartNew();
        try
        {
            var result = await audit();
            moduleTimings?.Add(new { module = auditName, elapsedMs = sw.ElapsedMilliseconds, ok = true });
            return result;
        }
        catch (OperationCanceledException) when (_context.OperationCancellation.IsCancellationRequested)
        {
            moduleTimings?.Add(new
            {
                module = auditName,
                elapsedMs = sw.ElapsedMilliseconds,
                ok = false,
                cancelled = true
            });
            return new { cancelled = true, isClean = (bool?)null, error = $"{auditName} cancelled." };
        }
        catch (Exception ex)
        {
            moduleTimings?.Add(new { module = auditName, elapsedMs = sw.ElapsedMilliseconds, ok = false, error = ex.Message });
            return new { error = $"{auditName} failed: {ex.Message}", isClean = (bool?)null };
        }
    }

    private sealed class AuditAllProgress
    {
        public bool Partial { get; set; }
    }

    private async Task<object> AuditAllModuleAsync(
        Func<Task<object>> audit,
        string auditName,
        List<object> moduleTimings,
        AuditAllProgress progress)
    {
        if (progress.Partial)
            return AuditModuleSkipped();
        var result = await SafeRunAuditAsync(audit, auditName, moduleTimings);
        if (IsAuditModuleCancelled(result))
            progress.Partial = true;
        return result;
    }

    /// <summary>Effective query string for the current request (supports internal scenario dispatch).</summary>
    private NameValueCollection ApiQuery(HttpListenerRequest request) =>
        _scenarioQueryOverride ?? request.QueryString;

    private async Task<JsonBody> ReadJsonBody(HttpListenerRequest request)
    {
        string? json = _scenarioBodyOverride ?? _preReadBody.Value;
        if (json == null)
        {
            if (request.ContentLength64 == 0)
                return new JsonBody(null);

            // Always use UTF-8 for JSON bodies (RFC 8259). request.ContentEncoding may
            // default to the system codepage when no charset is specified in Content-Type,
            // which causes valid JSON from PowerShell and other clients to be garbled.
            using var reader = new StreamReader(request.InputStream, Encoding.UTF8);
            json = await reader.ReadToEndAsync();
        }

        if (string.IsNullOrWhiteSpace(json))
            return new JsonBody(null);

        try
        {
            var doc = JsonDocument.Parse(json);
            return new JsonBody(doc);
        }
        catch (JsonException ex)
        {
            var detail = ex.Message;
            if (detail.Length > 200)
                detail = detail[..200] + "…";
            throw new ApiCommandException(400, $"Invalid JSON: {detail}");
        }
    }

    private async Task WriteSuccess(HttpListenerResponse response, object? data)
    {
        var wrapper = new Dictionary<string, object?>
        {
            ["success"] = true,
            ["activeTab"] = _context.GetActiveTabContext(),
            ["data"] = data
        };

        // When a verbose request trace is active (caller passed {"verbose": true} to a security
        // endpoint), always surface it — even with zero captured requests — so agents can tell
        // the flag was honored (docs promise top-level verboseTrace).
        var trace = _context.CurrentRequestTrace;
        if (trace != null)
        {
            wrapper["verboseTrace"] = new
            {
                requestCount = trace.Count,
                dropped = trace.Dropped,
                requests = trace.Entries
            };
        }

        await WriteJsonResponse(response, 200, wrapper);
    }

    /// <summary>Paths whose handlers issue outbound HTTP probes and support the <c>verbose</c> request trace.</summary>
    private static bool IsTraceableSecurityPath(string path) =>
        path.StartsWith("/api/security", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/api/orchestrate", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/api/attack-surface", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/api/firewall", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/api/authz", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when a pre-read JSON request body contains <c>"verbose": true</c> at the top level.</summary>
    private static bool BodyRequestsVerbose(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("verbose", out var v)
                && v.ValueKind == JsonValueKind.True;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>True when oauth-flow-test is passive-only (allowed under CLI --safe).</summary>
    internal static bool BodyRequestsPassiveOAuthFlowTest(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        try
        {
            return SafetyGate.OAuthFlowTestIsPassiveOnly(new JsonBody(JsonDocument.Parse(body)));
        }
        catch
        {
            return false;
        }
    }

    private async Task WriteError(HttpListenerResponse response, int statusCode, string error)
        => await WriteError(response, statusCode, new ApiCommandException(statusCode, error));

    private async Task WriteError(HttpListenerResponse response, int statusCode, Security.Orchestration.SafetyGateDenial denial)
        => await WriteError(response, statusCode, denial.ToException(statusCode));

    private async Task WriteError(HttpListenerResponse response, int statusCode, Security.Orchestration.SafetyGateDenial? denial)
    {
        if (denial != null)
            await WriteError(response, statusCode, denial.Value);
    }

    private async Task WriteError(HttpListenerResponse response, ApiCommandException ex)
        => await WriteError(response, ex.StatusCode, ex);

    private async Task WriteError(HttpListenerResponse response, int statusCode, ApiCommandException ex)
    {
        var wrapper = new Dictionary<string, object?>
        {
            ["success"] = false,
            ["activeTab"] = _context.GetActiveTabContext(),
            ["error"] = ex.Message
        };
        if (ex.RequestedSafetyMode != null)
            wrapper["requestedSafetyMode"] = ex.RequestedSafetyMode;
        if (ex.EffectiveSafetyMode != null)
            wrapper["effectiveSafetyMode"] = ex.EffectiveSafetyMode;
        if (ex.CappedBy != null)
            wrapper["cappedBy"] = ex.CappedBy;
        await WriteJsonResponse(response, statusCode, wrapper);
    }

    /// <summary>
    /// Shared REST adapter for canonical command builders. Reads the JSON body, runs the
    /// builder, and writes its structured result as JSON. An <see cref="ApiCommandException"/>
    /// thrown by the builder is mapped to <see cref="WriteError"/>. Used so a single
    /// <c>Build*</c> method backs both the REST endpoint and its MCP tool.
    /// </summary>
    internal async Task RespondAsync(HttpListenerRequest request, HttpListenerResponse response,
        Func<JsonBody, Task<object>> builder)
    {
        var body = await ReadJsonBody(request);
        try
        {
            await WriteSuccess(response, await builder(body));
        }
        catch (ApiCommandException ex)
        {
            await WriteError(response, ex);
        }
    }

    private async Task WriteJsonResponse(HttpListenerResponse response, int statusCode, object value)
    {
        if (_scenarioResponseCapture != null)
        {
            _scenarioResponseCapture.StatusCode = statusCode;
            var json = JsonSerializer.SerializeToUtf8Bytes(value, value.GetType(), JsonOptions);
            await _scenarioResponseCapture.Stream.WriteAsync(json);
            return;
        }

        response.StatusCode = statusCode;
        response.ContentType = "application/json; charset=utf-8";
        response.ContentEncoding = Encoding.UTF8;

        var jsonOut = JsonSerializer.SerializeToUtf8Bytes(value, value.GetType(), JsonOptions);
        response.ContentLength64 = jsonOut.Length;
        await response.OutputStream.WriteAsync(jsonOut);
        response.Close();
    }

    #endregion
}
