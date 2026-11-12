using System.Net;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    /// <summary>
    /// GUI bridge for interaction recording. Set by MainWindow when the API server starts.
    /// Captures human DOM input into a .csx script (not MCP/REST click tools).
    /// </summary>
    public Func<string?>? GuiRecordStart { get; set; }
    public Func<object>? GuiRecordStatus { get; set; }
    public Func<string?, bool, string?, Task<object>>? GuiRecordStopAsync { get; set; }

    private async Task HandlePostRecordStart(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (GuiRecordStart == null)
        {
            await WriteError(response, 503, "Recording is not available.");
            return;
        }

        string? error = null;
        await _dispatcher.InvokeAsync(() => { error = GuiRecordStart(); });
        if (error != null)
        {
            await WriteError(response, 409, error);
            return;
        }

        object status = new { recording = true };
        if (GuiRecordStatus != null)
            await _dispatcher.InvokeAsync(() => { status = GuiRecordStatus(); });

        await WriteSuccess(response, status);
    }

    private async Task HandleGetRecordStatus(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (GuiRecordStatus == null)
        {
            await WriteError(response, 503, "Recording is not available.");
            return;
        }

        object status = new { recording = false };
        await _dispatcher.InvokeAsync(() => { status = GuiRecordStatus(); });
        await WriteSuccess(response, status);
    }

    private async Task HandlePostRecordStop(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (GuiRecordStopAsync == null)
        {
            await WriteError(response, 503, "Recording is not available.");
            return;
        }

        var body = await ReadJsonBody(request);
        var description = body.GetString("description");
        var toJournal = body.GetBool("toJournal");
        var path = body.GetString("path") ?? body.GetString("toFile");
        if (string.Equals(path, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(path, "false", StringComparison.OrdinalIgnoreCase))
            path = null;

        string? resolvedPath = null;
        if (!string.IsNullOrWhiteSpace(path))
        {
            if (!ExportPathGuard.TryResolve(path, SafeMode, out var full, out var guardError))
            {
                await WriteError(response, 400, guardError ?? "Invalid export path.");
                return;
            }
            resolvedPath = full;
        }

        Task<object>? stopTask = null;
        await _dispatcher.InvokeAsync(() =>
        {
            stopTask = GuiRecordStopAsync(description, toJournal, resolvedPath);
        });
        var result = await stopTask!;
        await WriteSuccess(response, result);
    }

    internal Task<object> BuildRecordStartAsync(JsonBody body)
    {
        if (GuiRecordStart == null)
            throw new ApiCommandException(503, "Recording is not available.");

        string? error = null;
        _dispatcher.Invoke(() => { error = GuiRecordStart(); });
        if (error != null)
            throw new ApiCommandException(409, error);

        object status = new { recording = true };
        if (GuiRecordStatus != null)
            _dispatcher.Invoke(() => { status = GuiRecordStatus(); });
        return Task.FromResult(status);
    }

    internal Task<object> BuildRecordStatusAsync(JsonBody body)
    {
        if (GuiRecordStatus == null)
            throw new ApiCommandException(503, "Recording is not available.");

        object status = new { recording = false };
        _dispatcher.Invoke(() => { status = GuiRecordStatus(); });
        return Task.FromResult(status);
    }

    internal async Task<object> BuildRecordStopAsync(JsonBody body)
    {
        if (GuiRecordStopAsync == null)
            throw new ApiCommandException(503, "Recording is not available.");

        var description = body.GetString("description");
        var toJournal = body.GetBool("toJournal");
        var path = body.GetString("path") ?? body.GetString("toFile");
        if (string.Equals(path, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(path, "false", StringComparison.OrdinalIgnoreCase))
            path = null;

        string? resolvedPath = null;
        if (!string.IsNullOrWhiteSpace(path))
        {
            if (!ExportPathGuard.TryResolve(path, SafeMode, out var full, out var guardError))
                throw new ApiCommandException(400, guardError ?? "Invalid export path.");
            resolvedPath = full;
        }

        Task<object>? stopTask = null;
        await _dispatcher.InvokeAsync(() =>
        {
            stopTask = GuiRecordStopAsync(description, toJournal, resolvedPath);
        });
        return await stopTask!;
    }
}
