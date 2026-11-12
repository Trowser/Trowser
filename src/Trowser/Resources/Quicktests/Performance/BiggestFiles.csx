// @title Biggest Files
// @shadow light
// @effects none
// List the 10 biggest files in the captured network traffic

var all = GetNetworkLog();
Log($"Network traffic: {all.Count} requests captured");
Log("");

var withSize = all
    .Select(e =>
    {
        long size = 0;
        if (e.ResponseHeaders.TryGetValue("Content-Length", out var cl) ||
            e.ResponseHeaders.TryGetValue("content-length", out cl))
            long.TryParse(cl, out size);
        else if (e.ResponseBody != null)
            size = e.ResponseBody.Length;
        return new { Entry = e, Size = size };
    })
    .Where(x => x.Size > 0)
    .OrderByDescending(x => x.Size)
    .Take(10)
    .ToList();

if (withSize.Count == 0)
{
    Log("No files with known size found in network traffic.");
    Log("Browse some pages first to capture network requests.");
}
else
{
    Log("Top 10 biggest files:");
    Log($"  {"Size",10}  {"Type",-12}  URL");
    Log($"  {"----",10}  {"----",-12}  ---");

    foreach (var x in withSize)
    {
        var sizeStr = x.Size >= 1_048_576
            ? $"{x.Size / 1_048_576.0:F1} MB"
            : x.Size >= 1024
                ? $"{x.Size / 1024.0:F1} KB"
                : $"{x.Size} B";

        var url = x.Entry.Url;
        if (url.Length > 80) url = url[..77] + "...";

        Log($"  {sizeStr,10}  {x.Entry.ResourceType,-12}  {url}");
    }
}
