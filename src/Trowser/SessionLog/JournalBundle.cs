using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser.Pointers;

namespace Trowser.SessionLog;

/// <summary>
/// JSON round-trip of the in-memory journal plus any attached pointers.
/// Used by <c>GET /api/journal/export?format=json</c>, <c>POST /api/journal/import</c>,
/// and the Journal panel Open / Save commands.
/// </summary>
public static class JournalBundle
{
    public const string FormatName = "trowser-journal";
    public const int FormatVersion = 1;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public static string Serialize(IReadOnlyList<SessionLogger.JournalEntry> entries, PointerStore? pointers)
    {
        var pointerIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in entries)
        {
            if (e.Fields != null && e.Fields.TryGetValue("pointerId", out var id) && !string.IsNullOrWhiteSpace(id))
                pointerIds.Add(id);
        }

        var attached = new List<PointerDto>();
        if (pointers != null)
        {
            foreach (var id in pointerIds)
            {
                var p = pointers.Get(id);
                if (p != null) attached.Add(PointerDto.From(p));
            }
        }

        var bundle = new BundleDto
        {
            Format = FormatName,
            Version = FormatVersion,
            ExportedAt = DateTime.UtcNow.ToString("o"),
            Entries = entries.Select(EntryDto.From).ToList(),
            Pointers = attached.Count > 0 ? attached : null
        };
        return JsonSerializer.Serialize(bundle, JsonOptions);
    }

    public static BundleDto Deserialize(string json)
    {
        var bundle = JsonSerializer.Deserialize<BundleDto>(json, JsonOptions)
            ?? throw new InvalidOperationException("Journal JSON was empty.");
        if (!string.IsNullOrEmpty(bundle.Format)
            && !bundle.Format.Equals(FormatName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Unsupported journal format '{bundle.Format}'.");
        bundle.Entries ??= [];
        return bundle;
    }

    public sealed class BundleDto
    {
        public string Format { get; set; } = FormatName;
        public int Version { get; set; } = FormatVersion;
        public string? ExportedAt { get; set; }
        public List<EntryDto> Entries { get; set; } = [];
        public List<PointerDto>? Pointers { get; set; }
    }

    public sealed class EntryDto
    {
        public int Index { get; set; }
        public string? Timestamp { get; set; }
        public string Type { get; set; } = "";
        public string? Kind { get; set; }
        public string Source { get; set; } = "";
        public string? Summary { get; set; }
        public string? Details { get; set; }
        public string? Severity { get; set; }
        public string? Evidence { get; set; }
        public Dictionary<string, string>? Fields { get; set; }
        public List<string>? Tags { get; set; }
        public string? Url { get; set; }
        public bool StepsIsArray { get; set; }

        public static EntryDto From(SessionLogger.JournalEntry e)
        {
            Dictionary<string, string>? fields = null;
            if (e.Fields != null)
            {
                fields = new Dictionary<string, string>(e.Fields, StringComparer.OrdinalIgnoreCase);
                if (e.StepsIsArray && fields.TryGetValue("steps", out var steps)
                    && e.Fields.ContainsKey("steps"))
                {
                    // Keep newline-joined steps; StepsIsArray tells the importer to restore the array flag.
                }
            }

            return new EntryDto
            {
                Index = e.Index,
                Timestamp = e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                Type = e.Type,
                Kind = e.Kind,
                Source = e.Source,
                Summary = e.Summary,
                Details = e.Details,
                Severity = e.Severity,
                Evidence = e.Evidence,
                Fields = fields,
                Tags = e.Tags,
                Url = e.Url,
                StepsIsArray = e.StepsIsArray
            };
        }

        public SessionLogger.JournalEntry ToEntry()
        {
            DateTime ts;
            if (!DateTime.TryParse(Timestamp, out ts))
                ts = DateTime.Now;

            return new SessionLogger.JournalEntry
            {
                Index = Index,
                Timestamp = ts,
                Type = string.IsNullOrWhiteSpace(Type) ? (Kind ?? "note") : Type,
                Kind = Kind,
                Source = string.IsNullOrWhiteSpace(Source) ? "system" : Source,
                Summary = Summary ?? "",
                Details = Details,
                Severity = Severity,
                Evidence = string.IsNullOrWhiteSpace(Evidence) ? NoteKinds.EvidenceInferred : Evidence,
                Fields = Fields,
                Tags = Tags,
                Url = Url,
                StepsIsArray = StepsIsArray
            };
        }
    }

    public sealed class PointerDto
    {
        public string Id { get; set; } = "";
        public string Kind { get; set; } = PointerKinds.Element;
        public PointerAnchors? Anchors { get; set; }
        public string? CropPath { get; set; }
        public string? Caption { get; set; }
        public string Author { get; set; } = PointerAuthors.Human;
        public int? TabId { get; set; }
        public string? Url { get; set; }
        public string? CheckpointId { get; set; }
        public string Status { get; set; } = PointerStatuses.Resolved;
        public string? Source { get; set; }
        public DateTime CreatedAt { get; set; }
        public int JournalIndex { get; set; } = -1;

        public static PointerDto From(Pointer p) => new()
        {
            Id = p.Id,
            Kind = p.Kind,
            Anchors = p.Anchors,
            CropPath = p.CropPath,
            Caption = p.Caption,
            Author = p.Author,
            TabId = p.TabId,
            Url = p.Url,
            CheckpointId = p.CheckpointId,
            Status = p.Status,
            Source = p.Source,
            CreatedAt = p.CreatedAt,
            JournalIndex = p.JournalIndex
        };

        public Pointer ToPointer() => new()
        {
            Id = Id,
            Kind = PointerKinds.Normalize(Kind),
            Anchors = Anchors ?? new PointerAnchors(),
            CropPath = CropPath,
            Caption = Caption,
            Author = PointerAuthors.Normalize(Author),
            TabId = TabId,
            Url = Url,
            CheckpointId = CheckpointId,
            Status = PointerStatuses.Normalize(Status),
            Source = Source,
            CreatedAt = CreatedAt == default ? DateTime.Now : CreatedAt,
            JournalIndex = JournalIndex
        };
    }
}
