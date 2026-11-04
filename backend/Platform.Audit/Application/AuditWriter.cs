using System.Collections.Frozen;
using System.Text.Json;

namespace Platform.Audit.Application;

/// <summary>
/// Validates and writes a flat, size-limited audit payload. The occurrence time is
/// always supplied by the server clock; payload timestamps are never used as it.
/// </summary>
internal sealed class AuditWriter(TimeProvider timeProvider, IAuditLogStore store)
{
    internal const int MaximumKeyCount = 20;
    internal const int MaximumPayloadBytes = 2048;

    private readonly TimeProvider _timeProvider =
        timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly IAuditLogStore _store = store ?? throw new ArgumentNullException(nameof(store));

    public ValueTask WriteAsync(
        IDictionary<string, object?> payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);

        // Validate and detach from caller-owned mutable state before any side effect.
        if (payload.Count > MaximumKeyCount)
            throw InvalidAuditEventException.Create();

        var snapshot = new Dictionary<string, object?>(payload.Count, StringComparer.Ordinal);
        foreach (var (key, value) in payload)
        {
            if (string.IsNullOrEmpty(key) || !IsAllowedScalar(value))
                throw InvalidAuditEventException.Create();

            snapshot.Add(key, value);
        }

        if (JsonSerializer.SerializeToUtf8Bytes(snapshot).Length > MaximumPayloadBytes)
            throw InvalidAuditEventException.Create();

        cancellationToken.ThrowIfCancellationRequested();

        var auditEvent = new AuditLogEntry(
            _timeProvider.GetUtcNow(),
            snapshot.ToFrozenDictionary(StringComparer.Ordinal));

        return _store.AppendAsync(auditEvent, cancellationToken);
    }

    private static bool IsAllowedScalar(object? value) => value is
        string or int or long or double or bool or DateTime or Guid;
}

/// <summary>A safe validation failure which deliberately contains no rejected data.</summary>
internal sealed class InvalidAuditEventException : Exception
{
    private const string SafeMessage = "The audit event payload is invalid.";

    private InvalidAuditEventException() : base(SafeMessage)
    {
    }

    internal static InvalidAuditEventException Create() => new();
}

/// <summary>Immutable value handed to the append-only audit storage boundary.</summary>
internal sealed record AuditLogEntry(
    DateTimeOffset OccurredAt,
    IReadOnlyDictionary<string, object?> Payload);

/// <summary>Minimal append-only storage boundary used by the sanitizer/writer.</summary>
internal interface IAuditLogStore
{
    ValueTask AppendAsync(AuditLogEntry auditEvent, CancellationToken cancellationToken = default);
}
