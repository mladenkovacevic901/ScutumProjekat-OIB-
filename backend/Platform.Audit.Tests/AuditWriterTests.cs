using System.Text.Json;
using NUnit.Framework;
using Platform.Audit.Application;

namespace Platform.Audit.Tests;

[TestFixture]
public sealed class AuditWriterTests
{
    private static readonly DateTimeOffset FixedUtcTime =
        new(2026, 11, 4, 12, 30, 0, TimeSpan.Zero);

    [Test]
    public async Task WriteAsync_WhenPayloadIsValid_WritesSnapshotWithServerUtcTime()
    {
        var store = new RecordingAuditLogStore();
        var writer = CreateWriter(store);
        var id = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var payload = new Dictionary<string, object?>
        {
            ["eventType"] = "auth.login",
            ["attempt"] = 2,
            ["sequence"] = 3L,
            ["score"] = 0.5d,
            ["success"] = true,
            ["observedDate"] = new DateTime(2026, 11, 4),
            ["resourceId"] = id
        };

        await writer.WriteAsync(payload);
        payload["success"] = false;

        var written = store.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(written.OccurredAt, Is.EqualTo(FixedUtcTime));
            Assert.That(written.OccurredAt.Offset, Is.EqualTo(TimeSpan.Zero));
            Assert.That(written.Payload["success"], Is.EqualTo(true));
        }
    }

    [Test]
    public void WriteAsync_WhenPayloadContainsNestedObject_ThrowsWithoutWriting()
    {
        var store = new RecordingAuditLogStore();
        var writer = CreateWriter(store);
        var payload = new Dictionary<string, object?>
        {
            ["eventType"] = "auth.login",
            ["actor"] = new { Id = "forged-actor", Secret = "must-not-leak" }
        };

        var exception = Assert.ThrowsAsync<InvalidAuditEventException>(async () =>
            await writer.WriteAsync(payload));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(store.Events, Is.Empty);
            Assert.That(exception!.Message, Does.Not.Contain("forged-actor"));
            Assert.That(exception.Message, Does.Not.Contain("must-not-leak"));
        }
    }

    [TestCase(20, true)]
    [TestCase(21, false)]
    public async Task WriteAsync_EnforcesKeyCountBoundary(int keyCount, bool accepted)
    {
        var store = new RecordingAuditLogStore();
        var writer = CreateWriter(store);
        var payload = Enumerable.Range(0, keyCount)
            .ToDictionary(i => $"key{i}", i => (object?)i, StringComparer.Ordinal);

        if (accepted)
            await writer.WriteAsync(payload);
        else
            Assert.ThrowsAsync<InvalidAuditEventException>(async () => await writer.WriteAsync(payload));

        Assert.That(store.Events.Count, Is.EqualTo(accepted ? 1 : 0));
    }

    [TestCase(2048, true)]
    [TestCase(2049, false)]
    public async Task WriteAsync_EnforcesExactUtf8JsonSizeBoundary(int byteCount, bool accepted)
    {
        var store = new RecordingAuditLogStore();
        var writer = CreateWriter(store);
        var payload = PayloadWithSerializedSize(byteCount);

        Assert.That(JsonSerializer.SerializeToUtf8Bytes(payload), Has.Length.EqualTo(byteCount));

        if (accepted)
            await writer.WriteAsync(payload);
        else
            Assert.ThrowsAsync<InvalidAuditEventException>(async () => await writer.WriteAsync(payload));

        Assert.That(store.Events.Count, Is.EqualTo(accepted ? 1 : 0));
    }

    [Test]
    public void WriteAsync_WhenValidationFails_HasNoStorageOrClockSideEffects()
    {
        var store = new RecordingAuditLogStore();
        var clock = new CountingTimeProvider(FixedUtcTime);
        var writer = new AuditWriter(clock, store);
        var payload = new Dictionary<string, object?> { ["password"] = new object() };

        Assert.ThrowsAsync<InvalidAuditEventException>(async () => await writer.WriteAsync(payload));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(store.Events, Is.Empty);
            Assert.That(clock.GetUtcNowCallCount, Is.Zero);
        }
    }

    private static AuditWriter CreateWriter(RecordingAuditLogStore store) =>
        new(new CountingTimeProvider(FixedUtcTime), store);

    private static Dictionary<string, object?> PayloadWithSerializedSize(int byteCount)
    {
        var payload = new Dictionary<string, object?> { ["data"] = string.Empty };
        var emptySize = JsonSerializer.SerializeToUtf8Bytes(payload).Length;
        payload["data"] = new string('x', byteCount - emptySize);
        return payload;
    }

    private sealed class RecordingAuditLogStore : IAuditLogStore
    {
        public List<AuditLogEntry> Events { get; } = [];

        public ValueTask AppendAsync(
            AuditLogEntry auditEvent,
            CancellationToken cancellationToken = default)
        {
            Events.Add(auditEvent);
            return ValueTask.CompletedTask;
        }

        public AuditLogEntry Single() => Events.Single();
    }

    private sealed class CountingTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public int GetUtcNowCallCount { get; private set; }

        public override DateTimeOffset GetUtcNow()
        {
            GetUtcNowCallCount++;
            return utcNow;
        }
    }
}
