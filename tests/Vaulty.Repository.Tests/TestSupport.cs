using System.Security.Cryptography;
using Vaulty.Core.Storage;
using Vaulty.Repository.Chunking;
using Vaulty.Repository.Engine;
using Vaulty.Repository.Format;

namespace Vaulty.Repository.Tests;

internal static class TestKeys
{
    public static readonly Guid Tenant = Guid.Parse("11111111-2222-3333-4444-555555555555");
    public static readonly Guid Object = Guid.Parse("66666666-7777-8888-9999-aaaaaaaaaaaa");

    public static RepositoryKeys Fixed() =>
        new(Tenant, new Dictionary<int, byte[]> { [1] = Enumerable.Range(0x40, 32).Select(i => (byte)i).ToArray() });

    public static RepositoryKeys Random(Guid? tenant = null) =>
        new(tenant ?? Guid.NewGuid(), new Dictionary<int, byte[]> { [1] = RandomNumberGenerator.GetBytes(32) });
}

/// <summary>A deterministic, compressible, text-like stream of a given length, generated on the fly (never held in memory).</summary>
internal sealed class SyntheticStream : Stream
{
    private static readonly string[] Words =
    [
        "the", "backup", "snapshot", "mailbox", "invoice", "meeting", "quarterly", "report", "please", "review", "attached",
        "project", "timeline", "budget", "approved", "customer", "contract", "renewal", "schedule", "update", "thanks",
        "regards", "agenda", "minutes", "follow", "action", "items", "deadline", "Friday", "Monday", "draft", "final",
    ];

    private readonly long _length;
    private readonly long _insertAt;
    private readonly byte[] _insert;
    private ulong _state;
    private long _position;
    private byte[] _word = [];
    private int _wordPos;
    private int _insertPos;

    /// <param name="seed">Same seed, same bytes.</param>
    /// <param name="length">Length of the base content.</param>
    /// <param name="insertAt">Position where <paramref name="insert"/> is spliced in (a "new version" of the content).</param>
    public SyntheticStream(ulong seed, long length, long insertAt = -1, byte[]? insert = null)
    {
        _state = seed * 0x9E3779B97F4A7C15UL + 1;
        _length = length;
        _insertAt = insertAt;
        _insert = insert ?? [];
    }

    public long TotalLength => _length + (_insertAt >= 0 ? _insert.Length : 0);

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => TotalLength;
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        var written = 0;
        while (written < buffer.Length)
        {
            if (_insertAt >= 0 && _position == _insertAt && _insertPos < _insert.Length)
            {
                buffer[written++] = _insert[_insertPos++];
                continue;
            }
            if (_position >= _length) break;
            if (_wordPos >= _word.Length) NextWord();
            buffer[written++] = _word[_wordPos++];
            _position++;
        }
        return written;
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(Read(buffer.Span));

    private void NextWord()
    {
        var r = Next();
        // Mostly words (compressible), sometimes a random token (so data is not trivially compressible).
        _word = (r % 7) == 0
            ? System.Text.Encoding.ASCII.GetBytes(Convert.ToHexString(BitConverter.GetBytes(Next())) + " ")
            : System.Text.Encoding.ASCII.GetBytes(Words[(int)(r % (ulong)Words.Length)] + ((r >> 20) % 11 == 0 ? ".\n" : " "));
        _wordPos = 0;
    }

    private ulong Next()
    {
        _state += 0x9E3779B97F4A7C15UL;
        var z = _state;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
        return z ^ (z >> 31);
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>A write-only stream that only hashes what is written.</summary>
internal sealed class HashingStream : Stream
{
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    public long Written { get; private set; }

    public byte[] Hash() => _hash.GetHashAndReset();

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        _hash.AppendData(buffer);
        Written += buffer.Length;
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Write(buffer.Span);
        return ValueTask.CompletedTask;
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => Written;
    public override long Position { get => Written; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing) _hash.Dispose();
        base.Dispose(disposing);
    }

    public static async Task<byte[]> Of(Stream source)
    {
        using var hashing = new HashingStream();
        await source.CopyToAsync(hashing);
        return hashing.Hash();
    }
}

/// <summary>Throws at the n-th fault point, simulating a process that dies there.</summary>
internal sealed class CrashAt(int hit) : IFaultInjector
{
    public int Hits { get; private set; }
    public string? CrashedAt { get; private set; }

    public void Hit(string point)
    {
        Hits++;
        if (Hits == hit)
        {
            CrashedAt = point;
            throw new SimulatedCrashException(point);
        }
    }
}

internal sealed class CountingFaults : IFaultInjector
{
    public int Hits { get; private set; }
    public void Hit(string point) => Hits++;
}

internal sealed class SimulatedCrashException(string point) : Exception($"simulated crash at {point}");

internal static class SmallChunks
{
    public static readonly ChunkerOptions Options = new(1024, 4096, 16384);
}

internal static class Writers
{
    public static RepositoryWriter Create(InMemoryObjectStore store, RepositoryKeys keys, IChunkIndex index, int packSize = 1024 * 1024,
        ChunkerOptions? chunker = null, IFaultInjector? faults = null) =>
        new(store, keys, index, new RepositoryWriterOptions
        {
            LockUntil = DateTimeOffset.UtcNow.AddDays(120),
            PackTargetSize = packSize,
            Chunker = chunker ?? ChunkerOptions.Default,
        }, faults);
}
