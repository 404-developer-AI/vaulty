using System.Buffers;

namespace Vaulty.Repository.Chunking;

/// <summary>Chunk size parameters. The defaults are the repository format v1 values.</summary>
public sealed record ChunkerOptions(int MinSize, int AverageSize, int MaxSize)
{
    public static ChunkerOptions Default { get; } = new(256 * 1024, 1024 * 1024, 4 * 1024 * 1024);

    public void Validate()
    {
        if (MinSize < 64 || AverageSize <= MinSize || MaxSize <= AverageSize || !int.IsPow2(AverageSize))
        {
            throw new ArgumentException("Chunker options need 64 <= min < average < max and a power-of-two average.");
        }
    }
}

/// <summary>
/// FastCDC content-defined chunking with normalized chunking (level 2), as specified in docs/format/repository-v1.md.
/// A Gear rolling hash <c>h = (h &lt;&lt; 1) + Gear[byte]</c> is tested against a stricter mask before the average size and a
/// looser one after it. Boundaries depend only on content, so an insertion moves at most the boundaries around it.
/// </summary>
public static class FastCdc
{
    /// <summary>The 256 Gear values: SplitMix64 seeded with 0x5641554c54590001 ("VAULTY", version 1).</summary>
    public static readonly ulong[] Gear = BuildGear();

    private static ulong[] BuildGear()
    {
        var gear = new ulong[256];
        var state = 0x5641554c54590001UL;
        for (var i = 0; i < gear.Length; i++)
        {
            state += 0x9E3779B97F4A7C15UL;
            var z = state;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
            gear[i] = z ^ (z >> 31);
        }
        return gear;
    }

    /// <summary>A mask of the top <paramref name="bits"/> bits; with a left-shifting hash these bits see the most bytes.</summary>
    public static ulong TopBits(int bits) => bits == 0 ? 0 : ulong.MaxValue << (64 - bits);

    /// <summary>Length of the next chunk at the start of <paramref name="data"/>.</summary>
    /// <param name="data">The available bytes. When fewer than <c>MaxSize</c> remain, pass <paramref name="final"/>.</param>
    /// <param name="final">No more bytes follow; the remainder may be shorter than the minimum.</param>
    public static int NextBoundary(ReadOnlySpan<byte> data, ChunkerOptions options, bool final)
    {
        ArgumentNullException.ThrowIfNull(options);
        var length = data.Length;
        if (length <= options.MinSize)
        {
            return final ? length : throw new ArgumentException("Need more data unless this is the end of the stream.");
        }
        if (length > options.MaxSize) length = options.MaxSize;
        else if (!final && length < options.MaxSize) throw new ArgumentException("Need MaxSize bytes unless this is the end.");

        var bits = int.Log2(options.AverageSize);
        var maskS = TopBits(bits + 2);
        var maskL = TopBits(bits - 2);
        var normal = Math.Min(options.AverageSize, length);
        ulong hash = 0;
        var i = options.MinSize;
        for (; i < normal; i++)
        {
            hash = (hash << 1) + Gear[data[i]];
            if ((hash & maskS) == 0) return i + 1;
        }
        for (; i < length; i++)
        {
            hash = (hash << 1) + Gear[data[i]];
            if ((hash & maskL) == 0) return i + 1;
        }
        return length;
    }

    /// <summary>
    /// Splits a stream into chunks without holding more than about two maximum chunk sizes in memory. Each chunk is
    /// passed to <paramref name="onChunk"/>; the memory is only valid during the call.
    /// </summary>
    public static async Task ChunkAsync(Stream source, ChunkerOptions options, Func<ReadOnlyMemory<byte>, ValueTask> onChunk,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(onChunk);
        options.Validate();
        var buffer = ArrayPool<byte>.Shared.Rent(options.MaxSize * 2);
        try
        {
            var filled = 0;
            var start = 0;
            var eof = false;
            while (true)
            {
                // Keep at least MaxSize bytes available unless the stream is exhausted.
                while (!eof && filled - start < options.MaxSize)
                {
                    if (start > 0 && filled + options.MaxSize > buffer.Length)
                    {
                        Buffer.BlockCopy(buffer, start, buffer, 0, filled - start);
                        filled -= start;
                        start = 0;
                    }
                    var read = await source.ReadAsync(buffer.AsMemory(filled, buffer.Length - filled), cancellationToken)
                        .ConfigureAwait(false);
                    if (read == 0) eof = true;
                    else filled += read;
                }
                var available = filled - start;
                if (available == 0) return;
                var cut = NextBoundary(buffer.AsSpan(start, available), options, eof);
                await onChunk(buffer.AsMemory(start, cut)).ConfigureAwait(false);
                start += cut;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
