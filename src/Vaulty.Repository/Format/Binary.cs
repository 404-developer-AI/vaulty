using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Vaulty.Repository.Format;

/// <summary>Thrown for any structure that does not parse as the repository format. Parsers never throw anything else.</summary>
public sealed class RepositoryFormatException(string message) : Exception(message);

/// <summary>Big-endian writer for the repository format.</summary>
internal sealed class BinaryBuilder
{
    private readonly ArrayBufferWriter<byte> _buffer;

    public BinaryBuilder(int capacity = 256) => _buffer = new ArrayBufferWriter<byte>(capacity);

    public int Length => _buffer.WrittenCount;

    public ReadOnlySpan<byte> Written => _buffer.WrittenSpan;

    public byte[] ToArray() => _buffer.WrittenSpan.ToArray();

    public BinaryBuilder Bytes(ReadOnlySpan<byte> value)
    {
        value.CopyTo(_buffer.GetSpan(value.Length));
        _buffer.Advance(value.Length);
        return this;
    }

    public BinaryBuilder U8(byte value) => Bytes([value]);

    public BinaryBuilder U32(uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(_buffer.GetSpan(4), value);
        _buffer.Advance(4);
        return this;
    }

    public BinaryBuilder I64(long value)
    {
        BinaryPrimitives.WriteInt64BigEndian(_buffer.GetSpan(8), value);
        _buffer.Advance(8);
        return this;
    }

    public BinaryBuilder Guid(Guid value)
    {
        Core.Crypto.KeyHierarchy.WriteGuid(value, _buffer.GetSpan(16));
        _buffer.Advance(16);
        return this;
    }

    /// <summary>A UTF-8 string with a 4-byte length prefix.</summary>
    public BinaryBuilder String(string? value)
    {
        var bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        return U32((uint)bytes.Length).Bytes(bytes);
    }
}

/// <summary>Bounds-checked big-endian reader. Every malformed input ends in <see cref="RepositoryFormatException"/>.</summary>
internal ref struct BinaryParser
{
    private readonly ReadOnlySpan<byte> _data;
    private int _position;

    public BinaryParser(ReadOnlySpan<byte> data)
    {
        _data = data;
        _position = 0;
    }

    public readonly int Position => _position;
    public readonly int Remaining => _data.Length - _position;

    public ReadOnlySpan<byte> Bytes(int count)
    {
        if (count < 0 || count > Remaining) throw new RepositoryFormatException($"Truncated: need {count} bytes at {_position}.");
        var slice = _data.Slice(_position, count);
        _position += count;
        return slice;
    }

    public byte U8() => Bytes(1)[0];

    public uint U32() => BinaryPrimitives.ReadUInt32BigEndian(Bytes(4));

    public int Count(int elementSize)
    {
        var count = U32();
        if (count > int.MaxValue || (long)count * Math.Max(elementSize, 1) > Remaining)
        {
            throw new RepositoryFormatException($"Count {count} exceeds the remaining {Remaining} bytes.");
        }
        return (int)count;
    }

    public long I64() => BinaryPrimitives.ReadInt64BigEndian(Bytes(8));

    public Guid Guid() => new(Bytes(16), bigEndian: true);

    public string String(int maxBytes = 1 << 20)
    {
        var length = U32();
        if (length > maxBytes || length > Remaining) throw new RepositoryFormatException($"String of {length} bytes at {_position}.");
        try
        {
            return new UTF8Encoding(false, true).GetString(Bytes((int)length));
        }
        catch (DecoderFallbackException)
        {
            throw new RepositoryFormatException("Invalid UTF-8.");
        }
    }

    public void Expect(ReadOnlySpan<byte> magic, string what)
    {
        if (!Bytes(magic.Length).SequenceEqual(magic)) throw new RepositoryFormatException($"Not a {what}.");
    }

    public readonly void End()
    {
        if (Remaining != 0) throw new RepositoryFormatException($"{Remaining} trailing bytes.");
    }
}
