using System.Security.Cryptography;

namespace Vaulty.Core.Abstractions;

/// <summary>
/// An object written as a stream of unknown length (an export being produced): the bytes go up in parts while they are
/// written, so nothing larger than one part is held in memory and nothing touches the disk. Disposing without
/// <see cref="CompleteAsync"/> abandons the upload.
/// </summary>
public interface IObjectUpload : IAsyncDisposable
{
    Stream Stream { get; }

    /// <summary>SHA-256 and size of everything written; valid after <see cref="CompleteAsync"/>.</summary>
    Task<ObjectInfo> CompleteAsync(CancellationToken cancellationToken = default);

    byte[] Sha256 { get; }
}

public interface IObjectUploads
{
    Task<IObjectUpload> BeginUploadAsync(string key, ObjectPutOptions options, CancellationToken cancellationToken = default);
}

/// <summary>
/// The write side shared by the stores: buffers one part, hands every full part to <c>uploadPart</c> and the last one on
/// completion, and hashes everything that passes.
/// </summary>
public sealed class PartUploadStream(int partSize, Func<int, ReadOnlyMemory<byte>, CancellationToken, Task> uploadPart) : Stream
{
    private readonly byte[] _buffer = new byte[partSize];
    private readonly IncrementalHash _sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private int _filled;
    private int _part;
    private long _length;

    public int Parts => _part;
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => _length;
    public override long Position { get => _length; set => throw new NotSupportedException(); }

    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (buffer.Length > 0)
        {
            var take = Math.Min(buffer.Length, _buffer.Length - _filled);
            buffer.Span[..take].CopyTo(_buffer.AsSpan(_filled));
            _sha.AppendData(buffer.Span[..take]);
            _filled += take;
            _length += take;
            buffer = buffer[take..];
            if (_filled == _buffer.Length) await FlushPartAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    private async Task FlushPartAsync(CancellationToken cancellationToken)
    {
        await uploadPart(++_part, _buffer.AsMemory(0, _filled), cancellationToken).ConfigureAwait(false);
        _filled = 0;
    }

    /// <summary>Uploads what is left (at least one part, possibly empty) and returns the SHA-256 of the whole object.</summary>
    public async Task<byte[]> FinishAsync(CancellationToken cancellationToken)
    {
        if (_filled > 0 || _part == 0) await FlushPartAsync(cancellationToken).ConfigureAwait(false);
        return _sha.GetHashAndReset();
    }

    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing) _sha.Dispose();
        base.Dispose(disposing);
    }
}
