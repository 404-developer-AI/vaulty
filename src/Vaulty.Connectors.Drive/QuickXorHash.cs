namespace Vaulty.Connectors.Drive;

/// <summary>
/// Microsoft's QuickXorHash (OneDrive for Business file hash): 160 bits, each byte XOR-ed in at a position that moves by
/// 11 bits, then the total length XOR-ed into the last 8 bytes. Used to check every downloaded file against the hash Graph
/// reports for it.
/// </summary>
public sealed class QuickXorHash
{
    private const int WidthInBits = 160;
    private const int Shift = 11;
    private readonly ulong[] _data = new ulong[(WidthInBits - 1) / 64 + 1];
    private long _length;
    private int _shiftSoFar;

    public void Append(ReadOnlySpan<byte> array)
    {
        var currentShift = _shiftSoFar;
        var vectorArrayIndex = currentShift / 64;
        var vectorOffset = currentShift % 64;
        var iterations = Math.Min(array.Length, WidthInBits);
        for (var i = 0; i < iterations; i++)
        {
            var isLastCell = vectorArrayIndex == _data.Length - 1;
            var bitsInVectorCell = isLastCell ? WidthInBits % 64 : 64;
            if (vectorOffset <= bitsInVectorCell - 8)
            {
                for (var j = i; j < array.Length; j += WidthInBits) _data[vectorArrayIndex] ^= (ulong)array[j] << vectorOffset;
            }
            else
            {
                var index2 = isLastCell ? 0 : vectorArrayIndex + 1;
                var low = bitsInVectorCell - vectorOffset;
                byte xored = 0;
                for (var j = i; j < array.Length; j += WidthInBits) xored ^= array[j];
                _data[vectorArrayIndex] ^= (ulong)xored << vectorOffset;
                _data[index2] ^= (ulong)xored >> low;
            }
            vectorOffset += Shift;
            while (vectorOffset >= bitsInVectorCell)
            {
                vectorArrayIndex = isLastCell ? 0 : vectorArrayIndex + 1;
                vectorOffset -= bitsInVectorCell;
                isLastCell = vectorArrayIndex == _data.Length - 1;
                bitsInVectorCell = isLastCell ? WidthInBits % 64 : 64;
            }
        }
        _shiftSoFar = (int)((_shiftSoFar + (long)Shift * (array.Length % WidthInBits)) % WidthInBits);
        _length += array.Length;
    }

    public byte[] Finish()
    {
        var result = new byte[(WidthInBits - 1) / 8 + 1];
        for (var i = 0; i < _data.Length - 1; i++) BitConverter.GetBytes(_data[i]).CopyTo(result, i * 8);
        BitConverter.GetBytes(_data[^1]).AsSpan(0, result.Length - (_data.Length - 1) * 8).CopyTo(result.AsSpan((_data.Length - 1) * 8));
        var length = BitConverter.GetBytes(_length);
        for (var i = 0; i < length.Length; i++) result[WidthInBits / 8 - length.Length + i] ^= length[i];
        return result;
    }

    public static string Base64(ReadOnlySpan<byte> data)
    {
        var hash = new QuickXorHash();
        hash.Append(data);
        return Convert.ToBase64String(hash.Finish());
    }
}
