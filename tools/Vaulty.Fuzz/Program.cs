using SharpFuzz;
using Vaulty.Repository.Format;

// Fuzz targets for the repository format parsers, run nightly with libFuzzer (.github/workflows/nightly.yml).
// A parser may reject input only with RepositoryFormatException or IntegrityException; anything else is a finding.
//   Vaulty.Fuzz <manifest|snapshot|index|pack|blob|chunk>
var keys = new RepositoryKeys(Guid.Parse("11111111-2222-3333-4444-555555555555"),
    new Dictionary<int, byte[]> { [1] = Enumerable.Range(0x40, 32).Select(i => (byte)i).ToArray() });

Action<ReadOnlySpan<byte>> target = (args.FirstOrDefault() ?? "") switch
{
    "manifest" => data => StructureSerializer.DeserializeManifest(data),
    "snapshot" => data => StructureSerializer.DeserializeSnapshot(data),
    "index" => data => StructureSerializer.DeserializeIndex(data),
    "pack" => data => PackFormat.Parse(data, keys.TenantId, "00"),
    "blob" => data => SealedBlob.Open(keys, BlobType.Manifest, data),
    "chunk" => data => ChunkCodec.Decode(keys, data),
    _ => throw new ArgumentException("usage: Vaulty.Fuzz <manifest|snapshot|index|pack|blob|chunk>"),
};

Fuzzer.LibFuzzer.Run(span =>
{
    try
    {
        target(span);
    }
    catch (RepositoryFormatException)
    {
    }
    catch (IntegrityException)
    {
    }
});
