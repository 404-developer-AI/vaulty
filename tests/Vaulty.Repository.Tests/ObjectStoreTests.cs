using Microsoft.Extensions.Time.Testing;
using Vaulty.Core.Abstractions;
using Vaulty.Core.Storage;

namespace Vaulty.Repository.Tests;

public class InMemoryObjectStoreTests
{
    [Fact]
    public async Task A_locked_object_cannot_be_deleted_or_overwritten_before_its_lock_expires()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 11, 9, 0, 0, 0, TimeSpan.Zero));
        var store = new InMemoryObjectStore(clock);
        var lockUntil = clock.GetUtcNow().AddDays(1);
        await store.PutAsync("tenants/t/packs/aa/x.pack", new MemoryStream([1, 2, 3]), new ObjectPutOptions(lockUntil));

        await Assert.ThrowsAsync<ObjectLockedException>(() => store.DeleteAsync("tenants/t/packs/aa/x.pack"));
        await Assert.ThrowsAsync<ObjectAlreadyExistsException>(() =>
            store.PutAsync("tenants/t/packs/aa/x.pack", new MemoryStream([9]), new ObjectPutOptions(lockUntil)));
        await Assert.ThrowsAsync<ObjectLockedException>(() =>
            store.PutAsync("tenants/t/packs/aa/x.pack", new MemoryStream([9]), new ObjectPutOptions(lockUntil, FailIfExists: false)));

        clock.Advance(TimeSpan.FromDays(1) + TimeSpan.FromSeconds(1));
        await store.DeleteAsync("tenants/t/packs/aa/x.pack");
        Assert.Null(await store.HeadAsync("tenants/t/packs/aa/x.pack"));
    }

    [Fact]
    public async Task An_identity_without_delete_right_cannot_delete_even_expired_objects()
    {
        var store = new InMemoryObjectStore { DeleteAllowed = false };
        await store.PutAsync("k", new MemoryStream([1]), new ObjectPutOptions(null));
        await Assert.ThrowsAsync<ObjectStoreAccessDeniedException>(() => store.DeleteAsync("k"));
    }

    [Fact]
    public async Task Ranges_lists_and_integrity_checks()
    {
        var store = new InMemoryObjectStore();
        var data = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
        await store.PutAsync("a/1", new MemoryStream(data), new ObjectPutOptions(null,
            ExpectedSha256: System.Security.Cryptography.SHA256.HashData(data)));
        await store.PutAsync("a/2", new MemoryStream([1]), new ObjectPutOptions(null));
        await store.PutAsync("b/1", new MemoryStream([1]), new ObjectPutOptions(null));
        await Assert.ThrowsAsync<ObjectIntegrityException>(() =>
            store.PutAsync("a/3", new MemoryStream([1]), new ObjectPutOptions(null, ExpectedSha256: new byte[32])));

        await using var range = await store.GetAsync("a/1", new ByteRange(10, 5));
        var buffer = new byte[5];
        await range.ReadExactlyAsync(buffer);
        Assert.Equal(new byte[] { 10, 11, 12, 13, 14 }, buffer);

        var listed = new List<string>();
        await foreach (var o in store.ListAsync("a/")) listed.Add(o.Key);
        Assert.Equal(["a/1", "a/2"], listed);
        await Assert.ThrowsAsync<ObjectNotFoundException>(() => store.GetAsync("missing"));
    }
}
