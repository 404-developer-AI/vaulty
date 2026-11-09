using System.Text;
using Vaulty.Connectors.Drive;

namespace Vaulty.Graph.Tests;

public sealed class QuickXorHashTests
{
    // Published reference values of the algorithm (Microsoft's description and independent implementations).
    [Theory]
    [InlineData("", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("J", "SgAAAAAAAAAAAAAAAQAAAAAAAAA=")]
    [InlineData("hello world", "aCgDG9jwBhDc4Q1yawMZAAAAAAA=")]
    public void Matches_the_reference_values(string input, string expected) =>
        Assert.Equal(expected, QuickXorHash.Base64(Encoding.UTF8.GetBytes(input)));

    [Fact]
    public void Gives_the_same_hash_whatever_the_split_into_blocks()
    {
        var data = new byte[1_000_003];
        new Random(3).NextBytes(data);
        var expected = QuickXorHash.Base64(data);
        var random = new Random(4);
        for (var round = 0; round < 20; round++)
        {
            var hash = new QuickXorHash();
            for (var at = 0; at < data.Length;)
            {
                var count = Math.Min(data.Length - at, random.Next(1, 5_000));
                hash.Append(data.AsSpan(at, count));
                at += count;
            }
            Assert.Equal(expected, Convert.ToBase64String(hash.Finish()));
        }
    }
}
