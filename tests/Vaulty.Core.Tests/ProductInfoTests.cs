using Vaulty.Core;

namespace Vaulty.Core.Tests;

public class ProductInfoTests
{
    [Fact]
    public void Version_is_semantic_and_has_no_build_metadata()
    {
        Assert.Matches(@"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$", ProductInfo.Version);
    }
}
