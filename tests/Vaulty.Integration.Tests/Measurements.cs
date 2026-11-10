namespace Vaulty.Integration.Tests;

/// <summary>
/// Tests that measure time or memory of the whole process run in this collection: alone, after the parallel tests, so other
/// tests in the same process cannot distort what they measure.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class MeasurementsCollection
{
    public const string Name = "Measurements";
}
