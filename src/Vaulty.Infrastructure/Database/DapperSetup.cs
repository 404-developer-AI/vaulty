using System.Runtime.CompilerServices;

namespace Vaulty.Infrastructure.Database;

internal static class DapperSetup
{
    /// <summary>Columns are snake_case, properties PascalCase: map them for every Dapper query in every process.</summary>
    [ModuleInitializer]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA2255", Justification = "Process-wide mapping convention, set once.")]
    internal static void Initialize() => Dapper.DefaultTypeMap.MatchNamesWithUnderscores = true;
}
