using System.Reflection;

namespace Vaulty.Core;

/// <summary>Product name and version, read once from the assembly that ships with every service.</summary>
public static class ProductInfo
{
    public const string Name = "Vaulty";

    public static string Version { get; } =
        typeof(ProductInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            .Split('+')[0]
        ?? "0.0.0";
}
