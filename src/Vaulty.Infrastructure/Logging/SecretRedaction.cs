using System.Diagnostics.CodeAnalysis;
using Serilog.Core;
using Serilog.Events;
using Vaulty.Core.Abstractions;

namespace Vaulty.Infrastructure.Logging;

/// <summary>Serilog destructuring policy: a <see cref="Secret"/> is always logged as "[redacted]", also with @-destructuring.</summary>
public sealed class SecretDestructuringPolicy : IDestructuringPolicy
{
    public bool TryDestructure(object value, ILogEventPropertyValueFactory propertyValueFactory,
        [NotNullWhen(true)] out LogEventPropertyValue? result)
    {
        if (value is Secret)
        {
            result = new ScalarValue(Secret.Redacted);
            return true;
        }
        result = null;
        return false;
    }
}
