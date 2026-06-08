using System.Collections.Generic;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Maps R1CS variable indices to human-readable names for diagnostic
/// formatting. Optional — protocols and instances do not need names to
/// run; the names exist purely to make inspection output legible.
/// </summary>
/// <remarks>
/// <para>
/// Subclasses <see cref="Dictionary{TKey, TValue}"/> to inherit all
/// the standard lookup semantics while adding
/// <see cref="GetOrPlaceholder"/> for the common diagnostic pattern of
/// "use the registered name if there is one, else fall back to the
/// index's <c>x_&lt;value&gt;</c> string form."
/// </para>
/// </remarks>
public sealed class R1csVariableNames: Dictionary<R1csVariableIndex, string>
{
    /// <summary>An empty shared instance for callers that have no variable names to register.</summary>
    public static R1csVariableNames Empty { get; } = [];


    /// <summary>Constructs an empty mapping.</summary>
    public R1csVariableNames() { }


    /// <summary>Constructs a mapping seeded from <paramref name="source"/>.</summary>
    public R1csVariableNames(IDictionary<R1csVariableIndex, string> source) : base(source) { }


    /// <summary>
    /// Returns the registered name for <paramref name="variable"/> if
    /// one exists, otherwise the variable's standard placeholder
    /// representation (<c>x_&lt;value&gt;</c>).
    /// </summary>
    public string GetOrPlaceholder(R1csVariableIndex variable)
    {
        return TryGetValue(variable, out string? name) ? name : variable.ToString();
    }
}