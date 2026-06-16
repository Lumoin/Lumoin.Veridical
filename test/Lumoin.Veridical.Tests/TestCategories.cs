namespace Lumoin.Veridical.Tests;

/// <summary>
/// Shared MSTest category names. Centralising the literal keeps the <c>[TestCategory(...)]</c> attributes and the
/// CI filters in agreement: the regular build runs <c>--filter "TestCategory!=Slow"</c> and the slow-proof-gate
/// workflow runs <c>--filter "TestCategory=Slow"</c>, both keyed on <see cref="Slow"/>. Change the name here and
/// the attributes follow; the two workflow filter strings are the only places that must be updated in lockstep.
/// </summary>
internal static class TestCategories
{
    /// <summary>The multi-minute end-to-end proof gates — excluded from the regular build, run on demand.</summary>
    public const string Slow = "Slow";
}
