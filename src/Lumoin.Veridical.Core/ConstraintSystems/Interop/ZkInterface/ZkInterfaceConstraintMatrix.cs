namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Selects which of the three R1CS coefficient matrices a pushed
/// constraint term belongs to. A ZkInterface <c>BilinearConstraint</c>
/// is the triple of linear combinations <c>(A)·(B) = (C)</c>; a term
/// reported to <see cref="IZkInterfaceMessageSink.OnConstraintTerm"/>
/// names its matrix with this selector.
/// </summary>
public enum ZkInterfaceConstraintMatrix
{
    /// <summary>The left factor, <c>linear_combination_a</c>.</summary>
    A,

    /// <summary>The right factor, <c>linear_combination_b</c>.</summary>
    B,

    /// <summary>The product, <c>linear_combination_c</c>.</summary>
    C,
}
