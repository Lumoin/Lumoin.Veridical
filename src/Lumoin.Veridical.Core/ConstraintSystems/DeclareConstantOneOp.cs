namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Declares the constant <c>1</c> wire at variable index 0. Every circuit
/// opens with exactly this op; the builder emits it in its constructor so
/// index 0 is the constant before any author-declared variable.
/// </summary>
public sealed record DeclareConstantOneOp: IR1csOp;
