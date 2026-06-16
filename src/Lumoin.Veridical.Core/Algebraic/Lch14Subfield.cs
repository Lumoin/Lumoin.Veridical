namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The GF(2)-subfield of <c>GF(2^128)</c> an <see cref="Lch14AdditiveFft"/> transforms over — the
/// <c>subfield_log_bits</c> template parameter of google/longfellow-zk's <c>GF2_128&lt;&gt;</c>. The
/// subfield fixes the generator <c>g</c>, the basis <c>β_j = g^j</c>, the evaluation nodes and so
/// the codewords; two transforms over different subfields share no bytes.
/// <para>
/// The two instantiations serve different roles. The production mdoc path
/// (<c>lib/circuits/mdoc/mdoc_zk.cc</c>) takes <c>GF2_128&lt;&gt;</c> at its default — the
/// <see cref="Production16"/> subfield — so a wire-format conformant codeword is the one that
/// subfield produces. The reference's LCH14 unit tests run on <c>GF2_128&lt;5&gt;</c> — the
/// <see cref="TestParity32"/> subfield — and the port pins that set as well to anchor every gate to
/// the reference's own test vectors.
/// </para>
/// </summary>
public enum Lch14Subfield
{
    /// <summary>
    /// The <c>GF(2^16)</c> subfield — <c>subfield_log_bits = 4</c>, <c>16</c> basis vectors. The
    /// default of the reference's <c>GF2_128&lt;&gt;</c> and the subfield the production mdoc proof
    /// commits over, so this is the wire-format conformant instantiation. The default.
    /// </summary>
    Production16 = 0,

    /// <summary>
    /// The <c>GF(2^32)</c> subfield — <c>subfield_log_bits = 5</c>, <c>32</c> basis vectors. The
    /// <c>GF2_128&lt;5&gt;</c> instantiation the reference's LCH14 unit tests use; carried so the
    /// port pins the reference's test vectors as well as the production set.
    /// </summary>
    TestParity32 = 1,
}
