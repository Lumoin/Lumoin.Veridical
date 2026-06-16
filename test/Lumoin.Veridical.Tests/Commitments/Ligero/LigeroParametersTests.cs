using Lumoin.Veridical.Core.Commitments.Ligero;
using System;

namespace Lumoin.Veridical.Tests.Commitments.Ligero;

/// <summary>
/// Pins the Ligero layout arithmetic against hand-computed dimensions and the
/// structural invariants every tableau must satisfy: the block/extension
/// relation <c>blockEnc = (2 + rateinv)·block − 1</c>, the witness-block split
/// <c>w ≥ r</c>, and the row count closing exactly on the quadratic triples.
/// </summary>
[TestClass]
internal sealed class LigeroParametersTests
{
    [TestMethod]
    public void DerivesTheHandComputedLayout()
    {
        //block=8, rateinv=2, nreq=2, nw=10, nq=3:
        //  r=2, w=6, dblock=15, blockExt=16, blockEnc=31=(2+2)·8−1.
        //  nwrow=ceil(10/6)=2, nqtriples=ceil(3/6)=1, nwqrow=2+3=5, nrow=8.
        //  iw=3, iq=5, iqx=5, iqy=6, iqz=7.
        LigeroParameters p = new(witnessCount: 10, quadraticConstraintCount: 3, inverseRate: 2, openedColumnCount: 2, block: 8);

        Assert.AreEqual(2, p.RandomCount, "random blinding entries per block");
        Assert.AreEqual(6, p.WitnessPerRow, "witness entries per block");
        Assert.AreEqual(15, p.DoubleBlock, "double block (2·block − 1)");
        Assert.AreEqual(16, p.BlockExtension, "extension columns");
        Assert.AreEqual(31, p.BlockEncoded, "total row length");
        Assert.AreEqual(2, p.WitnessRowCount, "witness rows");
        Assert.AreEqual(1, p.QuadraticTripleCount, "quadratic row triples");
        Assert.AreEqual(5, p.WitnessQuadraticRowCount, "witness and quadratic rows");
        Assert.AreEqual(8, p.RowCount, "total rows");
        Assert.AreEqual(5, p.FirstQuadraticXRowIndex, "first quadratic x-operand row");
        Assert.AreEqual(6, p.FirstQuadraticYRowIndex, "first quadratic y-operand row");
        Assert.AreEqual(7, p.FirstQuadraticZRowIndex, "first quadratic z-product row");
    }


    [TestMethod]
    public void HoldsTheStructuralInvariantsAcrossConfigurations()
    {
        //A spread of valid configurations; each must satisfy the layout identities.
        (int Witnesses, int Quadratics, int Rate, int Opened, int Block)[] configurations =
        [
            (4, 2, 2, 1, 4),
            (10, 3, 2, 2, 8),
            (64, 16, 3, 4, 16),
            (1, 0, 2, 1, 2),
        ];

        foreach((int witnesses, int quadratics, int rate, int opened, int block) in configurations)
        {
            LigeroParameters p = new(witnesses, quadratics, rate, opened, block);

            Assert.AreEqual((2 + rate) * block - 1, p.BlockEncoded, "blockEnc = (2+rateinv)·block − 1");
            Assert.AreEqual(p.DoubleBlock + p.BlockExtension, p.BlockEncoded, "blockEnc = dblock + blockExt");
            Assert.IsGreaterThanOrEqualTo(p.RandomCount, p.WitnessPerRow, "w >= r");
            Assert.AreEqual(p.FirstQuadraticRowIndex + 3 * p.QuadraticTripleCount, p.RowCount, "nrow closes on the quadratic triples");
            Assert.IsLessThanOrEqualTo(p.BlockExtension, p.OpenedColumnCount, "opened columns fit the extension");
        }
    }


    [TestMethod]
    public void RejectsABlockTooSmallForTheOpenedColumns()
    {
        //block < 2·nreq would give w < r, which Ligero forbids.
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = new LigeroParameters(witnessCount: 4, quadraticConstraintCount: 0, inverseRate: 2, openedColumnCount: 3, block: 5));
    }
}
