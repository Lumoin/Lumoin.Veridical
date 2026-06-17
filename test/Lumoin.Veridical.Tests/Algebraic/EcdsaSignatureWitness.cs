using Lumoin.Veridical.Backends.Managed;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The C# port of <c>VerifyWitness3::compute_witness</c> +
/// <c>VerifyWitness3::fill_witness</c>
/// (<c>tempdocs/longfellow-zk-reference/lib/circuits/ecdsa/verify_witness.h</c>)
/// for the P-256/SHA-256 ECDSA verification circuit: given one public signature
/// triple <c>(pkX, pkY, e, r, s)</c> it lays out the 1034-element dense witness
/// column the circuit's nonce-recovery assertion reads, in the exact
/// <c>fill_witness</c> emit order, as canonical (non-Montgomery) 32-byte
/// big-endian base-field scalars.
/// </summary>
/// <remarks>
/// <para>
/// The circuit asserts the identity <c>id = g·e + pk·r + (rx,ry)·(−s)</c>
/// (verify_witness.h:72-74): for a valid signature <c>R = (e/s)·G + (r/s)·Q</c>,
/// so <c>e·G + r·Q − s·R = O</c> and the double-and-add accumulator the witness
/// records (the <c>int_x/int_y/int_z</c> projective intermediates) terminates at
/// the point at infinity. This filler reproduces every value that assertion
/// consumes; <see cref="EcdsaSignatureWitnessTests"/> gates each region.
/// </para>
/// <para>
/// Output discipline (the column is CANONICAL, non-Montgomery): the reference's
/// <c>to_bytes_field</c> strips Montgomery (fp_generic.h:378-380), so each
/// element here is a plain <see cref="BigInteger"/> reduced mod <c>p</c> (the
/// base field) or mod <c>n</c> (the scalar field) and emitted big-endian via
/// <see cref="EcdsaNonceRecovery.Bytes"/> — the library's <c>Scalar</c> form.
/// All point arithmetic reuses <see cref="EcdsaNonceRecovery"/> (the affine
/// oracle) and <see cref="ProjectivePointFp256"/> (the un-normalized projective
/// ladder), so the recorded intermediates match the reference operation order.
/// </para>
/// </remarks>
internal static class EcdsaSignatureWitness
{
    //EC::kBits for P-256: the scalar-multiply loop runs over the 256-bit window MSB-first (verify_witness.h:38, 147).
    private const int Bits = 256;

    //The fixed element count fill_witness emits: rx,ry,rx_inv,s_inv,pk_inv (5) + pre_[0..7] (8) +
    //per i=0..255 bi_[i] (256) + per i=0..254 int_x/int_y/int_z (3·255 = 765). Total 5+8+256+765 = 1034.
    public const int ElementCount = 5 + 8 + Bits + (3 * (Bits - 1));

    private static readonly BigInteger Prime = EcdsaNonceRecovery.P;


    /// <summary>
    /// Builds the 1034-element <c>VerifyWitness3</c> column for the signature
    /// triple <c>(pkX, pkY, e, r, s)</c>, in <c>fill_witness</c> order
    /// (verify_witness.h:53-70). Each element is a canonical 32-byte big-endian
    /// base-field scalar. The values reproduce <c>compute_witness</c>
    /// (verify_witness.h:75-197) operation-for-operation.
    /// </summary>
    public static IReadOnlyList<byte[]> Fill(BigInteger pkX, BigInteger pkY, BigInteger e, BigInteger r, BigInteger s)
    {
        Computed computed = Compute(pkX, pkY, e, r, s);
        var column = new List<byte[]>(ElementCount);

        //fill_witness, verify_witness.h:54-58 — rx, ry, rx_inv, s_inv, pk_inv.
        column.Add(Element(computed.Rx));
        column.Add(Element(computed.Ry));
        column.Add(Element(computed.RxInverse));
        column.Add(Element(computed.SInverse));
        column.Add(Element(computed.PkInverse));

        //fill_witness, verify_witness.h:59-61 — pre_[0..7], the normalized precomputed table as x,y pairs.
        for(int i = 0; i < 8; i++)
        {
            column.Add(Element(computed.Pre[i]));
        }

        //fill_witness, verify_witness.h:62-69 — per i: bi_[i], then (for i < kBits-1) int_x/int_y/int_z[i].
        for(int i = 0; i < Bits; i++)
        {
            column.Add(Element(computed.Bi[i]));
            if(i < Bits - 1)
            {
                column.Add(Element(computed.IntX[i]));
                column.Add(Element(computed.IntY[i]));
                column.Add(Element(computed.IntZ[i]));
            }
        }

        return column;
    }


    /// <summary>
    /// Computes every region's values (the structured form behind <see cref="Fill"/>),
    /// exposed so the region gate can assert each independently against an oracle.
    /// </summary>
    public static Computed Compute(BigInteger pkX, BigInteger pkY, BigInteger e, BigInteger r, BigInteger s)
    {
        //verify_witness.h:78-90 — R recovery R = nes·G + nrs·Q with nes = e·s⁻¹, nrs = r·s⁻¹ (mod n).
        //(rx,ry) = R normalized; the canonical base-field rx equals the signature r (verify_witness.h:74,92).
        //EcdsaNonceRecovery.RecoverNoncePoint forms exactly (e/s)·G + (r/s)·Q over the scalar field.
        (BigInteger X, BigInteger Y) noncePoint = EcdsaNonceRecovery.RecoverNoncePoint(pkX, pkY, e, r, s);

        BigInteger rx = ModP(r);
        BigInteger ry = noncePoint.Y;

        //verify_witness.h:96-99 — rx_inv = rx⁻¹ in the base field (rx ≠ 0 for a sound input).
        BigInteger rxInverse = ModInverseP(rx);

        //verify_witness.h:101-104 — s_inv: take nms = (−s) mod n (a Nat), REINTERPRET it as a base-field
        //element (F.to_montgomery(fn_.from_montgomery(tms)) lifts the integer into Fp), then invert in Fp.
        //nms < n < p, so the reinterpretation is the same integer; the inversion is mod p, not mod n.
        BigInteger nms = EcdsaNonceRecovery.ModN(-s);
        BigInteger sInverse = ModInverseP(nms);

        //verify_witness.h:106-108 — pk_inv = pkX⁻¹ in the base field.
        BigInteger pkInverse = ModInverseP(pkX);

        //verify_witness.h:112-138 — the normalized precomputed table.
        //pre[0,1]=g+pk; pre[2,3]=g+R; pre[4,5]=pk+R; pre[6,7]=(g+R)+pk = g+r+pk. Each affine (normalized).
        (BigInteger X, BigInteger Y) gPlusPk = EcdsaNonceRecovery.AffineAdd(EcdsaNonceRecovery.G, (pkX, pkY));
        (BigInteger X, BigInteger Y) gPlusR = EcdsaNonceRecovery.AffineAdd(EcdsaNonceRecovery.G, (rx, ry));
        (BigInteger X, BigInteger Y) pkPlusR = EcdsaNonceRecovery.AffineAdd((pkX, pkY), (rx, ry));
        (BigInteger X, BigInteger Y) gRPk = EcdsaNonceRecovery.AffineAdd(gPlusR, (pkX, pkY));

        BigInteger[] pre =
        [
            gPlusPk.X, gPlusPk.Y,
            gPlusR.X, gPlusR.Y,
            pkPlusR.X, pkPlusR.Y,
            gRPk.X, gRPk.Y,
        ];

        //verify_witness.h:147-187 — the muxed double-and-add ladder. Per i (MSB-first over the 256-bit window):
        //b[i] = e.bit(255−i) + 2·r.bit(255−i) + 4·nms.bit(255−i); bi_[i] = of_scalar(2·b[i]) − of_scalar(7);
        //if i>0 double; then add the muxed point for b[i]; then store the UN-NORMALIZED projective (aX,aY,aZ).
        var bi = new BigInteger[Bits];
        var intX = new BigInteger[Bits];
        var intY = new BigInteger[Bits];
        var intZ = new BigInteger[Bits];

        //The mux table (verify_witness.h:142-143, 157-182): 0=identity, 1=g, 2=pk, 3=g+pk(pre0,1),
        //4=R, 5=g+R(pre2,3), 6=pk+R(pre4,5), 7=g+r+pk(pre6,7).
        ProjectivePointFp256[] mux =
        [
            ProjectivePointFp256.Identity,
            ProjectivePointFp256.FromAffine(EcdsaNonceRecovery.G),
            ProjectivePointFp256.FromAffine((pkX, pkY)),
            ProjectivePointFp256.FromAffine(gPlusPk),
            ProjectivePointFp256.FromAffine((rx, ry)),
            ProjectivePointFp256.FromAffine(gPlusR),
            ProjectivePointFp256.FromAffine(pkPlusR),
            ProjectivePointFp256.FromAffine(gRPk),
        ];

        ProjectivePointFp256 accumulator = ProjectivePointFp256.Identity;
        for(int i = 0; i < Bits; i++)
        {
            int position = Bits - i - 1;
            int b = Bit(e, position) + (2 * Bit(r, position)) + (4 * Bit(nms, position));

            //verify_witness.h:152 — bi_[i] = of_scalar(2·b) − of_scalar(7), the (−7..7) symmetric encoding over Fp.
            bi[i] = ModP((2 * b) - 7);

            if(i > 0)
            {
                accumulator = ProjectivePointFp256.Double(accumulator);
            }

            accumulator = ProjectivePointFp256.Add(accumulator, mux[b]);

            //verify_witness.h:184-186 — store AFTER the double+add for this i (the column emits int for i<255).
            intX[i] = accumulator.X;
            intY[i] = accumulator.Y;
            intZ[i] = accumulator.Z;
        }

        return new Computed(rx, ry, rxInverse, sInverse, pkInverse, pre, bi, intX, intY, intZ, accumulator);
    }


    //Manually compute the standard symmetric residue mod p (the result of of_scalar over Fp), keeping
    //negative inputs in [0, p). The value of_scalar(2b)−of_scalar(7) is the integer (2b−7) reduced mod p.
    private static BigInteger ModP(BigInteger value) => ((value % Prime) + Prime) % Prime;

    private static BigInteger ModInverseP(BigInteger value) => BigInteger.ModPow(ModP(value), Prime - 2, Prime);


    //e.bit(j): the j-th bit (LSB index 0) of the 256-bit Nat. The reference walks j = kBits−i−1 (MSB-first).
    private static int Bit(BigInteger value, int position) => (int)((value >> position) & BigInteger.One);


    private static byte[] Element(BigInteger value) => EcdsaNonceRecovery.Bytes(value);


    /// <summary>
    /// The structured <c>VerifyWitness3</c> values, in canonical base-field
    /// <see cref="BigInteger"/> form (the same values <see cref="Fill"/> serializes),
    /// exposed for the region-by-region byte-oracle gate.
    /// </summary>
    internal sealed record Computed(
        BigInteger Rx,
        BigInteger Ry,
        BigInteger RxInverse,
        BigInteger SInverse,
        BigInteger PkInverse,
        BigInteger[] Pre,
        BigInteger[] Bi,
        BigInteger[] IntX,
        BigInteger[] IntY,
        BigInteger[] IntZ,
        ProjectivePointFp256 FinalAccumulator);
}
