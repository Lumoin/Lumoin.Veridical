using Lumoin.Veridical.Core.Spartan;
using System;
using System.Buffers.Binary;
using System.Diagnostics;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Shared statistical machinery for the zero-knowledge legs of the
/// Spartan gates: resolves the expected-blinded scoped sections of a
/// <see cref="MaskedSpartanProof"/> and runs a per-byte chi-squared
/// homogeneity test between two groups of proofs produced from distinct
/// secret inputs under a shared randomness seed. A compressed fold proof
/// shares the masked proof's layout, so the same scoped sections and
/// statistics apply. Generalises the approach in
/// <see cref="MaskedSpartanIndistinguishabilityTests"/> for reuse by the
/// fold-chain indistinguishability leg.
/// </summary>
internal static class ScopedProofIndistinguishability
{
    /// <summary>A named byte range within a proof's wire bytes.</summary>
    [DebuggerDisplay("{Name,nq} @{Offset} +{Length}")]
    internal readonly record struct ScopedSection(string Name, int Offset, int Length);


    /// <summary>The outcome of a scoped chi-squared homogeneity gate.</summary>
    [DebuggerDisplay("{PositionCount} positions, {BelowThreshold} below threshold (max chi2 {MaxChiSquared}, min p {MinPValue})")]
    internal readonly record struct HomogeneityResult(
        int PositionCount,
        int Below05,
        int Below01,
        int BelowThreshold,
        double MaxChiSquared,
        double MinPValue,
        int ExtremePosition,
        string? ExtremeSection);


    /// <summary>
    /// Deterministic per-(label, counter) 16-byte seed via BLAKE3.
    /// Reproducibility, not entropy — BLAKE3 satisfies both the analyzer
    /// ban on insecure randomness and the need for distinct seeds.
    /// </summary>
    public static byte[] DeriveSeed(string label, int counter)
    {
        ArgumentNullException.ThrowIfNull(label);

        byte[] labelBytes = System.Text.Encoding.UTF8.GetBytes(label);
        Span<byte> input = stackalloc byte[labelBytes.Length + sizeof(int)];
        labelBytes.AsSpan().CopyTo(input);
        BinaryPrimitives.WriteInt32BigEndian(input[labelBytes.Length..], counter);

        byte[] output = new byte[16];
        Lumoin.Veridical.Hashing.Blake3.Hash(input, output);

        return output;
    }


    /// <summary>
    /// Resolves the expected-blinded scoped sections (masking-polynomial
    /// commitments, masking sums, terminating evaluations, and
    /// masking-polynomial openings) of <paramref name="proof"/> as
    /// absolute byte ranges into its wire bytes. The per-round sumcheck
    /// messages are intentionally excluded — under the multilinear-mask
    /// adaptation their high-degree coefficients carry witness-dependent
    /// information by design.
    /// </summary>
    public static ScopedSection[] ResolveScopedSections(MaskedSpartanProof proof)
    {
        ArgumentNullException.ThrowIfNull(proof);

        ReadOnlySpan<byte> full = proof.AsReadOnlySpan();

        return
        [
            new ScopedSection("outer-mask-commitment", LocateSection(full, proof.GetOuterMaskCommitmentBytes()), proof.GetOuterMaskCommitmentBytes().Length),
            new ScopedSection("inner-mask-commitment", LocateSection(full, proof.GetInnerMaskCommitmentBytes()), proof.GetInnerMaskCommitmentBytes().Length),
            new ScopedSection("outer-mask-sum",        LocateSection(full, proof.GetOuterMaskSumBytes()),        proof.GetOuterMaskSumBytes().Length),
            new ScopedSection("inner-mask-sum",        LocateSection(full, proof.GetInnerMaskSumBytes()),        proof.GetInnerMaskSumBytes().Length),
            new ScopedSection("claim-Az",              LocateSection(full, proof.GetClaimAzBytes()),              proof.GetClaimAzBytes().Length),
            new ScopedSection("claim-Bz",              LocateSection(full, proof.GetClaimBzBytes()),              proof.GetClaimBzBytes().Length),
            new ScopedSection("claim-Cz",              LocateSection(full, proof.GetClaimCzBytes()),              proof.GetClaimCzBytes().Length),
            new ScopedSection("eval-W",                LocateSection(full, proof.GetEvalWBytes()),                proof.GetEvalWBytes().Length),
            new ScopedSection("outer-mask-opening",    LocateSection(full, proof.GetOuterMaskOpeningProofBytes()), proof.GetOuterMaskOpeningProofBytes().Length),
            new ScopedSection("inner-mask-opening",    LocateSection(full, proof.GetInnerMaskOpeningProofBytes()), proof.GetInnerMaskOpeningProofBytes().Length),
        ];
    }


    /// <summary>
    /// Runs a per-byte chi-squared homogeneity test (2 × 256 contingency,
    /// <c>df = 255</c>) across the scoped <paramref name="sections"/>
    /// between equally-sized proof groups, returning the count of byte
    /// positions whose upper-tail p-value falls below
    /// <paramref name="pThreshold"/> plus diagnostics. Zero positions
    /// below the threshold is the expected outcome when the scoped bytes
    /// are uniformly distributed regardless of the secret input.
    /// </summary>
    public static HomogeneityResult RunHomogeneity(
        byte[][] group1,
        byte[][] group2,
        ScopedSection[] sections,
        double pThreshold)
    {
        ArgumentNullException.ThrowIfNull(group1);
        ArgumentNullException.ThrowIfNull(group2);
        ArgumentNullException.ThrowIfNull(sections);

        int positionCount = 0;
        int below05 = 0;
        int below01 = 0;
        int belowThreshold = 0;
        double maxChiSquared = 0.0;
        double minPValue = double.PositiveInfinity;
        int extremePosition = -1;
        string? extremeSection = null;

        foreach(ScopedSection section in sections)
        {
            for(int local = 0; local < section.Length; local++)
            {
                int absolute = section.Offset + local;
                double chiSquared = ChiSquaredForPosition(group1, group2, absolute);
                double p = ChiSquaredPValueDf255(chiSquared);

                positionCount++;
                if(p < 0.05)
                {
                    below05++;
                }
                if(p < 0.01)
                {
                    below01++;
                }
                if(p < pThreshold)
                {
                    belowThreshold++;
                }

                if(chiSquared > maxChiSquared)
                {
                    maxChiSquared = chiSquared;
                    minPValue = p;
                    extremePosition = absolute;
                    extremeSection = section.Name;
                }
            }
        }

        return new HomogeneityResult(
            positionCount, below05, below01, belowThreshold,
            maxChiSquared, minPValue, extremePosition, extremeSection);
    }


    private static int LocateSection(ReadOnlySpan<byte> full, ReadOnlySpan<byte> slice)
    {
        if(!full.Overlaps(slice, out int elementOffset))
        {
            throw new InvalidOperationException("Scoped slice is not a view into the full proof bytes.");
        }

        return elementOffset;
    }


    private static double ChiSquaredForPosition(byte[][] samples1, byte[][] samples2, int position)
    {
        Span<int> counts1 = stackalloc int[256];
        Span<int> counts2 = stackalloc int[256];

        for(int i = 0; i < samples1.Length; i++)
        {
            counts1[samples1[i][position]]++;
            counts2[samples2[i][position]]++;
        }

        //Chi-squared homogeneity test on a 2 × 256 contingency table; equal
        //group sizes (samples1.Length == samples2.Length) simplify expected
        //counts to (counts1[b] + counts2[b]) / 2 per cell. Empty rows (no
        //sample in either group) contribute nothing.
        double chi = 0.0;
        for(int b = 0; b < 256; b++)
        {
            int total = counts1[b] + counts2[b];
            if(total == 0)
            {
                continue;
            }
            double expected = total / 2.0;
            double d1 = counts1[b] - expected;
            double d2 = counts2[b] - expected;
            chi += (d1 * d1 + d2 * d2) / expected;
        }

        return chi;
    }


    private static double ChiSquaredPValueDf255(double chiSquared)
    {
        //Wilson-Hilferty cube-root approximation: for X ~ chi^2(k), the
        //transform ((X/k)^(1/3) - (1 - 2/(9k))) / sqrt(2/(9k)) is approximately
        //standard normal. Excellent accuracy for k = 255.
        const double Df = 255.0;
        const double VarianceTerm = 2.0 / (9.0 * Df);
        double cubeRoot = Math.Cbrt(chiSquared / Df);
        double z = (cubeRoot - (1.0 - VarianceTerm)) / Math.Sqrt(VarianceTerm);

        //One-sided upper-tail p-value: 1 - Phi(z).
        return 0.5 * Erfc(z / Math.Sqrt(2.0));
    }


    private static double Erfc(double x)
    {
        //Abramowitz and Stegun 7.1.26 — max absolute error ~1.5e-7 across
        //the real line, plenty for a p-value comparison against 1e-3.
        double sign = x < 0.0 ? -1.0 : 1.0;
        double a = Math.Abs(x);
        double t = 1.0 / (1.0 + 0.3275911 * a);
        double y = 1.0 - ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.Exp(-a * a);

        return 1.0 - sign * y;
    }
}