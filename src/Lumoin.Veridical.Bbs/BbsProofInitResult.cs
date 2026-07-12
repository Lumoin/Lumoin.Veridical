using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// The proof-initialization tuple <c>(Abar, Bbar, D, T1, T2, domain)</c>
/// produced by <c>ProofInit</c> (Section 3.7.1) on the Prover side and
/// <c>ProofVerifyInit</c> (Section 3.7.3) on the Verifier side of IETF
/// <c>draft-irtf-cfrg-bbs-signatures-10</c>. Both sides feed the same
/// five G1 points and the domain scalar into
/// <c>ProofChallengeCalculate</c>, so one shared shape lets core proof
/// generation and verification — and the blind and pseudonym extension
/// pipelines that build on them — compose the same subroutines.
/// </summary>
/// <remarks>
/// The result owns its six components: disposing it disposes all of
/// them. A factory that receives pre-existing points from its caller
/// (the Verifier side hands in the decoded <c>Abar</c>, <c>Bbar</c>
/// and <c>D</c>) transfers their ownership here on successful
/// construction, and the caller must then dispose them only through
/// this result.
/// </remarks>
internal sealed class BbsProofInitResult: IDisposable
{
    /// <summary>The randomized signature point <c>Abar = A * (r1 * r2)</c>.</summary>
    public G1Point ABar { get; }

    /// <summary>The point <c>Bbar = D * r1 - Abar * e</c>.</summary>
    public G1Point BBar { get; }

    /// <summary>The blinded message commitment <c>D = B * r2</c>.</summary>
    public G1Point D { get; }

    /// <summary>The first Schnorr commitment <c>T1 = Abar * e~ + D * r1~</c>.</summary>
    public G1Point T1 { get; }

    /// <summary>The second Schnorr commitment <c>T2 = D * r3~ + sum_j H_j * m~_j</c>.</summary>
    public G1Point T2 { get; }

    /// <summary>The domain scalar binding the public key, generators, header and api_id.</summary>
    public Scalar Domain { get; }


    public BbsProofInitResult(G1Point aBar, G1Point bBar, G1Point d, G1Point t1, G1Point t2, Scalar domain)
    {
        ArgumentNullException.ThrowIfNull(aBar);
        ArgumentNullException.ThrowIfNull(bBar);
        ArgumentNullException.ThrowIfNull(d);
        ArgumentNullException.ThrowIfNull(t1);
        ArgumentNullException.ThrowIfNull(t2);
        ArgumentNullException.ThrowIfNull(domain);

        ABar = aBar;
        BBar = bBar;
        D = d;
        T1 = t1;
        T2 = t2;
        Domain = domain;
    }


    public void Dispose()
    {
        ABar.Dispose();
        BBar.Dispose();
        D.Dispose();
        T1.Dispose();
        T2.Dispose();
        Domain.Dispose();
    }
}
