namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The outcome of verifying a Longfellow JWT statement proof. The public mirror of the driver's internal
/// result so the verdict cause is observable without exposing the internal verifier surface.
/// </summary>
public enum LongfellowJwtVerdict
{
    /// <summary>The proof verified against the statement and the recomputed key-binding digest.</summary>
    Accepted = 0,

    /// <summary>The presented key-binding JWS failed structural parsing, or its signature segment's strict unpadded base64url decoded length is below the fixed-width r‖s pair.</summary>
    MalformedKeyBinding = 1,

    /// <summary>The proof envelope's commitment root, sumcheck segment, or Ligero segment failed to parse.</summary>
    MalformedProof = 2,

    /// <summary>The envelope parsed but verification rejected it.</summary>
    Rejected = 3
}
