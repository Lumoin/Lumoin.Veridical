using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates the SHA-256 word toolkit (<see cref="Sha256Gadget"/>) — the 32-bit words held as
/// boolean bit wires over the Fp256 Ligero constraint system — against plain C# 32-bit
/// arithmetic. Each operation's in-circuit result is read back and compared to the integer
/// reference, and the constraint system is confirmed internally consistent with the
/// prover-independent <see cref="LigeroConstraintEvaluator"/>. These are the building blocks
/// the SHA-256 compression composes from.
/// </summary>
[TestClass]
internal sealed class Sha256GadgetTests
{
    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;

    private static readonly (uint A, uint B)[] Vectors =
    [
        (0xDEADBEEFu, 0x12345678u),
        (0x00000000u, 0xFFFFFFFFu),
        (0x00000001u, 0x80000000u),
        (0xAAAAAAAAu, 0x55555555u),
        (0x6A09E667u, 0xBB67AE85u),
    ];

    private readonly List<LigeroConstraintSystemBuilder> builders = [];


    [TestCleanup]
    public void DisposeBuilders()
    {
        foreach(LigeroConstraintSystemBuilder builder in builders)
        {
            builder.Dispose();
        }
    }


    [TestMethod]
    public void BitwiseOperationsMatchPlainArithmetic()
    {
        foreach((uint a, uint b) in Vectors)
        {
            LigeroConstraintSystemBuilder builder = NewBuilder();
            var sha = new Sha256Gadget(builder);
            int[] wa = sha.WitnessWord(a);
            int[] wb = sha.WitnessWord(b);

            Assert.AreEqual(a ^ b, sha.WordValue(sha.Xor(wa, wb)), $"XOR of {a:X8},{b:X8}.");
            Assert.AreEqual(a & b, sha.WordValue(sha.And(wa, wb)), $"AND of {a:X8},{b:X8}.");
            Assert.AreEqual(a | b, sha.WordValue(sha.Or(wa, wb)), $"OR of {a:X8},{b:X8}.");
            Assert.AreEqual(~a, sha.WordValue(sha.Not(wa)), $"NOT of {a:X8}.");

            Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), $"Bitwise constraints for {a:X8},{b:X8} must be consistent.");
        }
    }


    [TestMethod]
    public void AdditionIsModuloTwoToThe32()
    {
        foreach((uint a, uint b) in Vectors)
        {
            LigeroConstraintSystemBuilder builder = NewBuilder();
            var sha = new Sha256Gadget(builder);
            int[] wa = sha.WitnessWord(a);
            int[] wb = sha.WitnessWord(b);

            Assert.AreEqual(unchecked(a + b), sha.WordValue(sha.AddMod32(wa, wb)), $"({a:X8} + {b:X8}) mod 2^32.");
            Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), "Addition constraints must be consistent.");
        }

        //A five-operand add (the SHA round's T1 has five terms) wraps correctly.
        LigeroConstraintSystemBuilder multi = NewBuilder();
        var multiSha = new Sha256Gadget(multi);
        uint[] values = [0xF0000000u, 0x20000000u, 0x30000000u, 0x10000000u, 0x0000007Fu];
        int[][] words = new int[values.Length][];
        for(int i = 0; i < values.Length; i++)
        {
            words[i] = multiSha.WitnessWord(values[i]);
        }

        uint expected = 0;
        foreach(uint value in values)
        {
            expected = unchecked(expected + value);
        }

        Assert.AreEqual(expected, multiSha.WordValue(multiSha.AddMod32(words)), "Five-operand modular sum.");
        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(multi), "Multi-operand addition constraints must be consistent.");
    }


    [TestMethod]
    public void RotationsAndShiftsMatchPlainArithmetic()
    {
        foreach((uint a, uint _) in Vectors)
        {
            LigeroConstraintSystemBuilder builder = NewBuilder();
            var sha = new Sha256Gadget(builder);
            int[] wa = sha.WitnessWord(a);

            foreach(int n in new[] { 1, 6, 7, 11, 13, 16, 17, 18, 22, 25, 31 })
            {
                Assert.AreEqual(BitOperations.RotateRight(a, n), sha.WordValue(Sha256Gadget.RotateRight(wa, n)), $"ROTR({a:X8}, {n}).");
            }

            foreach(int n in new[] { 1, 3, 10, 16, 31 })
            {
                Assert.AreEqual(a >> n, sha.WordValue(sha.ShiftRight(wa, n)), $"SHR({a:X8}, {n}).");
            }

            Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), $"Rotation/shift constraints for {a:X8} must be consistent.");
        }
    }


    [TestMethod]
    public void HashMatchesSha256AcrossBlockBoundaries()
    {
        //In-circuit SHA-256 matches the platform implementation across the padding boundaries
        //(55 → 1 block, 56 → 2, 119 → 2, 120 → the length spills to a 3rd), read back via the
        //digest words. The constraint logic — schedule, 64 rounds, the Ch/Maj/Σ/σ functions,
        //and the multi-block chaining — is what is gated; checked with the evaluator so it stays
        //fast (~25k constraints per block).
        Span<byte> digest = stackalloc byte[32];
        foreach(int length in new[] { 0, 3, 55, 56, 119, 120 })
        {
            byte[] message = new byte[length];
            for(int i = 0; i < length; i++)
            {
                message[i] = (byte)((i * 31) + 7);
            }

            LigeroConstraintSystemBuilder builder = NewBuilder();
            var sha = new Sha256Gadget(builder);

            int[][] digestWords = sha.Hash(message);
            sha.DigestBytes(digestWords, digest);

            Assert.IsTrue(digest.SequenceEqual(SHA256.HashData(message)), $"In-circuit SHA-256 of {length} bytes must match the reference.");
            Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), $"SHA-256 constraints ({length} bytes) must be consistent.");
        }
    }


    [TestMethod]
    public void HashFromByteWiresMatchesSha256()
    {
        //The byte-wire hashing path (the message witnessed once, shareable with the CBOR
        //gadget) produces the same digest as the platform implementation across block
        //boundaries; assembling words from bytes also pins each byte to [0,255].
        Span<byte> digest = stackalloc byte[32];
        foreach(int length in new[] { 0, 32, 56, 100 })
        {
            byte[] message = new byte[length];
            for(int i = 0; i < length; i++)
            {
                message[i] = (byte)((i * 17) + 3);
            }

            LigeroConstraintSystemBuilder builder = NewBuilder();
            var sha = new Sha256Gadget(builder);
            int[] byteWires = builder.WitnessMessage(message);

            int[][] digestWords = sha.Hash(byteWires);
            sha.DigestBytes(digestWords, digest);

            Assert.IsTrue(digest.SequenceEqual(SHA256.HashData(message)), $"Byte-wire SHA-256 of {length} bytes must match the reference.");
            Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), $"SHA-256 (byte wires, {length} bytes) constraints must be consistent.");
        }
    }


    private LigeroConstraintSystemBuilder NewBuilder()
    {
        var builder = new LigeroConstraintSystemBuilder(
            P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
            CurveParameterSet.None, InverseRate, OpenedColumns, Block, BaseMemoryPool.Shared);
        builders.Add(builder);

        return builder;
    }
}
