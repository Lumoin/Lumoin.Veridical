//The shared Lumoin bedrock namespace: the type-keyed Tag and the secure (Managed/Pinned/Native) byte memory
//pool. Imported globally so unqualified Tag and BaseMemoryPool across this assembly resolve to the
//family-wide Lumoin.Base types, keeping tagged/pooled cryptographic material a single type across package
//boundaries (the BBS+, SECDSA, and other signatures and keys Verifiable consumes).
global using Lumoin.Base;
