# Serialization

Serialization is a feature we don't focus too much of our effort on (Since we care more about the
correctness of the actual Incremental RTA algorithm). But regardless, it is still a VERY important
part of our system and also the **biggest bottleneck** of the whole process.

Since the current serialization method is probably **not the best**, we try to make it such that the actual algorithm
does not depend on the serialization method we do here.

> tl;dr
> 
> The process is as follows:
> 1. Serialize the ssa, rta, etc. with bare minimum info we need. (i.e. Only fn name + pkg, etc.)
> 2. Deserialize by looking for the same function in the new program.

The serialization process is quite simple. We serialize based on the proto definition found in
the `proto` folder.

As of October 21, 2025. We are currently only serializing 2 forms of SSA:

1. Functions
2. Call Sites

The information we store is the signature, name and package of the function.
An `ssa.Function` contains way more information than what
we store (for example blocks & instrs). However this is
fine because in our deserialization process, we don't reconstruct an
`ssa.Function`, rather we look for the function with these traits in our
new program.

For call sites, the actual type for this is `ssa.CallInstruction`.
The way I serialize this is by storing the parent function
(which fn this instr comes from), signature and some index.
The reason it's fine to store index here is because assume
the index has changed. That means, the function has changed
and we would **NOT CARE** if this instruction is discarded in
our deserialization because it would be in changedFn and
would be reprocessed either ways.