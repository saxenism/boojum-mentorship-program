# Understanding Boojum

## Notes from session 1

1. **Verifying Key:** explains to the verifier exactly what the structure of the circuit is that we're checking.
    + Since we want this *verifying key* to be consistent for the verifier we cannot allow conditional statements or loops of variable length to exist in the circuit since that make the circuits non-deterministic. For instance some branching code can produce different instructions depending on some variable.
2. An important paradigm of programming ZK circuits is that, *any variable we are using inside the circuit needs to be explicitly allocated. Furthermore, anything that isn't a direct input should always be computed with circuit functions and not native code*
    + Native code: Rust code
    + This paradigm is pointing towards the issue of *underconstraining*.
    + For instance, if you have some circuit which, in the middle of lots of operations, performs a hash and uses its output in the rest of circuit, if you perform this hash out-of-the-circuit, and then use the output in the circuit, you have no way of verifying what input you actually used for the hash function. This obviously is BAD, since it opens the gates for cheating massively.


```rust

// @note the number of cycles can at most be `limit`
for _cycle in 0..limit { // `limit` here is defined as the upper bound of sponge hash cycles we perform in the circuit. We can not hash more than `limit` amount of cycles, and we always make constraints for `limit` amount of cycles.
    let queue_is_empty = queue.is_empty(cs);
    let should_pop = queue_is_empty.negated(cs);

    let (output, _) = queue.pop_front(cs, should_pop);

    let now_empty = queue.is_empty(cs);
    // @follow-up Could we have used the regular AND function here?
    // @follow-up Link: https://github.com/matter-labs/era-boojum/blob/main/src/gadgets/boolean/mod.rs#L268
    let is_last_serialization = Boolean::multi_and(cs, &[should_pop, now_empty]); // A lot of these first few lines are just about understanding what state we're in
    use crate::base_structures::ByteSerializable;
    let as_bytes = output.into_bytes(cs); // Decompose a chunk of the input into separate bytes to work on. Note how this operation is constrained

    // @follow-up What is the buffer thing? Where did it come from?
    assert!(buffer.len() < 136);

    // @follow-up  Input? or Output? since as_bytes is the result of calling into_bytes on the output
    // @audit-ok I get it. It's fine. Like, it is the output, but not the final output, it's just a more      
    //           processed input.
    buffer.extend(as_bytes); // Absorb bytes from the input, as you would in a native keccak function

    // @follow-up Where did this `done` come up from?
    let continue_to_absorb = done.negated(cs);

    if buffer.len() >= 136 {
        // @note Array of type Uint8<F> and of length K_R_B and it's taking a slice of the first 136 elements from buffer
        let buffer_for_round: [UInt8<F>; KECCAK_RATE_BYTES] = buffer[..136].try_into().unwrap();
        let buffer_for_round = buffer_for_round.map(|el| el.get_variable());
        let carry_on = buffer[136..].to_vec();

        buffer = carry_on;

        // absorb if we are not done yet
        keccak256_conditionally_absorb_and_run_permutation(
            cs,
            continue_to_absorb,
            &mut keccak_accumulator_state,
            &buffer_for_round,
        ); // essentially, here we do a 'conditional sponge hash'. We only update the accumulator if the flag is true, but we always incur the constraints for the entire permutation. If the flag is false, we simply do so on an empty buffer and discard the output.
    }

    assert!(buffer.len() < 136);

    // in case if we do last round
    {
        // Every single hashing round, we also perform the 'last permutation' of the keccak code. Since we can't know in advance where to place this last hashing round, we do it at every step so we can accommodate any kind of input size
        // Based on the state variables allocated at the beginning of the loop, we ensure that we absorb correctly - i.e., we only absorb if it is the last round
        let absorb_as_last_round =
            Boolean::multi_and(cs, &[continue_to_absorb, is_last_serialization]);
        let mut last_round_buffer = [zero_u8; KECCAK_RATE_BYTES];
        let tail_len = buffer.len();
        last_round_buffer[..tail_len].copy_from_slice(&buffer);

        // Performs some padding
        if tail_len == KECCAK_RATE_BYTES - 1 {
            // unreachable, but we set it for completeness
            last_round_buffer[tail_len] = UInt8::allocated_constant(cs, 0x81);
        } else {
            last_round_buffer[tail_len] = UInt8::allocated_constant(cs, 0x01);
            last_round_buffer[KECCAK_RATE_BYTES - 1] = UInt8::allocated_constant(cs, 0x80);
        }

        let last_round_buffer = last_round_buffer.map(|el| el.get_variable());

        // absorb if it's the last round
        keccak256_conditionally_absorb_and_run_permutation(
            cs,
            absorb_as_last_round,
            &mut keccak_accumulator_state,
            &last_round_buffer,
        ); // Again, conditionally applying the permutation. if it isnt the last round, this incurs a lot of constraints but the inputs and outputs are considered irrelevant and are not used in the rest of the circuit (though they are allocated).
    }

    done = Boolean::multi_or(cs, &[done, is_last_serialization]); // Check the done flag which is used on further loop iterations
}
```


3. This was a pretty good example to understand how to design a circuit that produces an indentical trace for every invocation irrespective of the input size.
    + The constant checking of state and the `conditional` permutation calls and the repitition of the `last hashing step` in every cycle of the loop all fit together with the rules that we studied earlier.

4. However one strange thing is the usage of `if buffer.len() >= 136`. This breaks the rule of *no conditionals with out-of-circuit variables*.
    + To understand that, we need to have some context-dependent reasoning. So, in the original keccak algorithm, for any buffer length <136, the code is skipped. So, there is NEVER a case where we would want to constraint the other branch of buffer <136 since that never happens and is essentially overconstraining the circuit, bc that constraint is NOT required to cover the full execution trace of the keccak256 call.

---

# Task 

1. Implement a circuit that constraints the signing and verifying of a message with ECDSA using the secp256k1 curve.

2. Fixtures(whatever that means) for secp256k1 exist here: https://github.com/matter-labs/era-zkevm_circuits/tree/v1.4.1/src/ecrecover/secp256k1

3. A good example of how to use curves and non-native fields will be in the [ecrecover circuit](https://github.com/matter-labs/era-zkevm_circuits/tree/v1.4.1/src/ecrecover)

4. Here's a rough image of what this would look like:
    + Your inputs would be:
        + Private key scalar
        + Random Scalar
        + Some message (can be fixed length initially)
        + Some public key
    + Then follow the algorithm steps (The Signature Generation Algorithm and The Signature Verification Algorithm) to see if you were able to constrain both the signing and verification procedure.
    + Compute the signature out-of-circuit and make it an input to your circuit so that you can compare it to the in-circuit produced signature.
    + This will obviously require you to implement an out-of-circuit ECDSA implementation. Ig we will go with Python
    + Split the signing and verification into 2 different circuits
    + AFTER all this is done, modify your circuit such that
        +  it can do multiple signings and verifications AND pass in a variable-length set of inputs (can have an upper bound)
    + Check out the [Boojum gadgets](https://github.com/matter-labs/era-boojum/tree/main/src/gadgets) available to you. This library of handy tools can help you grasp what you can and can't do in a circuit.
        + These gadgets are your glossary of operations for a programming language and this is how you will compose the circuits together.
        + Examples of HOW to use them is plentiful. Everything inside the [zkevm circuit repo](https://github.com/matter-labs/zkevm_circuits/) is an example.
    + DO NOT forget to test your circuits as well. As to how to do that, look at how the `zkevm_circuits` do it and try to emulate that. Do not forget to add `failing` test-cases too, such that we know that your circuit does not accept just about anything :P


### ECDSA Algorithm

1. The ECDSA algorithm is based on the fundamental principles of Elliptic curve cryptography that is the discrete log problem. Given a point P that is represented as xG, it's statistically impossible to *guess* x.

2. The ECDSA algorithm is used to generate keys, authenticate, sign and verify messages.

3. An Ethereum EOA address is the last 20 bytes of the hash of the public key controlling the account. AND, it is impossible to derive the private key out of the public key. The private key is used to sign stuff and with the ECDSA algo, we can ascertain that the private key indeed signed a given message if it generates the intended public key.

4. The secp256k1 is the specific curve used in ECDSA. Two signatures exist for one signer at any point on the curve (the other identical point is the mirror image across the x-axis). This fact needs to be taken care of to avoid the `replay` attacks where the attacker can compute a second valid signature.

5. **Order n** of the subgroup of elliptic curve points, generated by G, which defines the length of the private key and is a prime number: `115792089237316195423570985008687907852837564279074904382605163141518161494337`

6. The Ethereum ECDSA signatures contain 3 integers: r,s and v.
    + r is the x coordinate
    + s serves as the proof of the signer's knowledge of the private key
    + `v` is used to recover public keys from the value of r and represents the index of the point of the elliptic curve used for the signature. The recovery process generates multiple solutions for the possible values of R. The addition of `v` specifies which solution is required.


7. What is the public and the private key?
    + Well, the private key `p` is a random number between [0...n-1]
    + And the public key is a point on the EC with the value `pG`.
    + This is the ground-work for the hard discrete log problem (ECDLP)
        + The only feasible threat to these kind of *hard* problems are quantum computers.

8. 