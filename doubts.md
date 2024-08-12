1. You mention that the usage of `if` statement backed by some context-dependent reasoning is rare... but there are a LOT of instances of `if` statements being used in our circuits. Are they any different than this instance?

2. Where did the name `secp256k1` come from ?

3. 

// STATIC ANALYSIS RULE

1. Flag all the usage of `if` statements in the circuits and those warnings would be dropped if a `SAFETY` comment explains why it is fine to use the `if` statement.
    + Jules wasn't too happy with this idea. Because (this is what I think) he thinks that this is a very CRUDE way to find out about geometric inconsistencies.