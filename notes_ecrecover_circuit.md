# ecrecover Circuit Notes

## Filename: `ecrecover/baseline.rs`

```rust

#[cfg(test)]
mod test {
    use std::alloc::Global;

    use boojum::field::goldilocks::GoldilocksField;
    use boojum::gadgets::traits::allocatable::CSAllocatable;
    use boojum::pairing::ff::{Field, PrimeField, SqrtField};
    use boojum::worker::Worker;

    use super::*;

    type F = GoldilocksField;
    type P = GoldilocksField;

    use boojum::config::DevCSConfig;

    use boojum::pairing::ff::PrimeFieldRepr;
    use boojum::pairing::{GenericCurveAffine, GenericCurveProjective};
    use rand::Rng;
    use rand::SeedableRng;
    use rand::XorShiftRng;

    /*
        Ok, what the fuck is XorShiftRng?

        Hmph, this XorShiftRng is just a type of PRNG (PseudoRandomNumberGenerator).
        The `from_seed` method simply creates a new instance of `XorShiftRng` from a given seed.
        The seed is typically an array of bytes (typically 16-byte arrays)

        Points to remember is that:
        1. XorShiftRng is deterministic, so it will always produce the same number for a given seed.
        2. It is NOT cryptographically secure, so attackers can reverse-engineer it
        3. It's fast
    */
    pub fn deterministic_rng() -> XorShiftRng {
        XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654])
    }

    /*
        What is this `Secp256Fr` stuff?

        Hmph, this is coming from the file src/ecrecover/mod.rs
        
        // order of group of points for secp curve
        use self::secp256k1::fr::Fr as Secp256Fr;

        The line `let sk: Secp256Fr = rng.gen();` generate a random number of type Secp256Fr

        And what is type Secp256Fr it is basically a number in the group of elements that make up the Secp256k1 curve since the struct Fr is using the `PrimeField` derive macro
    */
    fn simulate_signature() -> (Secp256Fr, Secp256Fr, Secp256Affine, Secp256Fr) {
        let mut rng = deterministic_rng();
        let sk: Secp256Fr = rng.gen();

        simulate_signature_for_sk(sk)
    }

    /*
        What is this transmute_representation function doing?

        It is converting type T into type U. T and U are any generic types that implement the PrimeFieldRepr trait (which likely defines how prime field elements are represented in memory)
    */
    fn transmute_representation<T: PrimeFieldRepr, U: PrimeFieldRepr>(repr: T) -> U {
        assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<U>());

        unsafe { std::mem::transmute_copy::<T, U>(&repr) }
    }

    /*
        This function takes in input sk which is an element of Secp256k1 curve and simulates a signature for that random_point

        The `pk` here seems to be the public key since typically the public key is calculated as pG where p is a random integer and also the private key.
        pk = G*sk in form of affine co-ordinate

        digest -> random number (one of the point on the EC)
        k -> random number (one of the point on the EC)
        R -> kG
        r_x -> R.x

        let r_x = r_point.into_xy_unchecked().0;
        let r = transmute_representation::<_, <Secp256Fr as PrimeField>::Repr>(r_x.into_repr());
        let r = Secp256Fr::from_repr(r).unwrap();

        So, what is happening in the above 2 lines:
        1. The code is taking the x-coordinate of a point on the secp256k1 curve.
        2. It's then converting this x-coordinate into a scalar field element.
        3. This conversion is necessary because in ECDSA (the signature scheme used with secp256k1), the 'r' value of a signature is the x-coordinate of a point, but treated as an element of the scalar field.

        Why is it done?

        1. The x-coordinate is originally in the base field of the curve.
        2. For signature operations, we need it as an element of the scalar field.
        3. The transmute_representation function is used to reinterpret the bits of the x-coordinate as a scalar field element.
        4. This works because in secp256k1, the base field and scalar field have the same bit size, even though they're different fields mathematically.

        k_inv -> inverse of k
        s -> (r * sk + digest) * k_inv  (this is the og formula for calculating signature's s value: `s = k ^ -1 * (h + p  * r) mod n`)

        For reference, verification algo is
        + `s_inv = s ^ -1 (mod n)`
        + `R' = (h * s_inv) * G + (r * s_inv) * pub_key`

        mul_by_generator -> (digest * r_inv).negate // negative means flip over the x-axis. That's it
        mul_by_r -> s * r_inv

        res_1 -> G * ((digest * r_inv).negate())
        res_2 -> r_point * s * r_inv

        tmp -> res_1 + res_2
        assert_eq!(tmp.x, pk.x)

    */
    fn simulate_signature_for_sk(
        sk: Secp256Fr,
    ) -> (Secp256Fr, Secp256Fr, Secp256Affine, Secp256Fr) {
        let mut rng = deterministic_rng();
        let pk = Secp256Affine::one().mul(sk.into_repr()).into_affine();
        let digest: Secp256Fr = rng.gen();
        let k: Secp256Fr = rng.gen();
        let r_point = Secp256Affine::one().mul(k.into_repr()).into_affine();

        let r_x = r_point.into_xy_unchecked().0;
        let r = transmute_representation::<_, <Secp256Fr as PrimeField>::Repr>(r_x.into_repr());
        let r = Secp256Fr::from_repr(r).unwrap();

        let k_inv = k.inverse().unwrap();
        let mut s = r;
        s.mul_assign(&sk);
        s.add_assign(&digest);
        s.mul_assign(&k_inv);

        {
            let mut mul_by_generator = digest;
            mul_by_generator.mul_assign(&r.inverse().unwrap());
            mul_by_generator.negate();

            let mut mul_by_r = s;
            mul_by_r.mul_assign(&r.inverse().unwrap());

            let res_1 = Secp256Affine::one().mul(mul_by_generator.into_repr());
            let res_2 = r_point.mul(mul_by_r.into_repr());

            let mut tmp = res_1;
            tmp.add_assign(&res_2);

            let tmp = tmp.into_affine();

            let x = tmp.into_xy_unchecked().0;
            assert_eq!(x, pk.into_xy_unchecked().0);
        }

        (r, s, pk, digest)
    }

    /*
        U256::zero() is the additive identity of this type
    */

    fn repr_into_u256<T: PrimeFieldRepr>(repr: T) -> U256 {
        let mut u256 = U256::zero(); 
        u256.0.copy_from_slice(&repr.as_ref()[..4]);

        u256
    }

    use boojum::cs::cs_builder::*;
    use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
    use boojum::cs::gates::*;
    use boojum::cs::traits::gate::GatePlacementStrategy;
    use boojum::cs::CSGeometry;
    use boojum::cs::*;
    use boojum::gadgets::tables::byte_split::ByteSplitTable;
    use boojum::gadgets::tables::*;

    #[test]
    fn test_signature_for_address_verification() {
        let geometry = CSGeometry {
            num_columns_under_copy_permutation: 100,
            num_witness_columns: 0,
            num_constant_columns: 8,
            max_allowed_constraint_degree: 4,
        };
        let max_trace_len = 1 << 20;

        fn configure<
            F: SmallField,
            T: CsBuilderImpl<F, T>,
            GC: GateConfigurationHolder<F>,
            TB: StaticToolboxHolder,
        >(
            builder: CsBuilder<T, F, GC, TB>,
        ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
            let builder = builder.allow_lookup(
                LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
                    width: 3,
                    num_repetitions: 8,
                    share_table_id: true,
                },
            );
            let builder = ConstantsAllocatorGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = ReductionGate::<F, 4>::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            // let owned_cs = ReductionGate::<F, 4>::configure_for_cs(owned_cs, GatePlacementStrategy::UseSpecializedColumns { num_repetitions: 8, share_constants: true });
            let builder = BooleanConstraintGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = UIntXAddGate::<32>::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = UIntXAddGate::<16>::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = SelectionGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            let builder = ZeroCheckGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
                false,
            );
            let builder = DotProductGate::<4>::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );
            // let owned_cs = DotProductGate::<4>::configure_for_cs(owned_cs, GatePlacementStrategy::UseSpecializedColumns { num_repetitions: 1, share_constants: true });
            let builder = NopGate::configure_builder(
                builder,
                GatePlacementStrategy::UseGeneralPurposeColumns,
            );

            builder
        }

        let builder_impl =
            CsReferenceImplementationBuilder::<F, P, DevCSConfig>::new(geometry, max_trace_len);
        let builder = new_builder::<_, F>(builder_impl);

        let builder = configure(builder);
        let mut owned_cs = builder.build(1 << 26);

        // add tables
        let table = create_xor8_table();
        owned_cs.add_lookup_table::<Xor8Table, 3>(table);

        let table = create_and8_table();
        owned_cs.add_lookup_table::<And8Table, 3>(table);

        let table = create_byte_split_table::<F, 1>();
        owned_cs.add_lookup_table::<ByteSplitTable<1>, 3>(table);
        let table = create_byte_split_table::<F, 2>();
        owned_cs.add_lookup_table::<ByteSplitTable<2>, 3>(table);
        let table = create_byte_split_table::<F, 3>();
        owned_cs.add_lookup_table::<ByteSplitTable<3>, 3>(table);
        let table = create_byte_split_table::<F, 4>();
        owned_cs.add_lookup_table::<ByteSplitTable<4>, 3>(table);

        let cs = &mut owned_cs;

        let sk = crate::ff::from_hex::<Secp256Fr>(
            "b5b1870957d373ef0eeffecc6e4812c0fd08f554b37b233526acc331bf1544f7",
        )
        .unwrap();
        let eth_address = hex::decode("12890d2cce102216644c59dae5baed380d84830c").unwrap();
        let (r, s, _pk, digest) = simulate_signature_for_sk(sk);

        let scalar_params = secp256k1_scalar_field_params();
        let base_params = secp256k1_base_field_params();

        let digest_u256 = repr_into_u256(digest.into_repr());
        let r_u256 = repr_into_u256(r.into_repr());
        let s_u256 = repr_into_u256(s.into_repr());

        let rec_id = UInt8::allocate_checked(cs, 0);
        let r = UInt256::allocate(cs, r_u256);
        let s = UInt256::allocate(cs, s_u256);
        let digest = UInt256::allocate(cs, digest_u256);

        let scalar_params = Arc::new(scalar_params);
        let base_params = Arc::new(base_params);

        let valid_x_in_external_field = Secp256BaseNNField::allocated_constant(
            cs,
            Secp256Fq::from_str("9").unwrap(),
            &base_params,
        );
        let valid_t_in_external_field = Secp256BaseNNField::allocated_constant(
            cs,
            Secp256Fq::from_str("16").unwrap(),
            &base_params,
        );
        let valid_y_in_external_field = Secp256BaseNNField::allocated_constant(
            cs,
            Secp256Fq::from_str("4").unwrap(),
            &base_params,
        );

        let (no_error, digest) = ecrecover_precompile_inner_routine(
            cs,
            &rec_id,
            &r,
            &s,
            &digest,
            valid_x_in_external_field.clone(),
            valid_y_in_external_field.clone(),
            valid_t_in_external_field.clone(),
            &base_params,
            &scalar_params,
        );

        assert!(no_error.witness_hook(&*cs)().unwrap() == true);
        let recovered_address = digest.to_be_bytes(cs);
        let recovered_address = recovered_address.witness_hook(cs)().unwrap();
        assert_eq!(&recovered_address[12..], &eth_address[..]);

        dbg!(cs.next_available_row());

        cs.pad_and_shrink();

        let mut cs = owned_cs.into_assembly::<Global>();
        cs.print_gate_stats();
        let worker = Worker::new();
        assert!(cs.check_if_satisfied(&worker));
    }
}

```