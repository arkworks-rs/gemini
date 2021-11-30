use std::env;

use ark_ec::bls12::Bls12;
use ark_ec::{AffineCurve, PairingEngine};
use ark_std::rand::Rng;
use ark_std::test_rng;
use gemini::snark::Proof;
use gemini::kzg::space::CommitterKeyStream;
use gemini::stream::dummy::{dumym_r1cs_relation, DummyStreamer};
const R1CS_INST_LOGSIZE: usize = 30;

type PE = Bls12<ark_bls12_381::Parameters>;
type G1 = <Bls12<ark_bls12_381::Parameters> as PairingEngine>::G1Affine;
type G2 = <Bls12<ark_bls12_381::Parameters> as PairingEngine>::G2Affine;

/// Start a watcher thread that will print the memory (stack+heap) currently allocated at regular intervals.
/// Informations are going to be printed only with feature "print-trace" enabled, and within a linux system.
pub fn memory_traces() {
    // XXX. In Cargo.toml we install profinfo only for x86_64-unknown-linux-gnu.
    // This means, for instance, that i686-unknown-linux-gnu will not compile.
    #[cfg(all(feature="print-trace",target_os="linux"))]
    {
        ark_std::thread::spawn(|| loop {
            let pages_used = procinfo::pid::statm_self().unwrap().data;
            // this can be obtained with getconf PAGESIZE
            // XXX. retrieve this at runtime.
            let page_size = 4096usize;
            let memory_used = page_size * pages_used;
            log::debug!("memory (statm.data): {}B", memory_used);
            ark_std::thread::sleep(std::time::Duration::from_secs(10))
        });
    }
}


fn elastic_snark_main(rng: &mut impl Rng, instance_logsize: usize) {
    let instance_size = 1 << instance_logsize;

    let g1 = G1::prime_subgroup_generator();
    let g2 = G2::prime_subgroup_generator();
    let r1cs_stream = dumym_r1cs_relation(rng, instance_size);
    let ck = CommitterKeyStream::<PE, _> {
        powers_of_g: DummyStreamer::new(g1, instance_size + 1),
        powers_of_g2: [g2, g2],
    };
    println!("Proving an instance of log size  {}", instance_logsize);
    Proof::new_elastic(r1cs_stream, ck);
}


fn time_snark_main(rng: &mut impl Rng, instance_logsize: usize) {
    let rng = &mut test_rng();
    let num_constraints = 1 << instance_logsize;
    let num_variables = 1 << instance_logsize;

    let circuit = gemini::circuit::random_circuit(rng, num_constraints, num_variables);
    let r1cs = gemini::circuit::generate_relation(circuit);
    let ck = gemini::kzg::CommitterKey::<ark_bls12_381::Bls12_381>::new(num_constraints + num_variables, 5, rng);

    println!("Proving an instance of log size  {}", instance_logsize);
    Proof::new_time(&r1cs, &ck);

}

fn main() {
    let rng = &mut test_rng();
    let args = env::args().collect::<Vec<_>>();
    let instance_logsize = if args.len() > 1 {
        args[1].parse::<usize>().expect("Invalid argument")
    } else {
        R1CS_INST_LOGSIZE
    };
    env_logger::init();
    memory_traces();

    time_snark_main(rng, instance_logsize)
}
