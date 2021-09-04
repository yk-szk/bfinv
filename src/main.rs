#[macro_use]
extern crate clap;
use digest::{Digest, FixedOutput};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::fmt::Write;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

static HASH_SIZE: phf::OrderedMap<&'static str, usize> = phf::phf_ordered_map! {
    "md5" => 32,
    "sha1" => 40,
    "sha256" => 64,
    "sha512" => 128,
    "sha3-256" => 64,
    "sha3-512" => 128,
};

use std::thread;

use std::collections::HashSet as Set;

fn read_file(filename: &str, set: &mut Set<String>) -> Result<(), Box<dyn std::error::Error>> {
    for result in BufReader::new(std::fs::File::open(filename)?).lines() {
        let l = result?;
        if !l.is_empty() {
            set.insert(l);
        }
    }
    Ok(())
}

fn bf_digest<Hasher: Digest + FixedOutput, const OUTPUT_SIZE: usize>(
    hash_set: Set<String>,
    n_start: usize,
    n_end: usize,
    n_threads: usize,
    verbosity: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let hash_set = Arc::new(hash_set);
    let counter = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];
    for thread_i in 0..n_threads {
        let counter = Arc::clone(&counter);
        let hash_set = Arc::clone(&hash_set);
        let handle = thread::spawn(move || {
            let mut hasher = Hasher::new();
            let mut i_str = String::with_capacity(8);
            let mut hex_string = String::from_utf8(vec![0u8; OUTPUT_SIZE]).unwrap();
            let mut hash_bytes = Default::default();
            let mut found_hashes: Vec<String> = vec![];
            for i in ((n_start + thread_i)..n_end).step_by(n_threads) {
                i_str.clear();
                write!(&mut i_str, "{:08}", i).unwrap();
                hasher.update(&i_str);
                hasher.finalize_into_reset(&mut hash_bytes);
                unsafe {
                    hex::encode_to_slice(&hash_bytes, hex_string.as_bytes_mut()).unwrap();
                }
                if hash_set.contains(&hex_string) {
                    println!("{},{:08}", hex_string, i);
                    found_hashes.push(hex_string.clone());
                    {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                }
                if counter.load(Ordering::Relaxed) == hash_set.len() {
                    if thread_i == 0 {
                        eprintln!("Found all hashes.");
                    }
                    break;
                }
                if verbosity >= 2 && i % 10000 == 0 {
                    eprintln!("{}", i);
                }
            }
            found_hashes
        });
        handles.push(handle);
    }
    let mut found_hashes: Set<String> = Set::new();
    for handle in handles {
        let found = handle.join().unwrap();
        for h in found {
            found_hashes.insert(h);
        }
    }
    let diff: Set<_> = hash_set.difference(&found_hashes).collect();
    for h in diff {
        println!("{},", h);
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = clap_app!(bfinv =>
        (version: crate_version!())
        (author: "YS")
        (about: "Try brute-forcing to invert digested 8 digits input.\ne.g. sha1(00000000)->703..., bfinv(703...)->00000000")
        (@arg START: --start +takes_value default_value("1") "Starting number")
        (@arg END: --end +takes_value default_value("10000000") "Ending number")
        (@arg THREADS: --threads +takes_value default_value("0") "The number of threads")
        (@arg HASH: --hash +takes_value default_value("sha1") "Hash function. Default is sha1")
        (@arg INPUT: +required "Sets the input list file to use, or hash string")
        (@arg LIST: --list "List available hash functions and exit.")
        (@arg VERBOSE: -v --verbose +multiple "Set the level of verbosity")
    )
    .get_matches();
    if matches.occurrences_of("LIST") > 0 {
        let hash_list: Vec<String> = HASH_SIZE.keys().map(|s| s.to_string()).collect();
        println!("{}", hash_list.join("\n"));
        return Ok(());
    }
    let verbosity = matches.occurrences_of("VERBOSE");
    let input_filename = matches.value_of("INPUT").unwrap();
    let mut hash_set = Set::new();
    let hash_function = matches.value_of("HASH").unwrap();
    let output_size = HASH_SIZE
        .get(&hash_function)
        .ok_or(format!("{} not found.", hash_function))?
        .clone();

    if input_filename.len() == output_size && input_filename.chars().all(char::is_alphanumeric) {
        hash_set.insert(input_filename.to_string());
    } else {
        read_file(input_filename, &mut hash_set)?;
    }
    eprintln!("{} hashes are in the input list", hash_set.len());
    let n_start = matches.value_of("START").unwrap().parse::<usize>()?;
    let n_end = matches.value_of("END").unwrap().parse::<usize>()?;
    let mut n_threads = matches.value_of("THREADS").unwrap().parse::<usize>()?;
    if n_threads == 0 {
        n_threads = num_cpus::get_physical();
    }
    match hash_function {
        "md5" => bf_digest::<Md5, 32>(hash_set, n_start, n_end, n_threads, verbosity)?,
        "sha1" => bf_digest::<Sha1, 40>(hash_set, n_start, n_end, n_threads, verbosity)?,
        "sha256" => bf_digest::<Sha256, 64>(hash_set, n_start, n_end, n_threads, verbosity)?,
        "sha512" => bf_digest::<Sha512, 128>(hash_set, n_start, n_end, n_threads, verbosity)?,
        "sha3-256" => bf_digest::<Sha3_256, 64>(hash_set, n_start, n_end, n_threads, verbosity)?,
        "sha3-512" => bf_digest::<Sha3_512, 128>(hash_set, n_start, n_end, n_threads, verbosity)?,
        _ => panic!("Implementation error."),
    }
    return Ok(());
}
