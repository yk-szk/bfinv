#[macro_use]
extern crate clap;
use digest::generic_array::GenericArray;
use digest::{Digest, FixedOutput};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::fmt::Write;
use std::io::{BufRead, BufReader, BufWriter};
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

use std::collections::HashMap;
use std::collections::HashSet as Set;
use std::iter::FromIterator;

fn read_file(filename: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut content = Vec::new();
    for result in BufReader::new(std::fs::File::open(filename)?).lines() {
        let l = result?;
        if !l.is_empty() {
            content.push(l);
        }
    }
    Ok(content)
}

fn bf_digest<Hasher: Digest + FixedOutput + 'static>(
    hash_set: Set<String>,
    n_start: usize,
    n_end: usize,
    n_threads: usize,
    verbosity: u64,
) -> Result<HashMap<String, usize>, Box<dyn std::error::Error>> {
    let mut u8_set = Set::new();
    for hash in hash_set.iter() {
        let v = hex::decode(hash)?;
        let a: GenericArray<u8, <Hasher as FixedOutput>::OutputSize> = GenericArray::from_iter(v);
        u8_set.insert(a);
    }
    let counter = Arc::new(AtomicUsize::new(0));
    let total_counts = hash_set.len();
    let mut handles = vec![];
    for thread_i in 0..n_threads {
        let counter = Arc::clone(&counter);
        let t_u8_set = u8_set.clone();
        let handle = thread::spawn(move || {
            let mut hasher = Hasher::new();
            let mut i_str = String::with_capacity(8);
            let mut hash_bytes = Default::default();
            let mut hash_map: HashMap<String, usize> = HashMap::new();
            for i in ((n_start + thread_i)..n_end).step_by(n_threads) {
                i_str.clear();
                write!(&mut i_str, "{:08}", i).unwrap();
                hasher.update(&i_str);
                hasher.finalize_into_reset(&mut hash_bytes);
                if t_u8_set.contains(&hash_bytes) {
                    let hex_string = hex::encode(&hash_bytes);
                    println!("{},{:08}", hex_string, i);
                    hash_map.insert(hex_string, i);
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                if counter.load(Ordering::Relaxed) == total_counts {
                    if thread_i == 0 {
                        eprintln!("Found all hashes.");
                    }
                    break;
                }
                if verbosity >= 2 && i % 10000 == 0 {
                    eprintln!("{}", i);
                }
            }
            hash_map
        });
        handles.push(handle);
    }
    let mut hash_map: HashMap<String, usize> = HashMap::new();
    for handle in handles {
        let hm = handle.join().unwrap();
        for (k, v) in hm {
            hash_map.insert(k, v);
        }
    }
    let found_hashes: Set<String> = Set::from_iter(hash_map.keys().cloned());
    let not_found: Set<_> = hash_set.difference(&found_hashes).collect();
    for h in not_found {
        println!("{},", h);
    }
    Ok(hash_map)
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
        (@arg CSV: --csv +takes_value "Save result as CSV.")
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
    let hash_function = matches.value_of("HASH").unwrap();
    let output_size = *HASH_SIZE
        .get(hash_function)
        .ok_or(format!("{} not found.", hash_function))?;

    let (hash_list, hash_set) = if input_filename.len() == output_size
        && input_filename.chars().all(char::is_alphanumeric)
    {
        let hash = input_filename.to_string();
        let v_hash: Vec<String> = vec![hash.clone()];
        (v_hash, Set::from([hash]))
    } else {
        let v_hash = read_file(input_filename)?;
        (v_hash.clone(), Set::from_iter(v_hash.into_iter()))
    };
    eprintln!("{} hashes are in the input list", hash_set.len());
    let n_start = matches.value_of("START").unwrap().parse::<usize>()?;
    let n_end = matches.value_of("END").unwrap().parse::<usize>()?;
    let mut n_threads = matches.value_of("THREADS").unwrap().parse::<usize>()?;
    if n_threads == 0 {
        n_threads = num_cpus::get_physical();
    }
    let hash_map = match hash_function {
        "md5" => bf_digest::<Md5>(hash_set, n_start, n_end, n_threads, verbosity)?,
        "sha1" => bf_digest::<Sha1>(hash_set, n_start, n_end, n_threads, verbosity)?,
        "sha256" => bf_digest::<Sha256>(hash_set, n_start, n_end, n_threads, verbosity)?,
        "sha512" => bf_digest::<Sha512>(hash_set, n_start, n_end, n_threads, verbosity)?,
        "sha3-256" => bf_digest::<Sha3_256>(hash_set, n_start, n_end, n_threads, verbosity)?,
        "sha3-512" => bf_digest::<Sha3_512>(hash_set, n_start, n_end, n_threads, verbosity)?,
        _ => panic!("Implementation error."),
    };
    if matches.is_present("CSV") {
        use std::fs::File;
        use std::io::Write;
        let filename = matches.value_of("CSV").unwrap();
        eprintln!("Save as {}", filename);
        let mut buffer = BufWriter::new(File::create(filename)?);
        for hash in hash_list {
            let key = hash_map
                .get(&hash)
                .map_or("".to_string(), |i| format!("{:08}", i));
            writeln!(buffer, "{},{}", hash, key)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_g<Hasher: Digest + FixedOutput + 'static>() {
        let src = [0, 1, 10, 100, 1000, 10000];
        let hashes: Vec<String> = src
            .iter()
            .map(|s| format!("{:08}", s))
            .map(|s| {
                let mut hasher = Hasher::new();
                hasher.update(s);
                hex::encode(hasher.finalize())
            })
            .collect();
        let hash_set = Set::from_iter(hashes.clone().into_iter());
        let hash_map = bf_digest::<Hasher>(hash_set, 0, 100000000, 1, 0).unwrap();
        for (value, hash) in src.iter().zip(hashes.iter()) {
            assert_eq!(hash_map[hash], *value);
        }
    }

    #[test]
    fn test_md5() {
        test_g::<Md5>();
    }

    #[test]
    fn test_sha1() {
        test_g::<Sha1>();
    }

    #[test]
    fn test_sha256() {
        test_g::<Sha256>();
    }

    #[test]
    fn test_sha512() {
        test_g::<Sha512>();
    }
}
