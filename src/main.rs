use clap::Parser;
use faster_hex::hex_decode;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::string::String;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use sha1::digest::generic_array::GenericArray;

#[derive(Deserialize)]
struct PoolData {
	pub ip: String,
	pub name: String,
	pub port: usize,
}

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
	#[arg(short, long, default_value="")]
	username: String,
	#[arg(short, long, default_value="NET")]
	diff: String,
	#[arg(short, long, default_value="pc")]
	identifier: String
}

fn main()
{
	let args = Args::parse();

	let running: Arc<AtomicBool> = Arc::new(AtomicBool::new(true));
	let clone = running.clone();
	ctrlc::set_handler(move || {
		println!("received Ctrl+C!");
		clone.store(false, Ordering::Relaxed);
	}).expect("Failed to handle ctrlc");

	println!("Selecting pool");
	let (pool, port, name) = select_pool();

	println!("Starting miner for {} at {} difficulty on {}", args.username, args.diff, name);
	start_mining(running, pool, port, args);
}

fn start_mining(running: Arc<AtomicBool>, pool: String, port: usize, args: Args) {
	println!("{pool}:{port}");
	let connection = TcpStream::connect(format!("{pool}:{port}")).unwrap();

	println!("Connected.");
	let job_req = format!("JOB,{},{}", args.username, args.diff);
	println!("{job_req} job");
	let ident = args.identifier;
	let mut writer = std::io::LineWriter::new(connection.try_clone().expect("Failed to clone"));
	let mut reader = BufReader::new(connection);

	let mut resp= String::new();
	let _ = reader.read_line(&mut resp);

	println!("Running v{resp}");

	loop {
		while running.load(Ordering::Relaxed)
		{
			let start = Instant::now();
			resp.clear();

			let _ = writer.write(job_req.as_bytes());
			let _ = writer.flush();
			let _ = reader.read_line(&mut resp);

			resp.pop(); // remove \n
			if resp.len() < 80
			{
				eprintln!("Response was the wrong length {resp}");
				break;
			}
			let last_hash = &resp[..40];
			let exp_hash = &resp[41..81];
			let diff = &resp[82..].parse::<usize>().unwrap();

			// let nonce = mine_sha1(last_hash, exp_hash, diff, &mut buffer, &mut dst_buffer);
			let nonce = mine_sha1(last_hash, exp_hash, *diff);
			let hash_rate = (1e9 * (nonce as f64 / start.elapsed().as_nanos() as f64)).floor();
			let send = format!("{nonce},{hash_rate},panda-rs,{ident}");
			writer.write_all(send.as_bytes()).expect("Failed to send");
			writer.flush().expect("Failed to flush");
			resp.clear();
			let _ = reader.read_line(&mut resp);
			println!("{resp} {hash_rate} {diff}");
		}

		if !running.load(Ordering::Relaxed)
		{
			break;
		}
	}


}

// SHA1 internal state words
const IV: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

fn mine_sha1(last_hash: &str, exp_hash: &str, diff: usize) -> usize
{
	let mut exp = [0u8; 20];
	hex_decode(exp_hash.as_bytes(), &mut exp).unwrap();
	// splitting into 5 big-endian words (target_hash is 20 bytes -> 20/5 = 4)
	let target: [u32; 5] = std::array::from_fn(|i| u32::from_be_bytes(exp[i * 4..i * 4 + 4].try_into().unwrap()));

	// Pre-padded block: last_hash + "0" + 0x80 + zeros + length
	let mut block = [0u8; 64];
	block[..40].copy_from_slice(last_hash.as_bytes());
	// length of first nonce
	let mut len = 1;
	// first nonce
	block[40] = b'0';
	// marking end of message and encoding length into last 8 bits of block
	set_tail(&mut block, len);

	for nonce in 0..=100 * diff
	{
		let mut state = IV;
		// run the sha1 rounds for the current nonce
		sha1::compress(&mut state, std::slice::from_ref(GenericArray::from_slice(&block)));
		if state == target
		{
			return nonce;
		}

		// increment digits in place
		let mut i = 40 + len;
		loop
		{
			i -= 1;
			// if the digit is below a nine, we can just add 1
			if block[i] < b'9' { block[i] += 1; break; }
			// if digit was 9, +1 turns it into a zero
			block[i] = b'0';
			if i == 40
			{
				// we reached the tail of `last_hash`
				// if we reached this point, all following digits (41..) flipped from 9 to 0
				// e.g. 99 -> 100, so we set the first digit to be a 1 again
				block[40] = b'1';
				// len is not zero indexed, so 40 + len adds a 0 to the end
				block[40 + len] = b'0';
				// we added a digit, so we increase the len
				len += 1;
				// mark end of message, encode length
				set_tail(&mut block, len);
				break;
			}
		}
	}
	0
}

fn set_tail(block: &mut [u8; 64], len: usize)
{
	// 0x80 marks the end of the message
	block[40 + len] = 0x80;
	// in the last 8 bits, the message length is encoded
	// 40 = length of last_hash, len = length of nonce (amount of digits), multiplied by eight because it's bits
	block[56..].copy_from_slice(&(((40 + len) * 8) as u64).to_be_bytes());
}


fn select_pool() -> (String, usize, String) {
	let resp: PoolData = reqwest::blocking::get("https://server.duinocoin.com/getPool").expect("Failed to get pool")
		.json().expect("Failed to get json");

	(resp.ip, resp.port, resp.name)
}
