use faster_hex::hex_decode;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::string::String;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use clap::Parser;
use sha1::{Digest, Sha1};
use sha1::digest::FixedOutput;

#[derive(Deserialize)]
struct PoolData {
	pub ip: String,
	pub name: String,
	pub port: usize,
	pub region: String,
	pub server: String,
	pub success: bool,
}

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
	/// Whether the ripe db should be loaded, otherwise the DB process is entirely discarded
	#[arg(short, long, default_value="")]
	username: String,
	#[arg(short, long, default_value="NET")]
	diff: String,
	#[arg(short, long, default_value="pc")]
	identifier: String
}

fn main()
{
	let mut args = Args::parse();

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
	let args_clone = args.clone();
	println!("Connected.");
	let job_req = format!("JOB,{},{}", args.username, args.diff);
	println!("{job_req} job");
	let ident = args.identifier;
	let mut writer = std::io::LineWriter::new(connection.try_clone().expect("Failed to clone"));
	let mut reader = BufReader::new(connection);

	let mut resp= String::new();
	let _ = reader.read_line(&mut resp);

	println!("Running v{resp}");


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


		let nonce = mine_sha1(last_hash, exp_hash, diff);
		let hash_rate = (1e9 * (nonce as f64 / start.elapsed().as_nanos() as f64)).floor();
		let send = format!("{nonce},{hash_rate},panda-rs,{ident}");
		writer.write(send.as_bytes()).expect("Failed to send");
		writer.flush().expect("Failed to flush");
		resp.clear();
		let _ = reader.read_line(&mut resp);
		println!("{resp} {hash_rate} {diff}");
	}


	if running.load(Ordering::Relaxed)
	{
		start_mining(running, pool, port, args_clone);
	}
}


fn mine_sha1(last_hash: &str, exp_hash: &str, diff: &usize) -> usize
{
	let mut hasher = Sha1::new();
	hasher.update(last_hash);
	// let exp = hex::decode(exp_hash).unwrap();
	let mut dst = vec![0; exp_hash.len() / 2];
	hex_decode(exp_hash.as_ref(), &mut dst).unwrap();

	let exp: &[u8] = &dst;
	let mut buffer = itoa::Buffer::new();

	for nonce in 0..(100*diff + 1)
	{
		let printed = buffer.format(nonce);
		let mut temp_hasher = hasher.clone();

		temp_hasher.update(printed.as_bytes());

		if temp_hasher.finalize().as_slice() == exp
		{
			return nonce;
		}
	}
	0
}

fn select_pool() -> (String, usize, String) {
	let resp: PoolData = reqwest::blocking::get("https://server.duinocoin.com/getPool").expect("Failed to get pool")
		.json().expect("Failed to get json");

	(resp.ip, resp.port, resp.name)
}
