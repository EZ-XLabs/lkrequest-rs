use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lkrequest::h2::profile::chrome_146_h2;
use lkrequest::Client;
use lktls::profile::presets;
use serde_json::{json, Value};

const DEFAULT_URL: &str = "https://tls.browserleaks.com/";

#[derive(Debug)]
struct Args {
    n: usize,
    out: PathBuf,
    proxy: Option<String>,
    label: String,
    delay_ms: u64,
    url: String,
    insecure: bool,
    ca_pem: Option<PathBuf>,
}

fn parse_args() -> Args {
    let mut n = 30usize;
    let mut out = PathBuf::from("target/fingerprint-samples/browserleaks");
    let mut proxy = None;
    let mut label = String::from("direct");
    let mut delay_ms = 300u64;
    let mut url = DEFAULT_URL.to_string();
    let mut insecure = false;
    let mut ca_pem = None;

    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--n" => n = iter.next().expect("--n value").parse().expect("valid --n"),
            "--out" => out = PathBuf::from(iter.next().expect("--out value")),
            "--proxy" => proxy = Some(iter.next().expect("--proxy value")),
            "--label" => label = iter.next().expect("--label value"),
            "--delay-ms" => {
                delay_ms = iter
                    .next()
                    .expect("--delay-ms value")
                    .parse()
                    .expect("valid --delay-ms")
            }
            "--url" => url = iter.next().expect("--url value"),
            "--insecure" => insecure = true,
            "--ca-pem" => ca_pem = Some(PathBuf::from(iter.next().expect("--ca-pem value"))),
            other => panic!("unknown arg: {other}"),
        }
    }

    Args {
        n,
        out,
        proxy,
        label,
        delay_ms,
        url,
        insecure,
        ca_pem,
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis()
}

fn request_builder(session: &lkrequest::Session, url: &str) -> lkrequest::session::RequestBuilder {
    session
        .get(url)
        .header("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
        .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
        .header("cache-control", "max-age=0")
        .header("sec-ch-ua", r#""Chromium";v="146", "Google Chrome";v="146", "Not/A)Brand";v="99""#)
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", r#""Windows""#)
        .header("accept-encoding", "gzip, deflate, br, zstd")
        .header("accept-language", "zh-CN,zh;q=0.9")
        .header("upgrade-insecure-requests", "1")
        .header("sec-fetch-site", "none")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-user", "?1")
        .header("sec-fetch-dest", "document")
        .header("priority", "u=0, i")
}

fn extension_ids(body: &Value) -> Vec<u16> {
    body.pointer("/tls/extensions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|ext| ext.get("id").and_then(Value::as_u64).map(|id| id as u16))
        .collect()
}

fn ech_summary(body: &Value) -> Value {
    let ech = body
        .pointer("/tls/extensions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|ext| ext.get("id").and_then(Value::as_u64) == Some(65037));
    ech.and_then(|ext| ext.get("data").cloned())
        .unwrap_or(Value::Null)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    fs::create_dir_all(&args.out)?;

    let mut summaries = Vec::new();

    for i in 0..args.n {
        let sample_index = i + 1;
        eprintln!(
            "[{}] sample {}/{}{}",
            args.label,
            sample_index,
            args.n,
            args.proxy
                .as_ref()
                .map(|p| format!(" via {p}"))
                .unwrap_or_default()
        );

        let mut client_builder = Client::builder()
            .fingerprint(presets::chrome_146())
            .h2_profile(chrome_146_h2())
            .verify(!args.insecure);
        if let Some(ca_pem) = &args.ca_pem {
            let pem = fs::read(ca_pem)?;
            client_builder = client_builder.add_ca_certs_pem(&pem);
        }
        let client = client_builder.build();
        let mut session_builder = client.session();
        if let Some(proxy) = &args.proxy {
            session_builder = session_builder.proxy(proxy);
        }
        let session = session_builder.build();

        let started_ms = now_ms();
        let result = request_builder(&session, &args.url).send().await;
        let finished_ms = now_ms();

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text()?;
                let body: Value = serde_json::from_str(text)?;
                let extensions = extension_ids(&body);
                let sample = json!({
                    "meta": {
                        "label": args.label,
                        "index": sample_index,
                        "url": args.url,
                        "proxy": args.proxy,
                        "insecure": args.insecure,
                        "ca_pem": args.ca_pem,
                        "started_ms": started_ms,
                        "finished_ms": finished_ms,
                        "status": status
                    },
                    "body": body
                });
                let file = args
                    .out
                    .join(format!("{}_{:03}.json", args.label, sample_index));
                fs::write(&file, serde_json::to_vec_pretty(&sample)?)?;

                summaries.push(json!({
                    "index": sample_index,
                    "status": status,
                    "ja3_hash": sample["body"]["ja3_hash"],
                    "ja3_text": sample["body"]["ja3_text"],
                    "ja3n_hash": sample["body"]["ja3n_hash"],
                    "ja4": sample["body"]["ja4"],
                    "ja4_o": sample["body"]["ja4_o"],
                    "ja4_ro": sample["body"]["ja4_ro"],
                    "akamai_hash": sample["body"]["akamai_hash"],
                    "akamai_text": sample["body"]["akamai_text"],
                    "ech": ech_summary(&sample["body"]),
                    "extension_ids": extensions
                }));
            }
            Err(err) => {
                summaries.push(json!({
                    "index": sample_index,
                    "error": err.to_string(),
                    "started_ms": started_ms,
                    "finished_ms": finished_ms
                }));
            }
        }

        if args.delay_ms > 0 && sample_index != args.n {
            tokio::time::sleep(Duration::from_millis(args.delay_ms)).await;
        }
    }

    let summary = json!({
        "label": args.label,
        "proxy": args.proxy,
        "insecure": args.insecure,
        "ca_pem": args.ca_pem,
        "url": args.url,
        "n": args.n,
        "samples": summaries
    });
    let summary_file = args.out.join(format!("{}_summary.json", args.label));
    fs::write(&summary_file, serde_json::to_vec_pretty(&summary)?)?;
    println!("{}", serde_json::to_string_pretty(&summary)?);

    Ok(())
}
