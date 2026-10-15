/// The reverse of ipp_bridge: discovers modern IPP printers via mDNS/Bonjour and
/// exposes each one on AppleTalk as an emulated LaserWriter, so old Macs can print
/// to them from the Chooser. The real printer's name, make/model, colour capability,
/// resolution and paper sizes are passed through to the Chooser name and the PAP
/// emulator's PostScript query answers (`*Product`, `*ColorDevice`, `*?Resolution`, …).
///
/// Jobs arrive as PostScript from the LaserWriter driver and are submitted with IPP
/// Print-Job: passed through untouched if the printer accepts PostScript, otherwise
/// converted with Ghostscript (PDF, or URF/PWG raster for driverless-only printers).
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io::Cursor,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

pub(crate) static GS_COUNTER: AtomicU64 = AtomicU64::new(1);

use ipp::prelude::*;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use tailtalk::{
    CancellationToken,
    atp::Atp,
    ddp::DdpHandle,
    nbp::{NbpHandle, RegisteredName},
    pap::{ConnectionId, PapServer, PaperSize, PrintJob, PrintSink, PrinterAttributes},
};
use tailtalk_packets::nbp::EntityName;
use tokio::sync::Mutex;

/// Names this bridge has registered on NBP. Shared with ipp_bridge so it can skip
/// them during its own discovery — otherwise a bridged printer would be re-exported
/// over mDNS as a duplicate of the real device.
pub type BridgedNames = Arc<StdMutex<HashSet<(String, u8)>>>;

/// Document format jobs are forwarded in, in order of preference. PostScript is a
/// pass-through; everything else is converted with Ghostscript.
#[derive(Clone, Copy, Debug)]
enum ForwardFormat {
    Postscript,
    Pdf,
    Urf,
    PwgRaster,
}

impl ForwardFormat {
    fn mime(self) -> &'static str {
        match self {
            Self::Postscript => "application/postscript",
            Self::Pdf => "application/pdf",
            Self::Urf => "image/urf",
            Self::PwgRaster => "image/pwg-raster",
        }
    }
}

/// How jobs are handed to one printer: the format it takes and, for a raster
/// format, the resolution, colour and quality it accepts.
#[derive(Clone, Copy, Debug)]
struct Forwarding {
    format: ForwardFormat,
    dpi: u32,
    color: bool,
    urf_quality: u8,
}

impl Forwarding {
    fn for_printer(caps: &IppCaps) -> Self {
        Self { format: caps.format, dpi: caps.dpi, color: caps.color, urf_quality: caps.urf_quality }
    }
}

/// Capabilities pulled from the real printer via Get-Printer-Attributes.
#[derive(Debug)]
struct IppCaps {
    make_and_model: String,
    color: bool,
    dpi: u32,
    paper_sizes: Vec<PaperSize>,
    format: ForwardFormat,
    /// `print-quality` value written into URF pages: 3 draft, 4 normal, 5 high.
    urf_quality: u8,
}

impl Default for IppCaps {
    /// Fallback when the attribute query fails: nearly every IPP printer accepts
    /// PDF, and assuming colour avoids degrading colour jobs (a mono printer
    /// grayscales them itself).
    fn default() -> Self {
        Self {
            make_and_model: String::new(),
            color: true,
            dpi: 300,
            paper_sizes: vec![PaperSize::Letter, PaperSize::A4],
            format: ForwardFormat::Pdf,
            urf_quality: 4,
        }
    }
}

struct BridgedPrinter {
    uri: String,
    nbp_name: String,
    registration: RegisteredName,
    task: tokio::task::JoinHandle<()>,
}

struct ResolvedPrinter {
    fullname: String,
    printer: BridgedPrinter,
}

pub async fn run(
    nbp: NbpHandle,
    ddp: DdpHandle,
    token: CancellationToken,
    bridged_names: BridgedNames,
) {
    let mdns = ServiceDaemon::new().expect("LW bridge: failed to create mDNS daemon");
    let receiver = match mdns.browse("_ipp._tcp.local.") {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("LW bridge: mDNS browse failed: {e}");
            let _ = mdns.shutdown();
            return;
        }
    };

    tracing::info!("LW bridge: browsing for IPP printers");

    let mut printers: HashMap<String, BridgedPrinter> = HashMap::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ResolvedPrinter>();

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            Some(res) = rx.recv() => {
                printers.insert(res.fullname, res.printer);
            }
            ev = receiver.recv_async() => {
                let Ok(ev) = ev else { break };
                match ev {
                    ServiceEvent::ServiceResolved(info) => {
                        let fullname = info.get_fullname().to_string();
                        let instance = fullname
                            .strip_suffix("._ipp._tcp.local.")
                            .unwrap_or(&fullname)
                            .to_string();

                        if info.get_hostname().starts_with("tailtalk-") || info.get_port() == 8631 {
                            tracing::debug!("LW bridge: ignoring TailTalk-published service '{instance}'");
                            continue;
                        }

                        let Some(ip) = info.get_addresses_v4().into_iter().min() else {
                            tracing::debug!("LW bridge: no IPv4 address for '{instance}', skipping");
                            continue;
                        };
                        let rp = info.get_property_val_str("rp").unwrap_or("");
                        // A `TLS` key in the TXT record (Bonjour Printing spec) means the
                        // printer takes IPP over TLS; some, like Epson's, take nothing else.
                        let tls = info.get_property("TLS").is_some();
                        let candidates = candidate_uris(&ip.to_string(), info.get_port(), rp, tls);
                        let uri_str = candidates[0].clone();

                        match printers.get(&fullname) {
                            Some(existing) if existing.uri == uri_str => continue,
                            Some(_) => remove_printer(&nbp, &mut printers, &bridged_names, &fullname).await,
                            None => {}
                        }

                        let taken: HashSet<String> = printers.values().map(|p| p.nbp_name.clone()).collect();
                        let nbp = nbp.clone();
                        let ddp = ddp.clone();
                        let bridged_names = bridged_names.clone();
                        let tx = tx.clone();
                        let _info = info.clone();

                        tokio::spawn(async move {
                            let (uri, caps) = match probe_printer(&instance, &candidates).await {
                                Some(found) => found,
                                None => {
                                    let Ok(uri) = uri_str.parse::<Uri>() else {
                                        tracing::warn!("LW bridge: bad URI '{uri_str}'");
                                        return;
                                    };
                                    tracing::warn!(
                                        "LW bridge: attribute query for '{instance}' failed, using defaults"
                                    );
                                    (uri, IppCaps { make_and_model: instance.clone(), ..IppCaps::default() })
                                }
                            };

                            let mut nbp_name = unique_nbp_name(&instance, &taken.iter().map(|s| s.as_str()).collect());
                            if nbp_name.is_empty() {
                                tracing::warn!("LW bridge: '{instance}' has no NBP-representable name, skipping");
                                return;
                            }

                            let mut suffix = 2;
                            loop {
                                let entity: EntityName = match format!("{nbp_name}:LaserWriter@*").as_str().try_into() {
                                    Ok(e) => e,
                                    Err(_) => return,
                                };
                                if let Ok(res) = nbp.lookup(entity).await {
                                    if res.is_empty() { break; }
                                } else {
                                    break;
                                }

                                let base = nbp_safe_name(&instance);
                                let s = format!(" {suffix}");
                                nbp_name = base.chars().take(32 - s.len()).collect::<String>().trim_end().to_string() + &s;
                                suffix += 1;
                                if suffix > 100 { return; }
                            }

                            let attrs = PrinterAttributes {
                                product_name: if caps.make_and_model.is_empty() {
                                    nbp_name.clone()
                                } else {
                                    caps.make_and_model.clone()
                                },
                                color: caps.color,
                                resolutions_dpi: vec![caps.dpi],
                                paper_sizes: caps.paper_sizes.clone(),
                                ..PrinterAttributes::default()
                            };
                            let gs_fonts = resident_fonts().await;
                            let attrs = if gs_fonts.is_empty() {
                                attrs
                            } else {
                                PrinterAttributes { resident_fonts: gs_fonts, ..attrs }
                            };

                            let sink = IppForwardSink {
                                uri,
                                forwarding: Forwarding::for_printer(&caps),
                                printer: nbp_name.clone(),
                                serial: Arc::new(tokio::sync::Mutex::new(())),
                                counter: std::sync::atomic::AtomicU32::new(0),
                                laser_prep: LaserPrep::new(),
                            };

                            let (socket_num, _, responder) = Atp::spawn(&ddp, None).await;
                            let mut server = PapServer::new(
                                responder,
                                ddp,
                                socket_num,
                                attrs,
                                Box::new(sink),
                            );

                            let entity: EntityName = match format!("{nbp_name}:LaserWriter@*").as_str().try_into() {
                                Ok(e) => e,
                                Err(e) => {
                                    tracing::warn!("LW bridge: invalid NBP name '{nbp_name}': {e}");
                                    return;
                                }
                            };
                            let registration = RegisteredName {
                                name: entity,
                                sock_num: socket_num,
                            };
                            
                            bridged_names.lock().unwrap().insert((nbp_name.clone(), socket_num));
                            if let Err(e) = nbp.register(registration.clone()).await {
                                tracing::warn!("LW bridge: NBP registration for '{nbp_name}' failed: {e}");
                                bridged_names.lock().unwrap().remove(&(nbp_name, socket_num));
                                return;
                            }

                            let task_name = nbp_name.clone();
                            let task = tokio::spawn(async move {
                                if let Err(e) = server.run().await {
                                    tracing::warn!("LW bridge: PAP server for '{task_name}' stopped: {e}");
                                }
                            });

                            tracing::info!(
                                "LW bridge: bridged '{instance}' → \"{nbp_name}:LaserWriter\" \
                                 ({}, {}dpi, color={}, sending {})",
                                if caps.make_and_model.is_empty() { "unknown model" } else { &caps.make_and_model },
                                caps.dpi,
                                caps.color,
                                caps.format.mime(),
                            );

                            let printer = BridgedPrinter {
                                uri: uri_str,
                                nbp_name,
                                registration,
                                task,
                            };
                            let _ = tx.send(ResolvedPrinter { fullname, printer });
                        });
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        remove_printer(&nbp, &mut printers, &bridged_names, &fullname).await;
                    }
                    _ => {}
                }
            }
        }
    }

    for (_, p) in printers.drain() {
        p.task.abort();
        let _ = nbp.unregister(p.registration.clone()).await;
        bridged_names.lock().unwrap().remove(&(p.nbp_name.clone(), p.registration.sock_num));
    }
    let _ = mdns.shutdown();
}

async fn remove_printer(
    nbp: &NbpHandle,
    printers: &mut HashMap<String, BridgedPrinter>,
    bridged_names: &BridgedNames,
    fullname: &str,
) {
    let Some(p) = printers.remove(fullname) else { return };
    tracing::info!("LW bridge: '{}' vanished, unregistering", p.nbp_name);
    p.task.abort();
    if let Err(e) = nbp.unregister(p.registration.clone()).await {
        tracing::warn!("LW bridge: NBP unregister for '{}' failed: {e}", p.nbp_name);
    }
    bridged_names.lock().unwrap().remove(&(p.nbp_name.clone(), p.registration.sock_num));
}

/// Make a printer's mDNS instance name safe for NBP: ASCII only (NBP names are
/// MacRoman on the wire; non-ASCII would mojibake in the Chooser), no NBP
/// metacharacters, at most 32 characters.
fn nbp_safe_name(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| match c {
            ':' | '@' | '=' | '*' => ' ',
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => ' ',
        })
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    cleaned.chars().take(32).collect::<String>().trim_end().to_string()
}

/// NBP-safe name, disambiguated with a numeric suffix if another bridged
/// printer already claimed it.
fn unique_nbp_name(instance: &str, taken: &HashSet<&str>) -> String {
    let base = nbp_safe_name(instance);
    if base.is_empty() || !taken.contains(base.as_str()) {
        return base;
    }
    for n in 2..100 {
        let suffix = format!(" {n}");
        let candidate: String = base
            .chars()
            .take(32 - suffix.len())
            .collect::<String>()
            .trim_end()
            .to_string()
            + &suffix;
        if !taken.contains(candidate.as_str()) {
            return candidate;
        }
    }
    String::new()
}

// ── IPP attribute query ───────────────────────────────────────────────────────

fn attr_string(v: &IppValue) -> Option<String> {
    match v {
        IppValue::NameWithoutLanguage(s) | IppValue::Keyword(s) => Some(s.to_string()),
        IppValue::TextWithoutLanguage(s) => Some(s.to_string()),
        _ => None,
    }
}

/// Iterate an attribute's values whether it's a single value or a 1setOf array.
fn attr_values(v: &IppValue) -> Vec<&IppValue> {
    match v {
        IppValue::Array(vals) => vals.iter().collect(),
        other => vec![other],
    }
}

/// Dots per inch of an IPP resolution value (cross-feed direction).
fn resolution_dpi(v: &IppValue) -> Option<u32> {
    match v {
        IppValue::Resolution { cross_feed, units, .. } if *cross_feed > 0 => {
            if *units == 4 {
                Some((*cross_feed as f64 * 2.54).round() as u32)
            } else {
                Some(*cross_feed as u32)
            }
        }
        _ => None,
    }
}

/// The resolutions a printer's `urf-supported` keywords allow: `RS300` is one,
/// `RS300-600` several, dash-separated.
fn urf_resolutions<'a>(keywords: impl IntoIterator<Item = &'a str>) -> Vec<u32> {
    keywords
        .into_iter()
        .filter_map(|k| k.strip_prefix("RS"))
        .flat_map(|list| list.split('-').filter_map(|n| n.parse::<u32>().ok()).collect::<Vec<_>>())
        .collect()
}

/// The print qualities a printer's `urf-supported` keywords allow: `PQ4-5` is 4 and 5.
fn urf_qualities<'a>(keywords: impl IntoIterator<Item = &'a str>) -> Vec<u8> {
    keywords
        .into_iter()
        .filter_map(|k| k.strip_prefix("PQ"))
        .flat_map(|list| list.split('-').filter_map(|n| n.parse::<u8>().ok()).collect::<Vec<_>>())
        .collect()
}

/// Normal quality (4) when the printer takes it or says nothing, else its lowest.
fn pick_urf_quality(supported: &[u8]) -> u8 {
    if supported.is_empty() || supported.contains(&4) {
        4
    } else {
        supported.iter().copied().min().unwrap_or(4)
    }
}

/// Fix up a URF stream from Ghostscript so AirPrint printers accept it.
///
/// Ghostscript's `urfgray`/`urfrgb` devices write a header that printers reject
/// as a document-format-error: the colour space is marked as device gray or
/// device RGB (4 and 5, the `DEVW8`/`DEVRGB24` keywords few printers list), the
/// duplex and quality fields are 0 (not a value either takes), and the page
/// count is 0. Set the colour space to W (0) or sRGB (1), which every URF printer
/// lists, duplex to one-sided (1), the quality to what the printer announced, and
/// the page count to the pages found. Pages are found by decoding the run
/// lengths, since the format has no page table.
fn urf_conform(data: &mut [u8], color: bool, quality: u8) -> anyhow::Result<()> {
    let headers = urf_page_headers(data)?;
    let count = u32::try_from(headers.len())?;
    data[8..12].copy_from_slice(&count.to_be_bytes());
    for at in headers {
        data[at + 1] = if color { 1 } else { 0 };
        data[at + 2] = 1;
        data[at + 3] = quality;
    }
    Ok(())
}

/// Byte offsets of the page headers in a URF stream.
///
/// Each page is a 32-byte header followed by its lines: a repeat byte (lines − 1),
/// then runs until the width is covered: `n < 128` repeats the next pixel n + 1
/// times, `n > 128` is followed by 257 − n literal pixels, and 128 blanks the rest
/// of the line.
fn urf_page_headers(data: &[u8]) -> anyhow::Result<Vec<usize>> {
    anyhow::ensure!(data.len() >= 12 && &data[..8] == b"UNIRAST\0", "not a URF stream");
    let mut headers = Vec::new();
    let mut pos = 12;
    let byte_at = |at: usize| data.get(at).copied().ok_or_else(|| anyhow::anyhow!("truncated URF page"));
    let u32_at = |at: usize| -> anyhow::Result<usize> {
        let b: [u8; 4] = data.get(at..at + 4).ok_or_else(|| anyhow::anyhow!("truncated URF page header"))?.try_into()?;
        Ok(u32::from_be_bytes(b) as usize)
    };
    while pos < data.len() {
        let bytes_per_pixel = byte_at(pos)? as usize / 8;
        let width = u32_at(pos + 12)?;
        let height = u32_at(pos + 16)?;
        anyhow::ensure!(bytes_per_pixel > 0 && width > 0 && height > 0, "bad URF page header");
        headers.push(pos);
        pos += 32;
        let mut lines = 0;
        while lines < height {
            lines += byte_at(pos)? as usize + 1;
            pos += 1;
            let mut pixels = 0;
            while pixels < width {
                let n = byte_at(pos)?;
                pos += 1;
                if n == 128 {
                    pixels = width;
                } else if n < 128 {
                    pixels += n as usize + 1;
                    pos += bytes_per_pixel;
                } else {
                    let literal = 257 - n as usize;
                    pixels += literal;
                    pos += literal * bytes_per_pixel;
                }
            }
            anyhow::ensure!(pos <= data.len(), "truncated URF page");
        }
    }
    Ok(headers)
}

/// The resolution to render a raster job at: the printer's default when it takes
/// it, else the highest supported one below it, else the lowest supported one.
/// With nothing known, the default stands.
fn pick_raster_dpi(default: u32, supported: &[u32]) -> u32 {
    if supported.is_empty() || supported.contains(&default) {
        return default;
    }
    supported
        .iter()
        .copied()
        .filter(|&d| d < default)
        .max()
        .or_else(|| supported.iter().copied().min())
        .unwrap_or(default)
}

/// The URIs to try for a discovered printer, best first.
///
/// `ipp://` is what the Bonjour record describes, but a printer that announces `TLS`
/// may refuse plain IPP (HTTP 426 Upgrade Required) and only serve `ipps://` on the
/// same port, so that goes first when it is announced. The other scheme stays as a
/// fallback either way: a printer that announces TLS but has it misconfigured still
/// gets bridged over plain IPP.
fn candidate_uris(ip: &str, port: u16, rp: &str, tls: bool) -> Vec<String> {
    let plain = format!("ipp://{ip}:{port}/{rp}");
    let secure = format!("ipps://{ip}:{port}/{rp}");
    if tls { vec![secure, plain] } else { vec![plain, secure] }
}

/// A client for one printer. Printers present self-signed certificates, so TLS
/// errors are ignored: the point of `ipps://` here is reaching a printer that
/// refuses anything else, not authenticating it.
fn ipp_client(uri: &Uri) -> AsyncIppClient {
    AsyncIppClient::builder(uri.clone()).ignore_tls_errors(true).build()
}

/// Ask each candidate URI for the printer's attributes and keep the first that answers.
async fn probe_printer(instance: &str, candidates: &[String]) -> Option<(Uri, IppCaps)> {
    for uri_str in candidates {
        let uri: Uri = match uri_str.parse() {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("LW bridge: bad URI '{uri_str}': {e}");
                continue;
            }
        };
        match query_ipp_caps(&uri).await {
            Ok(caps) => {
                tracing::info!("LW bridge: '{instance}' answers at {uri_str}");
                return Some((uri, caps));
            }
            Err(e) => tracing::info!("LW bridge: '{instance}' did not answer at {uri_str}: {e}"),
        }
    }
    None
}

async fn query_ipp_caps(uri: &Uri) -> anyhow::Result<IppCaps> {
    let client = ipp_client(uri);
    let op = IppOperationBuilder::get_printer_attributes(uri.clone())
        .attributes([
            "printer-make-and-model",
            "color-supported",
            "printer-resolution-default",
            "media-supported",
            "document-format-supported",
            "urf-supported",
            "pwg-raster-document-resolution-supported",
        ])
        .build()?;
    let resp = tokio::time::timeout(Duration::from_secs(15), client.send(op))
        .await
        .map_err(|_| anyhow::anyhow!("Get-Printer-Attributes timed out"))??;

    let status = resp.header().operation_or_status;
    anyhow::ensure!(status < 0x100, "Get-Printer-Attributes failed: 0x{status:04x}");

    let group = resp
        .attributes()
        .groups_of(DelimiterTag::PrinterAttributes)
        .next()
        .ok_or_else(|| anyhow::anyhow!("response has no printer attributes"))?;
    let attrs = group.attributes();

    let make_and_model = attrs
        .get("printer-make-and-model")
        .and_then(|a| attr_string(a.value()))
        .unwrap_or_default();

    let color = attrs
        .get("color-supported")
        .and_then(|a| match a.value() {
            IppValue::Boolean(b) => Some(*b),
            _ => None,
        })
        .unwrap_or(false);

    let dpi = attrs
        .get("printer-resolution-default")
        .and_then(|a| match a.value() {
            IppValue::Resolution { cross_feed, units, .. } if *cross_feed > 0 => {
                if *units == 4 {
                    Some((*cross_feed as f64 * 2.54).round() as u32)
                } else {
                    Some(*cross_feed as u32)
                }
            }
            _ => None,
        })
        .unwrap_or(300);

    let mut paper_sizes: Vec<PaperSize> = Vec::new();
    if let Some(a) = attrs.get("media-supported") {
        for v in attr_values(a.value()) {
            let Some(media) = attr_string(v) else { continue };
            let size = if media.starts_with("na_letter") {
                Some(PaperSize::Letter)
            } else if media.starts_with("na_legal") {
                Some(PaperSize::Legal)
            } else if media.starts_with("iso_a4") {
                Some(PaperSize::A4)
            } else if media.starts_with("iso_a3") {
                Some(PaperSize::A3)
            } else if media.starts_with("iso_b5") || media.starts_with("jis_b5") {
                Some(PaperSize::B5)
            } else if media.starts_with("na_executive") {
                Some(PaperSize::Executive)
            } else {
                None
            };
            if let Some(s) = size
                && !paper_sizes.contains(&s)
            {
                paper_sizes.push(s);
            }
        }
    }
    if paper_sizes.is_empty() {
        paper_sizes = vec![PaperSize::Letter, PaperSize::A4];
    }

    let mut formats: HashSet<String> = HashSet::new();
    if let Some(a) = attrs.get("document-format-supported") {
        for v in attr_values(a.value()) {
            if let IppValue::MimeMediaType(m) = v {
                formats.insert(m.to_string());
            }
        }
    }
    let format = if formats.contains("application/postscript") {
        ForwardFormat::Postscript
    } else if formats.contains("application/pdf") {
        ForwardFormat::Pdf
    } else if formats.contains("image/urf") {
        ForwardFormat::Urf
    } else if formats.contains("image/pwg-raster") {
        ForwardFormat::PwgRaster
    } else {
        // Nothing recognised (or the attribute was withheld); PDF is the safest bet.
        ForwardFormat::Pdf
    };

    // A raster job is rendered here, so it has to be at a resolution the printer
    // takes for that raster format, which is not always its default: the Epson
    // ET-4750 defaults to 600 dpi but accepts URF at 300 only (`RS300`), and
    // rejects a 600 dpi page as a document-format-error (0x0411).
    let urf: Vec<String> = attrs
        .get("urf-supported")
        .map(|a| attr_values(a.value()).into_iter().filter_map(attr_string).collect())
        .unwrap_or_default();
    let urf_quality = pick_urf_quality(&urf_qualities(urf.iter().map(String::as_str)));
    let dpi = match format {
        ForwardFormat::Urf => {
            let supported = urf_resolutions(urf.iter().map(String::as_str));
            pick_raster_dpi(dpi, &supported)
        }
        ForwardFormat::PwgRaster => {
            let supported: Vec<u32> = attrs
                .get("pwg-raster-document-resolution-supported")
                .map(|a| attr_values(a.value()).into_iter().filter_map(resolution_dpi).collect())
                .unwrap_or_default();
            pick_raster_dpi(dpi, &supported)
        }
        ForwardFormat::Postscript | ForwardFormat::Pdf => dpi,
    };

    Ok(IppCaps {
        make_and_model,
        color,
        dpi,
        paper_sizes,
        format,
        urf_quality,
    })
}

// ── Print sink: PostScript → IPP Print-Job ────────────────────────────────────

struct IppForwardSink {
    uri: Uri,
    forwarding: Forwarding,
    printer: String,
    /// Serialises forwarded jobs so two quick prints can't arrive out of order.
    serial: Arc<Mutex<()>>,
    counter: AtomicU32,
    laser_prep: LaserPrep,
}

impl PrintSink for IppForwardSink {
    fn receive_job(
        &self,
        job: PrintJob,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        let uri = self.uri.clone();
        let forwarding = self.forwarding;
        let printer = self.printer.clone();
        let serial = self.serial.clone();
        // A prologue download is not a document; keep it for the jobs that reference
        // it instead of sending a blank page to the printer. Checked before the
        // counter moves so job numbers still count documents.
        if self.laser_prep.capture(job.connection, &job.data) {
            return Box::pin(std::future::ready(Ok(())));
        }
        // Resolved here, while the connection that downloaded it is still the one
        // being served: the forward runs detached and may outlive it.
        let prep = self.laser_prep.for_job(job.connection, &job.data);
        let n = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        Box::pin(async move {
            // Forward in the background so the PAP session keeps answering the Mac's
            // status polls; the Mac considers the job delivered at PAP EOF, so a
            // failure here can only be logged.
            tokio::spawn(async move {
                let _guard = serial.lock().await;
                match forward_job(&uri, forwarding, job.data, prep, n).await {
                    Ok(job_id) => tracing::info!(
                        "LW bridge: job {n} for '{printer}' submitted (IPP job {job_id})"
                    ),
                    Err(e) => tracing::error!("LW bridge: job {n} for '{printer}' failed: {e}"),
                }
            });
            Ok(())
        })
    }
}

/// Extract the `%%Title:` DSC comment from a PostScript job for the IPP job name.
fn ps_title(data: &[u8]) -> Option<String> {
    let head = &data[..data.len().min(4096)];
    let text = String::from_utf8_lossy(head);
    for line in text.split(['\r', '\n']) {
        if let Some(title) = line.strip_prefix("%%Title:") {
            let title = title.trim().trim_matches(|c| c == '(' || c == ')').trim();
            if !title.is_empty() {
                return Some(title.chars().take(255).collect());
            }
        }
    }
    None
}

async fn forward_job(
    uri: &Uri,
    forwarding: Forwarding,
    ps: Vec<u8>,
    prep: Option<Vec<u8>>,
    n: u32,
) -> anyhow::Result<i32> {
    let Forwarding { format, dpi, color, urf_quality } = forwarding;
    let title = ps_title(&ps).unwrap_or_else(|| format!("TailTalk job {n}"));

    let doc = match format {
        // A document from a 5.x/6.x driver is not self-contained PostScript: it
        // leans on the prologue we swallowed, and forwarding it alone gets
        // `/undefined in md` at the printer. Ghostscript puts the two back together
        // and writes out PostScript that stands on its own.
        ForwardFormat::Postscript if prep.is_some() => {
            gs_convert(&ps, prep.as_deref(), "ps2write", &[]).await?
        }
        ForwardFormat::Postscript => ps,
        ForwardFormat::Pdf => gs_convert(&ps, prep.as_deref(), "pdfwrite", &[]).await?,
        ForwardFormat::Urf => {
            let device = if color { "urfrgb" } else { "urfgray" };
            let mut raster = gs_convert(&ps, prep.as_deref(), device, &[format!("-r{dpi}")]).await?;
            urf_conform(&mut raster, color, urf_quality)?;
            raster
        }
        ForwardFormat::PwgRaster => {
            gs_convert(&ps, prep.as_deref(), "pwgraster", &[format!("-r{dpi}")]).await?
        }
    };

    let payload = IppPayload::new(Cursor::new(doc));
    let op = IppOperationBuilder::print_job(uri.clone(), payload)
        .user_name("TailTalk")
        .job_title(&title)
        .document_format(format.mime())
        .build()?;

    let client = ipp_client(uri);
    let resp = tokio::time::timeout(Duration::from_secs(300), client.send(op))
        .await
        .map_err(|_| anyhow::anyhow!("Print-Job timed out"))??;

    let status = resp.header().operation_or_status;
    anyhow::ensure!(status < 0x100, "Print-Job failed: 0x{status:04x}");

    let job_id = resp
        .attributes()
        .groups_of(DelimiterTag::JobAttributes)
        .next()
        .and_then(|g| g.attributes().get("job-id"))
        .and_then(|a| match a.value() {
            IppValue::Integer(id) => Some(*id),
            _ => None,
        })
        .unwrap_or(0);
    Ok(job_id)
}

/// Fonts we may tell the Mac are already in the printer, worked out once per run.
static RESIDENT_FONTS: tokio::sync::OnceCell<Vec<String>> = tokio::sync::OnceCell::const_new();

/// The subset of the standard 35 that our renderer can actually produce.
///
/// Claiming a font makes the driver reference it by name instead of downloading the
/// font program, which is the difference between a job that crawls over LocalTalk
/// and one that doesn't. Claiming one we cannot render, though, means the page comes
/// out in a substitute face, so every name is checked against Ghostscript's own
/// font resources before we promise it. No Ghostscript, no promises: an empty list
/// comes back, and the caller decides what to do with it.
pub(crate) async fn resident_fonts() -> Vec<String> {
    RESIDENT_FONTS
        .get_or_init(|| async {
            let available = match gs_font_names().await {
                Ok(names) => names,
                Err(e) => {
                    tracing::info!(
                        "LW bridge: could not list Ghostscript's fonts ({e}), so the Mac \
                         will be told the printer has none and will embed them all"
                    );
                    return Vec::new();
                }
            };
            let (have, missing): (Vec<&str>, Vec<&str>) = tailtalk::pap::LASERWRITER_35
                .iter()
                .copied()
                .partition(|font| available.contains(*font));
            if !missing.is_empty() {
                tracing::info!(
                    "LW bridge: Ghostscript is missing {} of the standard 35 ({}), \
                     so those stay embedded",
                    missing.len(),
                    missing.join(", ")
                );
            }
            have.into_iter().map(str::to_string).collect()
        })
        .await
        .clone()
}

/// Ask Ghostscript for every font it can resolve, Fontmap aliases included.
async fn gs_font_names() -> anyhow::Result<HashSet<String>> {
    let output = tokio::process::Command::new(crate::ipp_bridge::gs_command())
        .args(["-q", "-dNODISPLAY", "-dBATCH", "-dNOPAUSE", "-dSAFER"])
        // resourceforall walks the /Font category, so this covers the URW faces
        // aliased to the standard names rather than just what is already loaded.
        .args(["-c", "(*) {cvn ==} 256 string /Font resourceforall quit"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("gs exited with {}: {}", output.status, stderr.trim());
    }

    // `==` prints each name in syntactic form, so one `/Name` per line.
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().strip_prefix('/'))
        .map(|name| name.to_string())
        .collect())
}

// ── LaserPrep, the Apple `md` dictionary ──────────────────────────────────────

/// Offset of `needle` in `haystack`.
///
/// On the bytes, not on a decoded string: a PostScript prologue carries eexec
/// binary, and an offset counted in a lossy decode of it does not point where it
/// says it does once a byte has been replaced by a three-byte U+FFFD.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The LaserPrep prologue downloaded on the PAP connection currently being served.
///
/// The LaserWriter 5.x/6.x/7.x drivers do not put their PostScript dictionary in the
/// document. They send it as its own PAP job, an ExitServer job that on a real
/// printer survives in VM until power-off, then print documents that merely say
/// `%%IncludeProcSet: "(AppleDict md)"` and `md begin`. Each of those documents is
/// meaningless on its own: Ghostscript stops at `/undefined in md`.
///
/// Scoped to the connection that sent it, which is all the scope it needs: we answer
/// every `%%?BeginProcSetQuery` with "0" (not resident), so a driver re-downloads
/// the prologue on every connection where it intends to use one, and a capture shows
/// query, prologue and document arriving as three jobs of a single conversation.
/// One slot is enough because [`PapServer`] serves one connection at a time and
/// refuses the rest as busy; a prologue from a conversation that has ended can never
/// be handed to the next one, because the [`ConnectionId`] will not match.
pub(crate) struct LaserPrep {
    held: StdMutex<Option<(ConnectionId, Vec<u8>)>>,
}

impl LaserPrep {
    pub(crate) const fn new() -> Self {
        Self { held: StdMutex::new(None) }
    }

    /// Remember a job if it is a prologue download, and report whether it was one.
    ///
    /// A prologue prints nothing, so a caller that gets `true` should drop the job
    /// rather than save or forward it.
    pub(crate) fn capture(&self, connection: ConnectionId, data: &[u8]) -> bool {
        if !Self::is_prologue(data) {
            return false;
        }
        let stripped = Self::strip_exit_server(data);
        tracing::info!(
            "LaserWriter: stored LaserPrep prologue ({} bytes) for this connection, \
             will replay it ahead of each job that needs it",
            stripped.len()
        );
        *self.held.lock().unwrap() = Some((connection, stripped));
        true
    }

    /// The prologue to run ahead of this job: one it asks for, downloaded by the
    /// conversation it belongs to.
    pub(crate) fn for_job(&self, connection: ConnectionId, data: &[u8]) -> Option<Vec<u8>> {
        if !Self::needs_prologue(data) {
            return None;
        }
        let held = self.held.lock().unwrap();
        let (from, prologue) = held.as_ref()?;
        (*from == connection).then(|| prologue.clone())
    }

    /// Is this job a prologue download rather than something to print?
    ///
    /// An ExitServer job says so on its `%!PS-Adobe` line. A few driver versions
    /// leave the header plain, so the `serverdict begin exitserver` call counts too.
    fn is_prologue(data: &[u8]) -> bool {
        let head = &data[..data.len().min(4096)];
        let first = head.split(|&b| b == b'\r' || b == b'\n').next().unwrap_or_default();
        (first.starts_with(b"%!") && find_bytes(first, b"ExitServer").is_some())
            || find_bytes(head, b"serverdict begin exitserver").is_some()
    }

    /// Does this job depend on a prologue it does not carry itself?
    fn needs_prologue(data: &[u8]) -> bool {
        let head = &data[..data.len().min(8192)];
        find_bytes(head, b"%%IncludeProcSet:").is_some()
            || find_bytes(head, b"(AppleDict md)").is_some()
    }

    /// Strip the `%%BeginExitServer`/`%%EndExitServer` block from a prologue.
    ///
    /// The block is just the password and the `serverdict begin exitserver` call
    /// that moves the definitions into the printer's permanent VM. Ghostscript
    /// refuses that call with `/invalidaccess in exitserver`, and we do not need it:
    /// replaying the prologue ahead of each job gives the same definitions for the
    /// job's lifetime.
    fn strip_exit_server(data: &[u8]) -> Vec<u8> {
        const END: &[u8] = b"%%EndExitServer";
        let Some(start) = find_bytes(data, b"%%BeginExitServer") else {
            return data.to_vec();
        };
        let Some(end) = find_bytes(&data[start..], END) else {
            return data.to_vec();
        };
        // Take the line terminator after the End comment with it, so the two halves
        // do not run together into one token.
        let mut after = start + end + END.len();
        while data.get(after).is_some_and(|b| *b == b'\r' || *b == b'\n') {
            after += 1;
        }
        let mut out = Vec::with_capacity(data.len());
        out.extend_from_slice(&data[..start]);
        out.extend_from_slice(&data[after..]);
        out
    }
}

/// Run Ghostscript over a PostScript job with the given output device.
pub(crate) async fn gs_convert(
    ps: &[u8],
    prep: Option<&[u8]>,
    device: &str,
    extra_args: &[String],
) -> anyhow::Result<Vec<u8>> {
    let id = GS_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = std::env::temp_dir();
    let in_path = tmp.join(format!("tailtalk-gs-{id}.ps"));
    let out_path = tmp.join(format!("tailtalk-gs-{id}.out"));
    tokio::fs::write(&in_path, ps).await?;

    // A job that includes a ProcSet we have seen downloaded gets that prologue put
    // back in front of it, as a *separate* input file rather than concatenated.
    // LaserPrep decides twice whether it is talking to a genuine LaserWriter, and
    // when it decides it is not it runs `currentfile … flushfile`, which on one
    // combined stream would swallow the document along with the rest of itself.
    // Ghostscript runs each file on the command line in turn in the same
    // interpreter, so the definitions carry over but the flush stops at the
    // prologue's own end.
    let prep_path = match prep {
        Some(prep) => {
            let path = tmp.join(format!("tailtalk-gs-{id}-prep.ps"));
            tokio::fs::write(&path, prep).await?;
            Some(path)
        }
        None => None,
    };

    let mut cmd = tokio::process::Command::new(crate::ipp_bridge::gs_command());
    cmd.args(["-dNOPAUSE", "-dBATCH", "-dSAFER"])
        .arg(format!("-sDEVICE={device}"))
        .args(extra_args)
        .arg("-o")
        .arg(&out_path);
    if let Some(path) = &prep_path {
        cmd.arg(path);
    }
    let output = cmd
        .arg(&in_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await?;

    let _ = tokio::fs::remove_file(&in_path).await;
    if let Some(path) = &prep_path {
        let _ = tokio::fs::remove_file(path).await;
    }

    if !output.status.success() {
        let _ = tokio::fs::remove_file(&out_path).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("gs {device} exited with {}: {}", output.status, stderr.trim());
    }

    let out = tokio::fs::read(&out_path).await?;
    let _ = tokio::fs::remove_file(&out_path).await;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header of a real System 6 LaserPrep job, CR-terminated like the wire.
    const PREP: &[u8] = b"%!PS-Adobe-2.0 ExitServer\r\
        %%BeginExitServer: 0000000000\r\
        0000000000\r\
        serverdict begin exitserver\r\
        %%EndExitServer\r\
        %%Title: \"Laser Prep\"\r\
        /md 200 dict def\r";

    /// The header of the document that follows it.
    const DOC: &[u8] = b"%!PS-Adobe-2.0\r\
        %%Creator: TeachText\r\
        %%IncludeProcSet: \"(AppleDict md)\" 68 0\r\
        md begin\r";

    #[test]
    fn laser_prep_recognised() {
        assert!(LaserPrep::is_prologue(PREP));
        assert!(!LaserPrep::is_prologue(DOC));
        // Header without the ExitServer keyword, recognised by the call itself.
        assert!(LaserPrep::is_prologue(b"%!PS-Adobe-2.0\rserverdict begin exitserver\r"));
    }

    #[test]
    fn exit_server_block_stripped() {
        let out = LaserPrep::strip_exit_server(PREP);
        let text = String::from_utf8(out).unwrap();
        // The password and the exitserver call go, everything else stays.
        assert!(!text.contains("exitserver"));
        assert!(!text.contains("0000000000"));
        assert!(text.starts_with("%!PS-Adobe-2.0 ExitServer\r"));
        assert!(text.contains("/md 200 dict def"));
        // The two halves must not have run together into one token.
        assert!(text.contains("ExitServer\r%%Title:"));
    }

    #[test]
    fn strip_exit_server_leaves_other_jobs_alone() {
        assert_eq!(LaserPrep::strip_exit_server(DOC), DOC);
    }

    #[test]
    fn exit_server_offsets_are_counted_on_the_bytes() {
        // A prologue is not text: the definitions it carries are eexec-encrypted, so
        // an offset taken from a lossy decode would land in the wrong place and cut
        // the job apart mid-token.
        let mut prep = PREP.to_vec();
        prep.extend_from_slice(b"\rdup(\x18\xae\xda\xe1\xa9\xf9)eexec\r");
        assert!(String::from_utf8(prep.clone()).is_err(), "fixture must not be text");

        let out = LaserPrep::strip_exit_server(&prep);
        assert!(find_bytes(&out, b"serverdict begin exitserver").is_none());
        assert!(out.starts_with(b"%!PS-Adobe-2.0 ExitServer\r%%Title:"));
        assert!(out.ends_with(b"eexec\r"), "the binary tail must survive intact");
    }

    #[test]
    fn procset_users_ask_for_the_prologue() {
        assert!(LaserPrep::needs_prologue(DOC));
        assert!(!LaserPrep::needs_prologue(
            b"%!PS-Adobe-3.0\r100 100 moveto\rshowpage\r"
        ));
    }

    #[test]
    fn capturing_a_prologue_consumes_it() {
        let conn = ConnectionId(1);
        let store = LaserPrep::new();
        assert!(store.capture(conn, PREP));
        assert!(!store.capture(conn, DOC));
        let held = store
            .for_job(conn, DOC)
            .expect("a document asking for it gets it");
        assert!(!String::from_utf8_lossy(&held).contains("exitserver"));
        assert_eq!(
            store.for_job(conn, b"%!PS-Adobe-3.0\rshowpage\r"),
            None,
            "a self-contained job is left alone"
        );
    }

    #[test]
    fn a_prologue_belongs_to_the_connection_that_sent_it() {
        // A driver downloads the prologue on the connection it is about to print
        // on, so one left over from a conversation that has ended says nothing
        // about this one: the next driver may be a different version of the
        // dictionary, or may not use one at all.
        let store = LaserPrep::new();
        assert!(store.capture(ConnectionId(1), PREP));
        assert_eq!(
            store.for_job(ConnectionId(2), DOC),
            None,
            "the next connection must not inherit it"
        );
        assert!(store.for_job(ConnectionId(1), DOC).is_some());

        // And the next connection's download replaces it.
        let mut newer = PREP.to_vec();
        newer.extend_from_slice(b"/newer true def\r");
        assert!(store.capture(ConnectionId(2), &newer));
        assert!(store.for_job(ConnectionId(2), DOC).is_some());
        assert_eq!(store.for_job(ConnectionId(1), DOC), None);
    }

    #[test]
    fn nbp_names_sanitized() {
        assert_eq!(nbp_safe_name("HP LaserJet Pro"), "HP LaserJet Pro");
        assert_eq!(nbp_safe_name("Foo: Bar @ Home"), "Foo Bar Home");
        assert_eq!(
            nbp_safe_name("A very long printer name that exceeds limits"),
            "A very long printer name that ex"
        );
        assert_eq!(nbp_safe_name("Caf\u{e9} Printer"), "Caf Printer");
    }

    #[test]
    fn nbp_names_disambiguated() {
        let mut taken = HashSet::new();
        assert_eq!(unique_nbp_name("Printer", &taken), "Printer");
        taken.insert("Printer");
        assert_eq!(unique_nbp_name("Printer", &taken), "Printer 2");
    }

    /// A URF stream as Ghostscript writes it: `pages` pages of 3 × 2 gray pixels.
    fn gs_style_urf(pages: usize) -> Vec<u8> {
        let mut v = b"UNIRAST\0".to_vec();
        v.extend_from_slice(&0u32.to_be_bytes());
        for _ in 0..pages {
            let mut header = [0u8; 32];
            header[0] = 8;
            header[1] = 4; // device gray, as Ghostscript marks it
            header[12..16].copy_from_slice(&3u32.to_be_bytes());
            header[16..20].copy_from_slice(&2u32.to_be_bytes());
            header[20..24].copy_from_slice(&300u32.to_be_bytes());
            v.extend_from_slice(&header);
            v.extend_from_slice(&[1, 2, 0xff]); // both lines: three white pixels
        }
        v
    }

    #[test]
    fn urf_pages_are_found_and_their_headers_corrected() {
        let mut urf = gs_style_urf(2);
        assert_eq!(urf_page_headers(&urf).unwrap(), [12, 12 + 35]);
        urf_conform(&mut urf, false, 5).unwrap();
        assert_eq!(&urf[8..12], &2u32.to_be_bytes());
        for at in [12, 47] {
            assert_eq!(&urf[at..at + 4], &[8, 0, 1, 5], "page header at {at}");
        }
        let mut colour = gs_style_urf(1);
        urf_conform(&mut colour, true, 4).unwrap();
        assert_eq!(&colour[12..16], &[8, 1, 1, 4]);
    }

    #[test]
    fn a_cut_short_urf_stream_is_refused() {
        let urf = gs_style_urf(1);
        assert!(urf_page_headers(&urf[..urf.len() - 1]).is_err());
        assert!(urf_page_headers(b"not urf").is_err());
    }

    #[test]
    fn urf_quality_comes_from_what_the_printer_takes() {
        assert_eq!(urf_qualities(["CP1", "PQ4-5", "W8"]), [4, 5]);
        assert_eq!(urf_qualities(["PQ5"]), [5]);
        assert_eq!(pick_urf_quality(&[4, 5]), 4);
        assert_eq!(pick_urf_quality(&[5]), 5);
        assert_eq!(pick_urf_quality(&[3, 5]), 3);
        assert_eq!(pick_urf_quality(&[]), 4);
    }

    #[test]
    fn raster_resolution_comes_from_what_the_printer_takes() {
        // The ET-4750: default 600, URF at 300 only.
        assert_eq!(urf_resolutions(["CP1", "RS300", "W8"]), [300]);
        assert_eq!(urf_resolutions(["RS300-600", "V1.4"]), [300, 600]);
        assert_eq!(pick_raster_dpi(600, &[300]), 300);
        assert_eq!(pick_raster_dpi(600, &[300, 600]), 600);
        assert_eq!(pick_raster_dpi(300, &[600, 1200]), 600);
        assert_eq!(pick_raster_dpi(600, &[]), 600);
    }

    #[test]
    fn plain_ipp_first_unless_the_printer_announces_tls() {
        assert_eq!(
            candidate_uris("192.168.1.9", 631, "ipp/print", false),
            ["ipp://192.168.1.9:631/ipp/print", "ipps://192.168.1.9:631/ipp/print"]
        );
        assert_eq!(
            candidate_uris("192.168.1.9", 631, "ipp/print", true),
            ["ipps://192.168.1.9:631/ipp/print", "ipp://192.168.1.9:631/ipp/print"]
        );
    }

    /// Live query against a real printer, e.g.:
    ///   TAILTALK_TEST_IPP_URI=ipp://printer.local:631/ipp/print \
    ///     cargo test -p tailtalk-gui live_ipp_caps -- --ignored --nocapture
    /// An `ipps://` URI exercises the TLS path.
    #[tokio::test]
    #[ignore]
    async fn live_ipp_caps() {
        let uri = std::env::var("TAILTALK_TEST_IPP_URI")
            .expect("set TAILTALK_TEST_IPP_URI to run this test");
        let caps = query_ipp_caps(&uri.parse().unwrap()).await.unwrap();
        println!("caps: {caps:?}");
    }

    /// Prints one page on a real printer, converted the way a bridged job would be:
    ///   TAILTALK_TEST_IPP_URI=ipps://printer.local:631/ipp/print \
    ///     cargo test -p tailtalk-gui live_ipp_print -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn live_ipp_print() {
        let uri: Uri = std::env::var("TAILTALK_TEST_IPP_URI")
            .expect("set TAILTALK_TEST_IPP_URI to run this test")
            .parse()
            .unwrap();
        let caps = query_ipp_caps(&uri).await.unwrap();
        println!("caps: {caps:?}");
        let ps = concat!(
            "%!PS-Adobe-3.0\n%%Title: TailTalk live_ipp_print\n",
            "/Helvetica findfont 24 scalefont setfont\n",
            "72 700 moveto (TailTalk: printed straight to the printer over IPP) show\n",
            "72 660 moveto (no relay, no driver) show\nshowpage\n"
        )
        .as_bytes()
        .to_vec();
        let job = forward_job(&uri, Forwarding::for_printer(&caps), ps, None, 1).await.unwrap();
        println!("submitted as IPP job {job}");
    }

    /// Skipped where Ghostscript isn't installed, since there is nothing to ask.
    #[tokio::test]
    async fn gs_reports_the_standard_35() {
        if !crate::ipp_bridge::gs_probe() {
            eprintln!("skipping: no Ghostscript on this machine");
            return;
        }
        let names = gs_font_names().await.expect("gs font query failed");
        // Ghostscript ships URW equivalents of all 35 under the standard names, so
        // anything missing here means the query itself broke, not the font set.
        let missing: Vec<_> = tailtalk::pap::LASERWRITER_35
            .iter()
            .filter(|f| !names.contains(**f))
            .collect();
        assert!(missing.is_empty(), "gs is missing {missing:?} of {} names", names.len());
        assert_eq!(resident_fonts().await.len(), 35);
    }

    #[test]
    fn ps_title_extracted() {
        let ps = b"%!PS-Adobe-3.0\r%%Title: (My Document)\r%%EndComments\r";
        assert_eq!(ps_title(ps).as_deref(), Some("My Document"));
        assert_eq!(ps_title(b"%!PS-Adobe-3.0\n"), None);
    }
}

