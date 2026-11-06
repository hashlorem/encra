use quick_xml::events::Event;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NmapHost {
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub ports: Vec<NmapPort>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NmapPort {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: String,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NmapScan {
    pub hosts: Vec<NmapHost>,
    pub total_hosts: usize,
    pub total_open_ports: usize,
}

/// Hard ceiling on the XML document we accept. Parsing holds the whole document
/// in memory, so an accidental or hostile multi-gigabyte file is rejected up
/// front rather than allowed to exhaust the process.
const MAX_XML_BYTES: usize = 32 * 1024 * 1024;
const MAX_HOSTS: usize = 100_000;
const MAX_PORTS_PER_HOST: usize = 10_000;

pub fn parse_nmap_xml(xml: &str) -> Result<NmapScan, String> {
    if xml.len() > MAX_XML_BYTES {
        return Err(format!(
            "scan file is too large: {} bytes (max {MAX_XML_BYTES})",
            xml.len()
        ));
    }

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut hosts: Vec<NmapHost> = Vec::new();
    let mut current_host: Option<NmapHost> = None;
    let mut current_port: Option<NmapPort> = None;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => match e.name().as_ref() {
                b"host" => {
                    if hosts.len() >= MAX_HOSTS {
                        return Err(format!("scan contains more than {MAX_HOSTS} hosts"));
                    }
                    current_host = Some(NmapHost {
                        ip: String::new(),
                        hostname: None,
                        os: None,
                        ports: Vec::new(),
                    });
                }
                b"ports" => {},
                b"port" => {
                    let mut port_num = 0u16;
                    let mut protocol = String::new();
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"portid" => {
                                port_num = String::from_utf8_lossy(&attr.value)
                                    .parse()
                                    .unwrap_or(0);
                            }
                            b"protocol" => {
                                protocol = String::from_utf8_lossy(&attr.value).to_string();
                            }
                            _ => {}
                        }
                    }
                    current_port = Some(NmapPort {
                        port: port_num,
                        protocol,
                        state: "unknown".into(),
                        service: "unknown".into(),
                        version: None,
                    });
                }
                b"address" => {
                    if let Some(ref mut host) = current_host {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"addr" && host.ip.is_empty() {
                                host.ip = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                }
                b"hostname" => {
                    if let Some(ref mut host) = current_host {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"name" {
                                host.hostname =
                                    Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                        }
                    }
                }
                b"osmatch" => {
                    if let Some(ref mut host) = current_host {
                        if host.os.is_none() {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"name" {
                                    host.os =
                                        Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                            }
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::End(ref e)) => match e.name().as_ref() {
                b"host" => {
                    if let Some(host) = current_host.take() {
                        hosts.push(host);
                    }
                }
                b"ports" => {},
                b"port" => {
                    if let Some(port) = current_port.take() {
                        if let Some(ref mut host) = current_host {
                            if host.ports.len() >= MAX_PORTS_PER_HOST {
                                return Err(format!(
                                    "host has more than {MAX_PORTS_PER_HOST} ports"
                                ));
                            }
                            host.ports.push(port);
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::Empty(ref e)) => match e.name().as_ref() {
                b"state" => {
                    if let Some(ref mut port) = current_port {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"state" {
                                port.state =
                                    String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                }
                b"service" => {
                    if let Some(ref mut port) = current_port {
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"name" => {
                                    port.service =
                                        String::from_utf8_lossy(&attr.value).to_string();
                                }
                                b"product" => {
                                    port.version =
                                        Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                }
                b"address" => {
                    if let Some(ref mut host) = current_host {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"addr" && host.ip.is_empty() {
                                host.ip = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                }
                b"hostname" => {
                    if let Some(ref mut host) = current_host {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"name" {
                                host.hostname = Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e)),
            _ => {}
        }
        buf.clear();
    }

    let total_open_ports: usize = hosts
        .iter()
        .map(|h| h.ports.iter().filter(|p| p.state == "open").count())
        .sum();

    Ok(NmapScan {
        total_hosts: hosts.len(),
        total_open_ports,
        hosts,
    })
}
