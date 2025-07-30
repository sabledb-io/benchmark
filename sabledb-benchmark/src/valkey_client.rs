use crate::sb_options as options;
use async_trait::async_trait;
use bytes::BytesMut;
use pki_types::{CertificateDer, ServerName, UnixTime};
use sbcommonlib::{
    BytesMutUtils, CommonError, ParserError, RequestParser, RespBuilderV2, RespResponseParserV2,
    ResponseParseResult, ValkeyObject,
};
use std::net::SocketAddrV4;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::Error as TLSError;
use tokio_rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    DigitallySignedStruct,
};

use std::collections::HashMap;

pub const SLOT_SIZE: u16 = 16384;

fn find_hashtags(key: &[u8]) -> Option<&[u8]> {
    let open = key.iter().position(|v| *v == b'{')?;
    let close = key[open..].iter().position(|v| *v == b'}')?;

    let rv = &key[open + 1..open + close];
    if rv.is_empty() {
        None
    } else {
        Some(rv)
    }
}

/// Provide an API for calculating the slot from a given user key
pub fn calculate_slot(key: &[u8]) -> u16 {
    // If we have hashtags, use the key inside it, otherwise use the entire key
    let key = match find_hashtags(key) {
        Some(tag) => tag,
        None => key,
    };
    crc16::State::<crc16::XMODEM>::calculate(key) % SLOT_SIZE
}

/// Given input buffer of raw RESP buffer, return the slot
/// for the command.
fn slot_from_buffer(buffer: &BytesMut) -> Result<Option<u16>, CommonError> {
    if buffer.is_empty() {
        return Ok(None);
    }

    let buffer = if buffer[0] == b'*' {
        // skip the array prefix and only parse the first command
        &buffer[1..]
    } else {
        &buffer[..]
    };

    let mut parser = RequestParser::default();
    let request = parser.parse(buffer)?;
    let Some(key) = request.command.get(1) else {
        return Ok(None);
    };
    // Convert key into slot
    Ok(Some(calculate_slot(&key[..])))
}

/// Parse host string in the format of: "host:port" and split it into address + port pair.
#[allow(dead_code)]
fn parse_address(addr: &str) -> Option<(String, u16)> {
    let (host, port) = addr.split_once(':')?;
    let port = port.parse().ok()?;
    Some((host.to_string(), port))
}

/// Parse MOVED error in the format of: "MOVED 16308 127.0.0.10:7002"
/// and return the triplet: slot,host,port
fn parse_moved(errmsg: &str) -> Option<(u16, String, u16)> {
    let (_, triplet) = errmsg.split_once(' ')?; // remove the "MOVED"
    let (slot, addr) = triplet.split_once(' ')?;
    let (host, port) = addr.split_once(':')?;
    let slot = slot.parse::<u16>().ok()?;
    let port = port.parse::<u16>().ok()?;
    Some((slot, host.to_string(), port))
}

/// Parse cluster nodes line output (a single line).
/// <id> <ip:port@cport[,hostname]> ...
/// We only care for the IP:PORT
fn parse_cluster_nodes_line(line: &str) -> Option<(String, u16)> {
    let (_, remainder) = line.split_once(' ')?; // remove the "id"
    let (addr, _) = remainder.split_once(' ')?;
    let (ip, port_cport) = addr.split_once(':')?;
    let (port, _) = port_cport.split_once('@')?;
    let port = port.parse::<u16>().ok()?;
    Some((ip.to_string(), port))
}

#[derive(Debug)]
struct NoVerifier;

/// Allow this client to accept self signed certificates by installing a `NoVerifier`
impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        let schemes = vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA1,
            tokio_rustls::rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA384,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA512,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
            tokio_rustls::rustls::SignatureScheme::ED25519,
            tokio_rustls::rustls::SignatureScheme::ED448,
        ];
        schemes
    }
}

#[derive(Default)]
pub enum StreamType {
    Tls(TlsStream<TcpStream>),
    Plain(TcpStream),
    #[default]
    Invalid,
}

struct StreamHelper {}

impl StreamHelper {
    async fn write_buffer(stream: &mut StreamType, buffer: &BytesMut) -> Result<(), CommonError> {
        match stream {
            StreamType::Tls(s) => {
                s.write_all(buffer).await?;
            }
            StreamType::Plain(s) => {
                s.write_all(buffer).await?;
            }
            StreamType::Invalid => {
                return Err(CommonError::InvalidArgument("Invalid stream".into()));
            }
        }
        Ok(())
    }

    async fn read_response(
        stream: &mut StreamType,
        read_buffer: &mut BytesMut,
    ) -> Result<ValkeyObject, CommonError> {
        loop {
            match RespResponseParserV2::parse_response(read_buffer)? {
                ResponseParseResult::NeedMoreData => {
                    Self::read_more_bytes(stream, read_buffer).await?;
                }
                ResponseParseResult::Ok((consume, obj)) => {
                    let _ = read_buffer.split_to(consume);
                    return Ok(obj);
                }
            }
        }
    }

    async fn read_more_bytes(
        stream: &mut StreamType,
        read_buffer: &mut BytesMut,
    ) -> Result<(), CommonError> {
        let mut buffer = BytesMut::with_capacity(4096);
        match stream {
            StreamType::Tls(s) => {
                s.read_buf(&mut buffer).await?;
            }
            StreamType::Plain(s) => {
                s.read_buf(&mut buffer).await?;
            }
            StreamType::Invalid => {
                return Err(CommonError::InvalidArgument("invalid stream type".into()));
            }
        }

        if buffer.is_empty() {
            return Err(CommonError::OtherError(
                "Server closed connection".to_string(),
            ));
        }
        read_buffer.extend_from_slice(&buffer);
        Ok(())
    }
}

#[derive(Default)]
pub struct ValkeyClient {
    builder: RespBuilderV2,
    read_buffer: BytesMut,
    stream: StreamType,
}

impl ValkeyClient {
    /// Connect with retries
    async fn connect_with_retries(host: &String, port: u16) -> Result<TcpStream, CommonError> {
        let connection_string = format!("{}:{}", host, port);
        let socket: SocketAddrV4 = connection_string.parse().expect("parse");
        let mut counter = 0u64;
        loop {
            let res = TcpStream::connect(socket).await;
            if let Ok(conn) = res {
                return Ok(conn);
            } else {
                counter += 1;
                tokio::time::sleep(tokio::time::Duration::from_millis(counter)).await;
                if counter == 100 {
                    return Err(CommonError::OtherError(format!(
                        "Failed to connect. {:?}",
                        res.err()
                    )));
                }
            }
        }
    }

    pub async fn connect(
        host: String,
        port: u16,
        ssl: bool,
    ) -> Result<Box<dyn Connection>, CommonError> {
        let stream = Self::connect_with_retries(&host, port).await?;
        let stream = if ssl {
            let mut root_cert_store = rustls::RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = tokio_rustls::rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(
                    crate::valkey_client::NoVerifier {},
                ))
                .with_no_client_auth(); // i guess this was previously the default?
            let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
            let dns: ServerName = host.try_into().expect("invalid DNS name");
            let stream = connector.connect(dns, stream).await?;

            StreamType::Tls(stream)
        } else {
            StreamType::Plain(stream)
        };

        Ok(Box::new(ValkeyClient {
            stream,
            ..Default::default()
        }))
    }

    pub async fn connect_stream(
        host: String,
        port: u16,
        ssl: bool,
    ) -> Result<StreamType, CommonError> {
        let stream = Self::connect_with_retries(&host, port).await?;
        let stream = if ssl {
            let mut root_cert_store = rustls::RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = tokio_rustls::rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(
                    crate::valkey_client::NoVerifier {},
                ))
                .with_no_client_auth(); // i guess this was previously the default?
            let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
            let dns: ServerName = host.try_into().expect("invalid DNS name");
            let stream = connector.connect(dns, stream).await?;

            StreamType::Tls(stream)
        } else {
            StreamType::Plain(stream)
        };
        Ok(stream)
    }

    pub fn build_set_command(&self, buffer: &mut BytesMut, key: &BytesMut, value: &BytesMut) {
        // prepare and send command
        self.builder.add_array_len(buffer, 3);
        self.builder.add_bulk_string(buffer, &BytesMut::from("set"));
        self.builder.add_bulk_string(buffer, key);
        self.builder.add_bulk_string(buffer, value);
    }

    pub fn build_get_command(&self, buffer: &mut BytesMut, key: &BytesMut) {
        // prepare and send command
        self.builder.add_array_len(buffer, 2);
        self.builder.add_bulk_string(buffer, &BytesMut::from("get"));
        self.builder.add_bulk_string(buffer, key);
    }

    pub fn build_ping_command(&self, buffer: &mut BytesMut) {
        // prepare and send command
        self.builder.add_array_len(buffer, 1);
        self.builder
            .add_bulk_string(buffer, &BytesMut::from("ping"));
    }

    pub fn build_incr_command(&self, buffer: &mut BytesMut, key: &BytesMut, incremenet: u64) {
        self.builder.add_array_len(buffer, 3);
        self.builder
            .add_bulk_string(buffer, &BytesMut::from("incrby"));
        self.builder.add_bulk_string(buffer, key);
        self.builder
            .add_bulk_string(buffer, &BytesMutUtils::from::<u64>(&incremenet));
    }

    pub fn build_push_command(
        &self,
        buffer: &mut BytesMut,
        key: &BytesMut,
        value: &BytesMut,
        right: bool,
    ) {
        let cmd = if right {
            BytesMut::from("rpush")
        } else {
            BytesMut::from("lpush")
        };
        self.builder.add_array_len(buffer, 3);
        self.builder.add_bulk_string(buffer, &cmd);
        self.builder.add_bulk_string(buffer, key);
        self.builder.add_bulk_string(buffer, value);
    }

    pub fn build_pop_command(&self, buffer: &mut BytesMut, key: &BytesMut, right: bool) {
        let cmd = if right {
            BytesMut::from("rpop")
        } else {
            BytesMut::from("lpop")
        };
        self.builder.add_array_len(buffer, 2);
        self.builder.add_bulk_string(buffer, &cmd);
        self.builder.add_bulk_string(buffer, key);
    }

    pub fn build_cluster_nodes(&self, buffer: &mut BytesMut) {
        self.builder.add_array_len(buffer, 2);
        self.builder.add_bulk_string(buffer, b"CLUSTER");
        self.builder.add_bulk_string(buffer, b"NODES");
    }

    pub fn build_hset_command(
        &self,
        buffer: &mut BytesMut,
        key: &BytesMut,
        field: &BytesMut,
        value: &BytesMut,
    ) {
        // build the command
        self.builder.add_array_len(buffer, 4);
        self.builder
            .add_bulk_string(buffer, &BytesMut::from("hset"));
        self.builder.add_bulk_string(buffer, key);
        self.builder.add_bulk_string(buffer, field);
        self.builder.add_bulk_string(buffer, value);
    }

    // Build an inline string
    pub fn build_vecdb_hset_command(&self, key: &str, field: &str, value: &str) -> String {
        // build the command
        format!("HSET {} {} \"{}\"\r\n", key, field, value)
    }

    /// Build FT.CREATE command.
    /// Example:
    /// FT.CREATE hash_idx1 ON HASH PREFIX 1 hash: SCHEMA vec AS VEC VECTOR HNSW 6 DIM 2 TYPE FLOAT32 DISTANCE_METRIC L2
    /// Return the index name.
    pub fn build_ft_create_command(&self, buffer: &mut BytesMut, opts: &crate::Options) -> String {
        // build the command
        let index_name = options::vecdb_index_name();
        let prefix = options::vecdb_index_prefix();
        let dim = opts.dim.to_string();
        let parts = [
            "FT.CREATE",
            index_name.as_str(),
            "ON",
            "HASH",
            "PREFIX",
            "1",
            prefix.as_str(),
            "SCHEMA",
            "vec",
            "AS",
            "VEC",
            "VECTOR",
            "HNSW",
            "6",
            "DIM",
            dim.as_str(),
            "TYPE",
            "FLOAT32",
            "DISTANCE_METRIC",
            "L2",
        ];
        self.builder.add_array_len(buffer, parts.len());
        parts
            .iter()
            .for_each(|s| self.builder.add_bulk_string(buffer, s.as_bytes()));
        index_name
    }
}

#[allow(dead_code)]
pub struct ValkeyCluster {
    address_to_conn: HashMap<String, (StreamType, BytesMut)>,
    slot_to_address: HashMap<u16, String>,
    discovery_conn: (StreamType, BytesMut),
    ssl_enabled: bool,
}

#[allow(dead_code)]
impl ValkeyCluster {
    pub async fn connect(
        host: String,
        port: u16,
        ssl_enabled: bool,
    ) -> Result<Box<dyn Connection>, CommonError> {
        let mut discovery_conn = (
            ValkeyClient::connect_stream(host.clone(), port, ssl_enabled).await?,
            BytesMut::default(),
        );

        // Run CLUSTER NODES
        let cmd_build = ValkeyClient::default();
        let mut buffer = BytesMut::default();
        cmd_build.build_cluster_nodes(&mut buffer);
        StreamHelper::write_buffer(&mut discovery_conn.0, &buffer).await?;
        let obj = StreamHelper::read_response(&mut discovery_conn.0, &mut discovery_conn.1).await?;

        let lines = match obj {
            ValkeyObject::Str(lines) => String::from_utf8_lossy(&lines).to_string(),
            _ => {
                return Err(CommonError::OtherError(
                    "Unexpected response. Expected String".into(),
                ))
            }
        };

        // Open connection to all the nodes in the cluster
        let mut address_to_conn = HashMap::<String, (StreamType, BytesMut)>::default();
        let lines = lines
            .lines()
            .map(|line| line.trim().to_string())
            .collect::<Vec<String>>();
        for line in lines {
            let (host, port) = parse_cluster_nodes_line(line.as_str()).ok_or(
                ParserError::InvalidInput(format!("Failed to parse cluster nodes line: {line}")),
            )?;

            let node_conn = (
                ValkeyClient::connect_stream(host.clone(), port, ssl_enabled).await?,
                BytesMut::default(),
            );
            address_to_conn.insert(format!("{}:{}", host, port), node_conn);
        }

        Ok(Box::new(ValkeyCluster {
            address_to_conn,
            slot_to_address: HashMap::<u16, String>::default(),
            discovery_conn,
            ssl_enabled,
        }))
    }

    /// Get connection for slot.
    pub async fn connection_for_slot(
        &mut self,
        slot: u16,
    ) -> Result<Option<&mut (StreamType, BytesMut)>, CommonError> {
        let Some(addr) = self.slot_to_address.get(&slot) else {
            // No mapping for this slot yet
            return Ok(None);
        };
        // Return the connection associated with this address (can be None)
        let c = self
            .connection_for_address(addr.clone())
            .ok_or(CommonError::OtherError(
                "Could not find connection for host".into(),
            ))?;
        Ok(Some(c))
    }

    /// Get or create a connection for host:port address.
    pub fn connection_for_address(&mut self, addr: String) -> Option<&mut (StreamType, BytesMut)> {
        self.address_to_conn.get_mut(&addr)
    }

    pub fn set_slot_address(&mut self, slot: u16, addr: String) {
        self.slot_to_address.insert(slot, addr);
    }
}

#[async_trait]
pub trait Connection {
    async fn send_recv(&mut self, buffer: &BytesMut) -> Result<ValkeyObject, CommonError>;

    /// Send request and read N responses. Useful when the request is a pipeline of requests.
    async fn send_recv_multi(
        &mut self,
        buffer: &BytesMut,
        count: usize,
    ) -> Result<Vec<ValkeyObject>, CommonError>;
}

#[async_trait]
impl Connection for ValkeyClient {
    /// Send request and read exactly 1 response.
    async fn send_recv(&mut self, buffer: &BytesMut) -> Result<ValkeyObject, CommonError> {
        StreamHelper::write_buffer(&mut self.stream, buffer).await?;
        Ok(StreamHelper::read_response(&mut self.stream, &mut self.read_buffer).await?)
    }

    /// Send request and read N responses. Useful when the request is a pipeline of requests.
    async fn send_recv_multi(
        &mut self,
        buffer: &BytesMut,
        count: usize,
    ) -> Result<Vec<ValkeyObject>, CommonError> {
        StreamHelper::write_buffer(&mut self.stream, buffer).await?;
        let mut objects = Vec::<ValkeyObject>::with_capacity(count);
        for _ in 0..count {
            objects
                .push(StreamHelper::read_response(&mut self.stream, &mut self.read_buffer).await?);
        }
        Ok(objects)
    }
}

#[async_trait]
impl Connection for ValkeyCluster {
    /// Send request and read exactly 1 response.
    async fn send_recv(&mut self, buffer: &BytesMut) -> Result<ValkeyObject, CommonError> {
        let (stream, read_buffer) = if let Some(slot) = slot_from_buffer(buffer)? {
            if let Some(conn) = self.connection_for_slot(slot).await? {
                conn
            } else {
                &mut self.discovery_conn
            }
        } else {
            &mut self.discovery_conn
        };
        StreamHelper::write_buffer(stream, buffer).await?;
        let response = StreamHelper::read_response(stream, read_buffer).await?;
        let response = match response {
            ValkeyObject::Error(msg) => {
                let s = String::from_utf8_lossy(&msg);
                if s.starts_with("MOVED") {
                    // Parse the correct address for the slot and replace the connection
                    let (slot, host, port) = parse_moved(s.as_ref()).ok_or(
                        CommonError::InvalidArgument(format!("MOVED error wrong format. {s}")),
                    )?;
                    // Register the slot for this address
                    let addr = format!("{}:{}", host, port);
                    self.set_slot_address(slot, addr.clone());

                    // Fetch or create the connection for the address and use it
                    let (stream, read_buffer) = self.connection_for_address(addr.clone()).ok_or(
                        CommonError::OtherError(format!("Could not find connection to: {addr}")),
                    )?;
                    StreamHelper::write_buffer(stream, buffer).await?;
                    StreamHelper::read_response(stream, read_buffer).await?
                } else {
                    ValkeyObject::Error(msg)
                }
            }
            response => response,
        };
        Ok(response)
    }

    /// Send request and read N responses. Useful when the request is a pipeline of requests.
    async fn send_recv_multi(
        &mut self,
        buffer: &BytesMut,
        count: usize,
    ) -> Result<Vec<ValkeyObject>, CommonError> {
        if count != 1 {
            return Err(CommonError::InvalidArgument(
                "In cluster connection, count must be 1".into(),
            ));
        }
        let obj = self.send_recv(buffer).await?;
        Ok(vec![obj])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case("MOVED 16308 127.0.0.10:7002", Some((16308, "127.0.0.10".to_string(), 7002)); "MOVED 16308 127.0.0.10:7002")]
    #[test_case("MOVED 16308 localhost:7002", Some((16308, "localhost".to_string(), 7002)); "MOVED 16308 localhost:7002")]
    #[test_case("16308 127.0.0.10:7002", None; "16308 127.0.0.10:7002")]
    #[test_case("16308 127.0.0.10:7002", None; "MOVED 16308 127.0.0.10:abc")]
    #[test_case("16308 127.0.0.10:7002", None; "MOVED 16308 127.0.0.10 1234")]
    fn test_parse_moved(msg: &str, result: Option<(u16, String, u16)>) {
        assert_eq!(parse_moved(msg), result);
    }

    #[test_case("07c37dfeb235213a872192d90877d0cd55635b91 127.0.0.1:30004@31004,hostname4 slave", Some(("127.0.0.1".to_string(), 30004)); "test_1")]
    fn test_parse_cluster_nodes_line(line: &str, result: Option<(String, u16)>) {
        assert_eq!(parse_cluster_nodes_line(line), result);
    }
}
