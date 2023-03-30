mod util;
mod cache;
pub(crate) mod native_certs;
pub mod client;
pub mod server;
pub mod quic;

#[cfg(test)]
mod tests {
    use tls_wrap_common::ClientBuilder;
    use crate::client;

    #[tokio::test]
    async fn test_client() {
        let mut builder = client::TlsClientBuilder::new("www.amazon.com".into());
        builder.set_load_system_ca(true);
        let client = builder.build().unwrap();
        let mut stream = tokio::net::TcpStream::connect("1.1.1.1:443").await.unwrap();
        let res = client.connect(stream).await.unwrap();
        println!("{:?}", res.alpn_protocol());
    }
}