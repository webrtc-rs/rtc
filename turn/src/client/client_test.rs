use tokio::net::UdpSocket;

use super::*;
use crate::auth::*;

async fn create_listening_test_client(rto_in_ms: u16) -> Result<Client> {
    let conn = UdpSocket::bind("0.0.0.0:0").await?;

    let c = Client::new(ClientConfig {
        stun_serv_addr: String::new(),
        turn_serv_addr: String::new(),
        username: String::new(),
        password: String::new(),
        realm: String::new(),
        software: "TEST SOFTWARE".to_owned(),
        rto_in_ms,
        conn: Arc::new(conn),
        vnet: None,
    })
    .await?;

    c.listen().await?;

    Ok(c)
}

async fn create_listening_test_client_with_stun_serv() -> Result<Client> {
    let conn = UdpSocket::bind("0.0.0.0:0").await?;

    let c = Client::new(ClientConfig {
        stun_serv_addr: "stun1.l.google.com:19302".to_owned(),
        turn_serv_addr: String::new(),
        username: String::new(),
        password: String::new(),
        realm: String::new(),
        software: "TEST SOFTWARE".to_owned(),
        rto_in_ms: 0,
        conn: Arc::new(conn),
        vnet: None,
    })
    .await?;

    c.listen().await?;

    Ok(c)
}

#[tokio::test]
async fn test_client_with_stun_send_binding_request() -> Result<()> {
    //env_logger::init();

    let c = create_listening_test_client_with_stun_serv().await?;

    let resp = c.send_binding_request().await?;
    log::debug!("mapped-addr: {}", resp);
    {
        let ci = c.client_internal.lock().await;
        let tm = ci.tr_map.lock().await;
        assert_eq!(0, tm.size(), "should be no transaction left");
    }

    c.close().await?;

    Ok(())
}

#[tokio::test]
async fn test_client_with_stun_send_binding_request_to_parallel() -> Result<()> {
    env_logger::init();

    let c1 = create_listening_test_client(0).await?;
    let c2 = c1.clone();

    let (stared_tx, mut started_rx) = mpsc::channel::<()>(1);
    let (finished_tx, mut finished_rx) = mpsc::channel::<()>(1);

    let to = lookup_host(true, "stun1.l.google.com:19302").await?;

    tokio::spawn(async move {
        drop(stared_tx);
        if let Ok(resp) = c2.send_binding_request_to(&to.to_string()).await {
            log::debug!("mapped-addr: {}", resp);
        }
        drop(finished_tx);
    });

    let _ = started_rx.recv().await;

    let resp = c1.send_binding_request_to(&to.to_string()).await?;
    log::debug!("mapped-addr: {}", resp);

    let _ = finished_rx.recv().await;

    c1.close().await?;

    Ok(())
}

#[tokio::test]
async fn test_client_with_stun_send_binding_request_to_timeout() -> Result<()> {
    //env_logger::init();

    let c = create_listening_test_client(10).await?;

    let to = lookup_host(true, "127.0.0.1:9").await?;

    let result = c.send_binding_request_to(&to.to_string()).await;
    assert!(result.is_err(), "expected error, but got ok");

    c.close().await?;

    Ok(())
}

struct TestAuthHandler;
impl AuthHandler for TestAuthHandler {
    fn auth_handle(&self, username: &str, realm: &str, _src_addr: SocketAddr) -> Result<Vec<u8>> {
        Ok(generate_auth_key(username, realm, "pass"))
    }
}
