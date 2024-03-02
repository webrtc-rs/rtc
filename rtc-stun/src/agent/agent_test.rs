use std::ops::Add;
use std::time::Duration;

use super::*;
use shared::error::*;

#[test]
fn test_agent_process_in_transaction() -> Result<()> {
    let mut m = Message::new();
    let mut a = Agent::new();
    m.transaction_id = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    a.start(m.transaction_id, Instant::now())?;
    a.process(m)?;
    a.close()?;

    while let Some(e) = a.poll_event() {
        assert!(e.result.is_ok(), "got error: {:?}", e.result);

        let tid = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(
            e.result.as_ref().unwrap().transaction_id,
            tid,
            "{:?} (got) != {:?} (expected)",
            e.result.as_ref().unwrap().transaction_id,
            tid
        );
    }

    Ok(())
}

#[test]
fn test_agent_process() -> Result<()> {
    let mut m = Message::new();
    let mut a = Agent::new();
    m.transaction_id = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    a.process(m.clone())?;
    a.close()?;

    while let Some(e) = a.poll_event() {
        assert!(e.result.is_ok(), "got error: {:?}", e.result);

        let tid = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(
            e.result.as_ref().unwrap().transaction_id,
            tid,
            "{:?} (got) != {:?} (expected)",
            e.result.as_ref().unwrap().transaction_id,
            tid
        );
    }

    let result = a.process(m);
    if let Err(err) = result {
        assert_eq!(
            err,
            Error::ErrAgentClosed,
            "closed agent should return <{}>, but got <{}>",
            Error::ErrAgentClosed,
            err,
        );
    } else {
        panic!("expected error, but got ok");
    }

    Ok(())
}

#[test]
fn test_agent_start() -> Result<()> {
    let mut a = Agent::new();
    let id = TransactionId::new();
    let deadline = Instant::now().add(Duration::from_secs(3600));
    a.start(id, deadline)?;

    let result = a.start(id, deadline);
    if let Err(err) = result {
        assert_eq!(
            err,
            Error::ErrTransactionExists,
            "duplicate start should return <{}>, got <{}>",
            Error::ErrTransactionExists,
            err,
        );
    } else {
        panic!("expected error, but got ok");
    }
    a.close()?;

    let id = TransactionId::new();
    let result = a.start(id, deadline);
    if let Err(err) = result {
        assert_eq!(
            err,
            Error::ErrAgentClosed,
            "start on closed agent should return <{}>, got <{}>",
            Error::ErrAgentClosed,
            err,
        );
    } else {
        panic!("expected error, but got ok");
    }

    Ok(())
}

#[test]
fn test_agent_stop() -> Result<()> {
    let mut a = Agent::new();

    let result = a.stop(TransactionId::default());
    if let Err(err) = result {
        assert_eq!(
            err,
            Error::ErrTransactionNotExists,
            "unexpected error: {}, should be {}",
            Error::ErrTransactionNotExists,
            err,
        );
    } else {
        panic!("expected error, but got ok");
    }

    let id = TransactionId::new();
    let deadline = Instant::now().add(Duration::from_millis(200));
    a.start(id, deadline)?;
    a.stop(id)?;

    if let Err(err) = a.poll_event().unwrap().result {
        assert_eq!(
            err,
            Error::ErrTransactionStopped,
            "unexpected error: {}, should be {}",
            err,
            Error::ErrTransactionStopped
        );
    } else {
        panic!("expected error, got ok");
    }

    a.close()?;

    let result = a.close();
    if let Err(err) = result {
        assert_eq!(
            err,
            Error::ErrAgentClosed,
            "a.Close returned {} instead of {}",
            Error::ErrAgentClosed,
            err,
        );
    } else {
        panic!("expected error, but got ok");
    }

    let result = a.stop(TransactionId::default());
    if let Err(err) = result {
        assert_eq!(
            err,
            Error::ErrAgentClosed,
            "unexpected error: {}, should be {}",
            Error::ErrAgentClosed,
            err,
        );
    } else {
        panic!("expected error, but got ok");
    }

    Ok(())
}
