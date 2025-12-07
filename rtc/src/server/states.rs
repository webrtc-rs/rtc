use crate::configs::server_config::ServerConfig;
use crate::configs::session_config::SessionConfig;
use crate::description::RTCSessionDescription;
use crate::endpoint::{
    candidate::{Candidate, ConnectionCredentials},
    transport::Transport,
    Endpoint,
};
use crate::metrics::Metrics;
use crate::session::Session;
use crate::types::{EndpointId, FourTuple, SessionId, UserName};
use log::{debug, info};
use opentelemetry::metrics::Meter;
use shared::error::{Error, Result};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

/// ServerStates maintains SFU internal states, such sessions, endpoints, etc.
pub struct ServerStates {
    server_config: Arc<ServerConfig>,
    local_addr: SocketAddr,
    metrics: Metrics,

    sessions: HashMap<SessionId, Session>,
    endpoints: HashMap<FourTuple, (SessionId, EndpointId)>,
    candidates: HashMap<UserName, Rc<Candidate>>,
}

impl ServerStates {
    /// create new server states
    pub fn new(
        server_config: Arc<ServerConfig>,
        local_addr: SocketAddr,
        meter: Meter,
    ) -> Result<Self> {
        let _ = server_config
            .certificates
            .first()
            .ok_or(Error::ErrInvalidCertificate)?
            .get_fingerprints()
            .first()
            .ok_or(Error::ErrInvalidCertificate)?;

        Ok(Self {
            server_config,
            local_addr,
            metrics: Metrics::new(meter),
            sessions: HashMap::new(),
            endpoints: HashMap::new(),
            candidates: HashMap::new(),
        })
    }

    /// accept offer and return answer
    pub fn accept_offer(
        &mut self,
        session_id: SessionId,
        endpoint_id: EndpointId,
        four_tuple: Option<FourTuple>,
        mut offer: RTCSessionDescription,
    ) -> Result<RTCSessionDescription> {
        let parsed = offer.unmarshal()?;
        let remote_conn_cred = ConnectionCredentials::from_sdp(&parsed)?;
        offer.parsed = Some(parsed);

        let fingerprints = self
            .server_config
            .certificates
            .first()
            .unwrap()
            .get_fingerprints();

        let session = self.create_or_get_mut_session(session_id);
        let has_endpoint = session.has_endpoint(&endpoint_id);

        let local_conn_cred = if has_endpoint {
            session.set_remote_description(endpoint_id, &offer)?;

            let endpoint = session
                .get_endpoint(&endpoint_id)
                .ok_or(Error::Other(format!(
                    "can't find endpoint id {}",
                    endpoint_id
                )))?;
            let four_tuple = four_tuple.ok_or(Error::Other("missing FourTuple".to_string()))?;
            let transports = endpoint.get_transports();
            let transport = transports.get(&four_tuple).ok_or(Error::Other(format!(
                "can't find transport for endpoint id {} with {:?}",
                endpoint_id, four_tuple
            )))?;
            transport.candidate().local_connection_credentials().clone()
        } else {
            ConnectionCredentials::new(fingerprints, remote_conn_cred.dtls_params.role)
        };

        let answer = session.create_answer(endpoint_id, &offer, &local_conn_cred.ice_params)?;
        if has_endpoint {
            session.set_local_description(endpoint_id, &answer)?;
        } else {
            self.add_candidate(Rc::new(Candidate::new(
                session_id,
                endpoint_id,
                remote_conn_cred,
                local_conn_cred,
                offer,
                answer.clone(),
                Instant::now() + self.server_config.idle_timeout,
            )));
        }

        Ok(answer)
    }

    pub(crate) fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub(crate) fn accept_answer(
        &mut self,
        session_id: SessionId,
        endpoint_id: EndpointId,
        _four_tuple: FourTuple,
        mut answer: RTCSessionDescription,
    ) -> Result<()> {
        let parsed = answer.unmarshal()?;
        answer.parsed = Some(parsed);

        let session = self.create_or_get_mut_session(session_id);
        if session.has_endpoint(&endpoint_id) {
            session.set_remote_description(endpoint_id, &answer)?;
        };

        Ok(())
    }

    pub(crate) fn server_config(&self) -> &Arc<ServerConfig> {
        &self.server_config
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn create_or_get_mut_session(&mut self, session_id: SessionId) -> &mut Session {
        if let Entry::Vacant(e) = self.sessions.entry(session_id) {
            let session = Session::new(
                SessionConfig::new(Arc::clone(&self.server_config), self.local_addr),
                session_id,
            );
            e.insert(session);
        }

        self.sessions.get_mut(&session_id).unwrap()
    }

    pub(crate) fn get_mut_sessions(&mut self) -> &mut HashMap<SessionId, Session> {
        &mut self.sessions
    }

    pub(crate) fn get_sessions(&self) -> &HashMap<SessionId, Session> {
        &self.sessions
    }

    pub(crate) fn get_session(&self, session_id: &SessionId) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    pub(crate) fn get_mut_session(&mut self, session_id: &SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(session_id)
    }

    pub(crate) fn remove_session(&mut self, session_id: &SessionId) -> Option<Session> {
        self.sessions.remove(session_id)
    }

    pub(crate) fn add_candidate(&mut self, candidate: Rc<Candidate>) -> Option<Rc<Candidate>> {
        let username = candidate.username();
        self.candidates.insert(username, candidate)
    }

    pub(crate) fn remove_candidate(&mut self, username: &UserName) -> Option<Rc<Candidate>> {
        self.candidates.remove(username)
    }

    pub(crate) fn find_candidate(&self, username: &UserName) -> Option<&Rc<Candidate>> {
        self.candidates.get(username)
    }

    pub(crate) fn get_candidates(&self) -> &HashMap<UserName, Rc<Candidate>> {
        &self.candidates
    }

    pub(crate) fn get_endpoints(&self) -> &HashMap<FourTuple, (SessionId, EndpointId)> {
        &self.endpoints
    }

    pub(crate) fn add_endpoint(
        &mut self,
        four_tuple: FourTuple,
        session_id: SessionId,
        endpoint_id: EndpointId,
    ) {
        self.endpoints.insert(four_tuple, (session_id, endpoint_id));
        info!(
            "{}/{} is connected via {:?}",
            session_id, endpoint_id, four_tuple
        )
    }

    pub(crate) fn remove_endpoint(&mut self, four_tuple: &FourTuple) {
        self.endpoints.remove(four_tuple);
    }

    pub(crate) fn find_endpoint(&self, four_tuple: &FourTuple) -> Option<(SessionId, EndpointId)> {
        self.endpoints.get(four_tuple).cloned()
    }

    pub(crate) fn get_mut_endpoint(&mut self, four_tuple: &FourTuple) -> Result<&mut Endpoint> {
        let (session_id, endpoint_id) = self.find_endpoint(four_tuple).ok_or(Error::Other(
            format!("can't find endpoint with four_tuple {:?}", four_tuple),
        ))?;

        let session = self
            .get_mut_session(&session_id)
            .ok_or(Error::Other(format!(
                "can't find session id {:?}",
                session_id
            )))?;
        let endpoint = session
            .get_mut_endpoint(&endpoint_id)
            .ok_or(Error::Other(format!(
                "can't find endpoint id {:?}",
                endpoint_id
            )))?;

        Ok(endpoint)
    }

    pub(crate) fn get_mut_transport(&mut self, four_tuple: &FourTuple) -> Result<&mut Transport> {
        let (session_id, endpoint_id) = self.find_endpoint(four_tuple).ok_or(Error::Other(
            format!("can't find endpoint with four_tuple {:?}", four_tuple),
        ))?;

        let session = self
            .get_mut_session(&session_id)
            .ok_or(Error::Other(format!(
                "can't find session id {:?}",
                session_id
            )))?;
        let endpoint = session
            .get_mut_endpoint(&endpoint_id)
            .ok_or(Error::Other(format!(
                "can't find endpoint id {:?}",
                endpoint_id
            )))?;
        let transports = endpoint.get_mut_transports();
        let transport = transports.get_mut(four_tuple).ok_or(Error::Other(format!(
            "can't find transport with four_tuple {:?} for endpoint id {}",
            four_tuple, endpoint_id,
        )))?;

        Ok(transport)
    }

    pub(crate) fn remove_transport(&mut self, four_tuple: FourTuple) {
        debug!("remove idle transport {:?}", four_tuple);

        let Some((session_id, endpoint_id)) = self.find_endpoint(&four_tuple) else {
            return;
        };
        let Some(session) = self.get_mut_session(&session_id) else {
            return;
        };
        let Some(endpoint) = session.get_mut_endpoint(&endpoint_id) else {
            return;
        };

        let transport = endpoint.remove_transport(&four_tuple);
        if endpoint.get_transports().is_empty() {
            session.remove_endpoint(&endpoint_id);
            if session.get_endpoints().is_empty() {
                self.remove_session(&session_id);
            }
            self.remove_endpoint(&four_tuple);
        }
        if let Some(transport) = transport {
            self.remove_candidate(&transport.candidate().username());
        }
    }
}
