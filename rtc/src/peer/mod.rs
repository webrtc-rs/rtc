use crate::peer::configuration::RTCConfiguration;
use log::{trace, warn};
use shared::error::{Error, Result};

pub mod certificate;
pub mod configuration;
pub mod state;

pub struct RTCPeerConnection {
    config: RTCConfiguration,
    /*readonly attribute RTCSessionDescription? localDescription;
    readonly attribute RTCSessionDescription? currentLocalDescription;
    readonly attribute RTCSessionDescription? pendingLocalDescription;
    readonly attribute RTCSessionDescription? remoteDescription;
    readonly attribute RTCSessionDescription? currentRemoteDescription;
    readonly attribute RTCSessionDescription? pendingRemoteDescription;
    readonly attribute RTCSignalingState signalingState;
    readonly attribute RTCIceGatheringState iceGatheringState;
    readonly attribute RTCIceConnectionState iceConnectionState;
    readonly attribute RTCPeerConnectionState connectionState;
    readonly attribute boolean? canTrickleIceCandidates;

    attribute EventHandler onnegotiationneeded;
    attribute EventHandler onicecandidate;
    attribute EventHandler onicecandidateerror;
    attribute EventHandler onsignalingstatechange;
    attribute EventHandler oniceconnectionstatechange;
    attribute EventHandler onicegatheringstatechange;
    attribute EventHandler onconnectionstatechange;*/
}

impl RTCPeerConnection {
    fn new(config: RTCConfiguration) -> Result<Self> {
        trace!("Creating PeerConnection");

        /*TODO: if (config.certificatePemFile && config.keyPemFile) {
            std::promise<certificate_ptr> cert;
            cert.set_value(std::make_shared<Certificate>(
                config.certificatePemFile->find(PemBeginCertificateTag) != string::npos
                    ? Certificate::FromString(*config.certificatePemFile, *config.keyPemFile)
                    : Certificate::FromFile(*config.certificatePemFile, *config.keyPemFile,
                                            config.keyPemPass.value_or(""))));
            mCertificate = cert.get_future();
        } else if (!config.certificatePemFile && !config.keyPemFile) {
            mCertificate = make_certificate(config.certificateType);
        } else {
            throw std::invalid_argument(
                "Either none or both certificate and key PEM files must be specified");
        }*/

        if config.port_range_end > 0 && config.port_range_begin > config.port_range_end {
            return Err(Error::Other("Invalid port range".to_string()));
        }

        if let Some(mtu) = &config.mtu {
            if *mtu < 576 {
                // Min MTU for IPv4
                return Err(Error::Other("Invalid MTU value".to_string()));
            }

            if *mtu > 1500 {
                // Standard Ethernet
                warn!("MTU set to {}", *mtu);
            } else {
                trace!("MTU set to {}", *mtu);
            }
        }
        Ok(Self { config })
    }
    /*
     Promise<RTCSessionDescriptionInit> createOffer(optional RTCOfferOptions options = {});
     Promise<RTCSessionDescriptionInit> createAnswer(optional RTCAnswerOptions options = {});
     Promise<undefined> setLocalDescription(optional RTCLocalSessionDescriptionInit description = {});

     Promise<undefined> setRemoteDescription(RTCSessionDescriptionInit description);

     Promise<undefined> addIceCandidate(optional RTCIceCandidateInit candidate = {});

     undefined restartIce();
     RTCConfiguration getConfiguration();
     undefined setConfiguration(optional RTCConfiguration configuration = {});
     undefined close();


     // Legacy Interface Extensions
     // Supporting the methods in this section is optional.
     // If these methods are supported
     // they must be implemented as defined
     // in section "Legacy Interface Extensions"
     Promise<undefined> createOffer(RTCSessionDescriptionCallback successCallback,
                               RTCPeerConnectionErrorCallback failureCallback,
                               optional RTCOfferOptions options = {});
     Promise<undefined> setLocalDescription(RTCLocalSessionDescriptionInit description,
                                       VoidFunction successCallback,
                                       RTCPeerConnectionErrorCallback failureCallback);
     Promise<undefined> createAnswer(RTCSessionDescriptionCallback successCallback,
                                RTCPeerConnectionErrorCallback failureCallback);
     Promise<undefined> setRemoteDescription(RTCSessionDescriptionInit description,
                                        VoidFunction successCallback,
                                        RTCPeerConnectionErrorCallback failureCallback);
     Promise<undefined> addIceCandidate(RTCIceCandidateInit candidate,
                                   VoidFunction successCallback,
                                   RTCPeerConnectionErrorCallback failureCallback);

    */
}
