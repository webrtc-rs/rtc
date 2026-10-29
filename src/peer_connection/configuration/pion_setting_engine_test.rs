//! pion/webrtc v4.2.24 `settingengine_test.go`.

use super::setting_engine::SettingEngineBuilder;
use ice::agent::agent_config::IpFilter;
use ice::network_type::NetworkType;

/// `TestSetICEUseCandidateCheckPriority` and the filter half of
/// `TestSettingEngine_CandidateFiltersAndNetworkTypes`.
#[test]
fn ice_options_are_stored() {
    assert!(
        !SettingEngineBuilder::new()
            .build()
            .candidates
            .ice_use_candidate_check_priority
    );
    let on = SettingEngineBuilder::new()
        .with_ice_use_candidate_check_priority(true)
        .build();
    assert!(on.candidates.ice_use_candidate_check_priority);
    let off = SettingEngineBuilder::new()
        .with_ice_use_candidate_check_priority(true)
        .with_ice_use_candidate_check_priority(false)
        .build();
    assert!(!off.candidates.ice_use_candidate_check_priority);

    let se = SettingEngineBuilder::new()
        .with_network_types(vec![NetworkType::Udp4, NetworkType::Udp6])
        .with_ip_filter(IpFilter::new(|ip| ip.is_loopback()))
        .with_remote_ip_filter(IpFilter::new(|ip| match ip {
            std::net::IpAddr::V4(v4) => v4.is_private(),
            std::net::IpAddr::V6(_) => false,
        }))
        .with_include_loopback_candidate(true)
        .build();
    assert_eq!(
        se.candidates.ice_network_types,
        vec![NetworkType::Udp4, NetworkType::Udp6]
    );
    assert!(se.candidates.ip_filter.is_some() && se.candidates.remote_ip_filter.is_some());
    assert!(se.candidates.include_loopback_candidate);
}
