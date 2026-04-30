use anyhow::anyhow;
use ipnet::IpNet;
use regex::Regex;
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::path::Path;
use std::str::FromStr;
use std::vec;
use types::{MatchConfig, RestrictionsRules};

use crate::restrictions::types::{default_cidr, default_host};

pub mod auth;
pub mod config_reloader;
pub mod jwt;
pub mod types;

impl RestrictionsRules {
    pub fn from_config_file(config_path: &Path) -> anyhow::Result<Self> {
        let restrictions: Self = serde_yaml::from_reader(BufReader::new(File::open(config_path)?))?;
        Ok(restrictions)
    }

    /// Returns true if any restriction has at least one `MatchConfig::Jwt` matcher.
    pub fn has_jwt_matcher(&self) -> bool {
        self.restrictions
            .iter()
            .any(|r| r.r#match.iter().any(|m| matches!(m, MatchConfig::Jwt(_))))
    }

    /// Validates that every `MatchConfig::Jwt` matcher has non-empty allow-lists for each
    /// configured claim. An empty list would silently always reject -- almost certainly a
    /// config bug.
    pub fn validate_jwt_matchers(&self) -> anyhow::Result<()> {
        for restriction in &self.restrictions {
            for m in &restriction.r#match {
                if let MatchConfig::Jwt(cfg) = m {
                    for (claim, allowed) in &cfg.required_claims {
                        if allowed.is_empty() {
                            return Err(anyhow!(
                                "restriction \"{}\" Jwt matcher claim \"{}\" has an empty allowed-values list",
                                restriction.name,
                                claim
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Combined check that this rules config is consistent with the runtime JWT verifier.
    /// Used at startup (panic on Err) and at hot-reload (log + keep old rules on Err) so
    /// the two paths apply identical checks.
    pub fn validate_runtime_consistency(&self, jwt_verifier_present: bool) -> anyhow::Result<()> {
        self.validate_jwt_matchers()?;
        if self.has_jwt_matcher() && !jwt_verifier_present {
            return Err(anyhow!(
                "restrictions configure a Jwt matcher but no JWT verifier is available \
                 (server was started without --jwt-keys-redis-url)"
            ));
        }
        Ok(())
    }

    pub fn from_path_prefix(path_prefixes: &[String], restrict_to: &[(String, u16)]) -> anyhow::Result<Self> {
        let tunnels_restrictions = if restrict_to.is_empty() {
            let r = types::AllowConfig::Tunnel(types::AllowTunnelConfig {
                protocol: vec![],
                port: vec![],
                host: default_host(),
                cidr: default_cidr(),
            });
            let reverse_tunnel = types::AllowConfig::ReverseTunnel(types::AllowReverseTunnelConfig {
                protocol: vec![],
                port: vec![],
                port_mapping: Default::default(),
                cidr: default_cidr(),
            });

            vec![r, reverse_tunnel]
        } else {
            restrict_to
                .iter()
                .map(|(host, port)| {
                    let tunnels = if let Ok(ip) = IpAddr::from_str(host) {
                        vec![types::AllowConfig::Tunnel(types::AllowTunnelConfig {
                            protocol: vec![],
                            port: vec![RangeInclusive::new(*port, *port)],
                            host: Regex::new("^$")?,
                            cidr: vec![IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 })?],
                        })]
                    } else {
                        vec![types::AllowConfig::Tunnel(types::AllowTunnelConfig {
                            protocol: vec![],
                            port: vec![RangeInclusive::new(*port, *port)],
                            host: Regex::new(&format!("^{}$", regex::escape(host)))?,
                            cidr: vec![],
                        })]
                    };

                    Ok(tunnels)
                })
                .collect::<Result<Vec<_>, anyhow::Error>>()?
                .into_iter()
                .flatten()
                .collect()
        };

        let restrictions = if path_prefixes.is_empty() {
            // if no path prefixes are provided, we allow all
            let r = types::RestrictionConfig {
                name: "Allow All".to_string(),
                r#match: vec![types::MatchConfig::Any],
                allow: tunnels_restrictions,
            };
            vec![r]
        } else {
            path_prefixes
                .iter()
                .map(|path_prefix| {
                    let reg = Regex::new(&format!("^{}$", regex::escape(path_prefix)))?;
                    Ok(types::RestrictionConfig {
                        name: format!("Allow path prefix {}", path_prefix),
                        r#match: vec![types::MatchConfig::PathPrefix(reg)],
                        allow: tunnels_restrictions.clone(),
                    })
                })
                .collect::<Result<Vec<_>, anyhow::Error>>()?
        };

        Ok(Self { restrictions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restrictions::types::{AllowConfig, AllowTunnelConfig, JwtMatchConfig, MatchConfig, RestrictionConfig};
    use std::collections::HashMap;

    fn jwt_matcher_with_claim(name: &str, allowed: Vec<String>) -> RestrictionConfig {
        let mut required_claims = HashMap::new();
        required_claims.insert(name.to_string(), allowed);
        RestrictionConfig {
            name: "jwt-clients".to_string(),
            r#match: vec![MatchConfig::Jwt(JwtMatchConfig { required_claims })],
            allow: vec![AllowConfig::Tunnel(AllowTunnelConfig {
                protocol: vec![],
                port: vec![],
                cidr: default_cidr(),
                host: default_host(),
            })],
        }
    }

    #[test]
    fn validate_passes_for_non_jwt_config() {
        let rules = RestrictionsRules {
            restrictions: vec![RestrictionConfig {
                name: "any".into(),
                r#match: vec![MatchConfig::Any],
                allow: vec![],
            }],
        };
        assert!(!rules.has_jwt_matcher());
        rules.validate_jwt_matchers().expect("should pass");
    }

    #[test]
    fn validate_passes_with_non_empty_lists() {
        let rules = RestrictionsRules {
            restrictions: vec![jwt_matcher_with_claim("sub", vec!["alice".into()])],
        };
        assert!(rules.has_jwt_matcher());
        rules.validate_jwt_matchers().expect("should pass");
    }

    #[test]
    fn validate_rejects_empty_allow_list() {
        let rules = RestrictionsRules {
            restrictions: vec![jwt_matcher_with_claim("sub", vec![])],
        };
        let err = rules.validate_jwt_matchers().expect_err("must reject");
        assert_eq!(
            err.to_string(),
            "restriction \"jwt-clients\" Jwt matcher claim \"sub\" has an empty allowed-values list"
        );
    }

    #[test]
    fn runtime_consistency_passes_without_jwt_matcher() {
        let rules = RestrictionsRules {
            restrictions: vec![RestrictionConfig {
                name: "any".into(),
                r#match: vec![MatchConfig::Any],
                allow: vec![],
            }],
        };
        rules.validate_runtime_consistency(false).expect("ok without verifier");
        rules.validate_runtime_consistency(true).expect("ok with verifier");
    }

    #[test]
    fn runtime_consistency_passes_when_jwt_matcher_has_verifier() {
        let rules = RestrictionsRules {
            restrictions: vec![jwt_matcher_with_claim("sub", vec!["alice".into()])],
        };
        rules
            .validate_runtime_consistency(true)
            .expect("ok when verifier is present");
    }

    #[test]
    fn runtime_consistency_rejects_jwt_matcher_without_verifier() {
        let rules = RestrictionsRules {
            restrictions: vec![jwt_matcher_with_claim("sub", vec!["alice".into()])],
        };
        let err = rules.validate_runtime_consistency(false).expect_err("must reject");
        assert!(
            err.to_string().contains("no JWT verifier is available"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn runtime_consistency_rejects_empty_allow_list_through_helper() {
        let rules = RestrictionsRules {
            restrictions: vec![jwt_matcher_with_claim("sub", vec![])],
        };
        let err = rules.validate_runtime_consistency(true).expect_err("must reject");
        assert!(err.to_string().contains("empty allowed-values list"), "unexpected error: {err}");
    }

    /// A typo like `required_claim:` (missing trailing 's') would otherwise silently
    /// deserialize to an empty `required_claims` map, leaving the matcher accepting
    /// any valid JWT. `deny_unknown_fields` turns that into a load-time error.
    #[test]
    fn jwt_matcher_rejects_unknown_field() {
        const YAML: &str = r#"
restrictions:
  - name: jwt-clients
    match:
      - !Jwt
        required_claim:
          sub:
            - alice
    allow:
      - !Tunnel {}
"#;
        let err = serde_yaml::from_str::<RestrictionsRules>(YAML).expect_err("must reject");
        assert!(err.to_string().contains("required_claim"), "unexpected error: {err}");
    }
}
