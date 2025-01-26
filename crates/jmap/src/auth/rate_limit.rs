/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use common::{
    ip_to_bytes,
    listener::limiter::{InFlight, LimiterResult},
    Server, KV_RATE_LIMIT_HTTP_ANONYMOUS, KV_RATE_LIMIT_HTTP_AUTHENTICATED,
};
use directory::Permission;
use trc::AddContext;

use common::auth::AccessToken;
use std::future::Future;

pub trait RateLimiter: Sync + Send {
    fn is_http_authenticated_request_allowed(
        &self,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<Option<InFlight>>> + Send;
    fn is_http_anonymous_request_allowed(
        &self,
        addr: &IpAddr,
    ) -> impl Future<Output = trc::Result<()>> + Send;
    fn is_upload_allowed(&self, access_token: &AccessToken) -> trc::Result<Option<InFlight>>;
}

impl RateLimiter for Server {
    async fn is_http_authenticated_request_allowed(
        &self,
        access_token: &AccessToken,
    ) -> trc::Result<Option<InFlight>> {
        let is_rate_allowed = if let Some(rate) = &self.core.jmap.rate_authenticated {
            self.core
                .storage
                .lookup
                .is_rate_allowed(
                    KV_RATE_LIMIT_HTTP_AUTHENTICATED,
                    &access_token.primary_id.to_be_bytes(),
                    rate,
                    false,
                )
                .await
                .caused_by(trc::location!())?
                .is_none()
        } else {
            true
        };

        if is_rate_allowed {
            match access_token.is_http_request_allowed() {
                LimiterResult::Allowed(in_flight) => Ok(Some(in_flight)),
                LimiterResult::Forbidden => {
                    if access_token.has_permission(Permission::UnlimitedRequests) {
                        Ok(None)
                    } else {
                        Err(trc::LimitEvent::ConcurrentRequest.into_err())
                    }
                }
                LimiterResult::Disabled => Ok(None),
            }
        } else if access_token.has_permission(Permission::UnlimitedRequests) {
            Ok(None)
        } else {
            Err(trc::LimitEvent::TooManyRequests.into_err())
        }
    }

    async fn is_http_anonymous_request_allowed(&self, addr: &IpAddr) -> trc::Result<()> {
        if let Some(rate) = &self.core.jmap.rate_anonymous {
            if !self.is_ip_allowed(addr)
                && self
                    .core
                    .storage
                    .lookup
                    .is_rate_allowed(
                        KV_RATE_LIMIT_HTTP_ANONYMOUS,
                        &ip_to_bytes(addr),
                        rate,
                        false,
                    )
                    .await
                    .caused_by(trc::location!())?
                    .is_some()
            {
                return Err(trc::LimitEvent::TooManyRequests.into_err());
            }
        }
        Ok(())
    }

    fn is_upload_allowed(&self, access_token: &AccessToken) -> trc::Result<Option<InFlight>> {
        match access_token.is_upload_allowed() {
            LimiterResult::Allowed(in_flight) => Ok(Some(in_flight)),
            LimiterResult::Forbidden => {
                if access_token.has_permission(Permission::UnlimitedRequests) {
                    Ok(None)
                } else {
                    Err(trc::LimitEvent::ConcurrentUpload.into_err())
                }
            }
            LimiterResult::Disabled => Ok(None),
        }
    }
}
