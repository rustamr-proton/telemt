use crate::proxy::traffic_limiter::{RateDirection, TrafficLease, next_refill_delay};
use crate::stats::{Stats, UserStats};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};
use tracing::trace;

mod combined;
mod counters;
mod quota;

pub(super) use self::combined::CombinedStream;
pub(super) use self::counters::SharedCounters;
pub(super) use self::quota::is_quota_io_error;
use self::quota::{
    QUOTA_RESERVE_MAX_ROUNDS, QUOTA_RESERVE_SPIN_RETRIES, quota_io_error,
    refund_reserved_quota_bytes,
};
pub(super) use self::quota::{quota_adaptive_interval_bytes, should_immediate_quota_check};

/// Transparent I/O wrapper that tracks per-user statistics and activity.
///
/// Wraps the **client** side of the relay. Direction mapping:
///
/// | poll method  | direction | stats updated                        |
/// |-------------|-----------|--------------------------------------|
/// | `poll_read`  | C→S       | `octets_from`, `msgs_from`, counters |
/// | `poll_write` | S→C       | `octets_to`, `msgs_to`, counters     |
///
/// Both update the shared activity timestamp for the watchdog.
///
/// Note on message counts: the original code counted one `read()`/`write_all()`
/// as one "message". Here we count `poll_read`/`poll_write` completions instead.
/// Byte counts are identical; op counts may differ slightly due to different
/// internal buffering in `copy_bidirectional`. This is fine for monitoring.
pub(super) struct StatsIo<S> {
    inner: S,
    counters: Arc<SharedCounters>,
    stats: Arc<Stats>,
    user: String,
    user_stats: Arc<UserStats>,
    traffic_lease: Option<Arc<TrafficLease>>,
    c2s_rate_debt_bytes: u64,
    c2s_wait: RateWaitState,
    s2c_wait: RateWaitState,
    quota_wait: RateWaitState,
    quota_limit: Option<u64>,
    quota_exceeded: Arc<AtomicBool>,
    pub(super) quota_bytes_since_check: u64,
    epoch: Instant,
}

#[derive(Default)]
struct RateWaitState {
    sleep: Option<Pin<Box<Sleep>>>,
    started_at: Option<Instant>,
    blocked_user: bool,
    blocked_cidr: bool,
}

impl<S> StatsIo<S> {
    /// Creates a StatsIo wrapper without a traffic lease for relay unit tests.
    #[cfg(test)]
    pub(super) fn new(
        inner: S,
        counters: Arc<SharedCounters>,
        stats: Arc<Stats>,
        user: String,
        quota_limit: Option<u64>,
        quota_exceeded: Arc<AtomicBool>,
        epoch: Instant,
    ) -> Self {
        Self::new_with_traffic_lease(
            inner,
            counters,
            stats,
            user,
            None,
            quota_limit,
            quota_exceeded,
            epoch,
        )
    }

    pub(super) fn new_with_traffic_lease(
        inner: S,
        counters: Arc<SharedCounters>,
        stats: Arc<Stats>,
        user: String,
        traffic_lease: Option<Arc<TrafficLease>>,
        quota_limit: Option<u64>,
        quota_exceeded: Arc<AtomicBool>,
        epoch: Instant,
    ) -> Self {
        // Mark initial activity so the watchdog doesn't fire before data flows
        counters.touch(Instant::now(), epoch);
        let user_stats = stats.get_or_create_user_stats_handle(&user);
        Self {
            inner,
            counters,
            stats,
            user,
            user_stats,
            traffic_lease,
            c2s_rate_debt_bytes: 0,
            c2s_wait: RateWaitState::default(),
            s2c_wait: RateWaitState::default(),
            quota_wait: RateWaitState::default(),
            quota_limit,
            quota_exceeded,
            quota_bytes_since_check: 0,
            epoch,
        }
    }

    fn record_wait(
        wait: &mut RateWaitState,
        lease: Option<&Arc<TrafficLease>>,
        direction: RateDirection,
    ) {
        let Some(started_at) = wait.started_at.take() else {
            return;
        };
        let wait_ms = started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        if let Some(lease) = lease {
            lease.observe_wait_ms(direction, wait.blocked_user, wait.blocked_cidr, wait_ms);
        }
        wait.blocked_user = false;
        wait.blocked_cidr = false;
    }

    fn arm_wait(wait: &mut RateWaitState, blocked_user: bool, blocked_cidr: bool) {
        if wait.sleep.is_none() {
            wait.sleep = Some(Box::pin(tokio::time::sleep(next_refill_delay())));
            wait.started_at = Some(Instant::now());
        }
        wait.blocked_user |= blocked_user;
        wait.blocked_cidr |= blocked_cidr;
    }

    fn poll_wait(
        wait: &mut RateWaitState,
        cx: &mut Context<'_>,
        lease: Option<&Arc<TrafficLease>>,
        direction: RateDirection,
    ) -> Poll<()> {
        let Some(sleep) = wait.sleep.as_mut() else {
            return Poll::Ready(());
        };
        if sleep.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        wait.sleep = None;
        Self::record_wait(wait, lease, direction);
        Poll::Ready(())
    }

    fn settle_c2s_rate_debt(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(lease) = self.traffic_lease.as_ref() else {
            self.c2s_rate_debt_bytes = 0;
            return Poll::Ready(());
        };

        while self.c2s_rate_debt_bytes > 0 {
            let consume = lease.try_consume(RateDirection::Up, self.c2s_rate_debt_bytes);
            if consume.granted > 0 {
                self.c2s_rate_debt_bytes = self.c2s_rate_debt_bytes.saturating_sub(consume.granted);
                continue;
            }
            Self::arm_wait(
                &mut self.c2s_wait,
                consume.blocked_user,
                consume.blocked_cidr,
            );
            if Self::poll_wait(&mut self.c2s_wait, cx, Some(lease), RateDirection::Up).is_pending()
            {
                return Poll::Pending;
            }
        }

        if Self::poll_wait(&mut self.c2s_wait, cx, Some(lease), RateDirection::Up).is_pending() {
            return Poll::Pending;
        }

        Poll::Ready(())
    }

    fn arm_quota_wait(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        Self::arm_wait(&mut self.quota_wait, false, false);
        Self::poll_wait(&mut self.quota_wait, cx, None, RateDirection::Up)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StatsIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.quota_exceeded.load(Ordering::Acquire) {
            return Poll::Ready(Err(quota_io_error()));
        }
        if this.settle_c2s_rate_debt(cx).is_pending() {
            return Poll::Pending;
        }
        if buf.remaining() == 0 {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        let mut remaining_before = None;
        let mut reserved_read_bytes = 0u64;
        let mut read_limit = buf.remaining();
        if let Some(limit) = this.quota_limit {
            let used_before = this.user_stats.quota_used();
            let remaining = limit.saturating_sub(used_before);
            if remaining == 0 {
                this.quota_exceeded.store(true, Ordering::Release);
                return Poll::Ready(Err(quota_io_error()));
            }
            remaining_before = Some(remaining);
            read_limit = read_limit.min(remaining as usize);
            if read_limit == 0 {
                this.quota_exceeded.store(true, Ordering::Release);
                return Poll::Ready(Err(quota_io_error()));
            }

            let desired = read_limit as u64;
            let mut reserve_rounds = 0usize;
            while reserved_read_bytes == 0 {
                for _ in 0..QUOTA_RESERVE_SPIN_RETRIES {
                    match this.user_stats.quota_try_reserve(desired, limit) {
                        Ok(_) => {
                            reserved_read_bytes = desired;
                            break;
                        }
                        Err(crate::stats::QuotaReserveError::LimitExceeded) => {
                            this.quota_exceeded.store(true, Ordering::Release);
                            return Poll::Ready(Err(quota_io_error()));
                        }
                        Err(crate::stats::QuotaReserveError::Contended) => {
                            this.stats.increment_quota_contention_total();
                        }
                    }
                }

                if reserved_read_bytes == 0 {
                    reserve_rounds = reserve_rounds.saturating_add(1);
                    if reserve_rounds >= QUOTA_RESERVE_MAX_ROUNDS {
                        this.stats.increment_quota_contention_timeout_total();
                        if this.arm_quota_wait(cx).is_pending() {
                            return Poll::Pending;
                        }
                        reserve_rounds = 0;
                    }
                }
            }
        }

        let limited_read = read_limit < buf.remaining();
        let read_result = if limited_read {
            let mut limited_buf = ReadBuf::new(buf.initialize_unfilled_to(read_limit));
            match Pin::new(&mut this.inner).poll_read(cx, &mut limited_buf) {
                Poll::Ready(Ok(())) => {
                    let n = limited_buf.filled().len();
                    buf.advance(n);
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            let before = buf.filled().len();
            match Pin::new(&mut this.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    let n = buf.filled().len() - before;
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        };

        match read_result {
            Poll::Ready(Ok(n)) => {
                if reserved_read_bytes > n as u64 {
                    let refund_bytes = reserved_read_bytes - n as u64;
                    refund_reserved_quota_bytes(this.user_stats.as_ref(), refund_bytes);
                    this.stats.add_quota_refund_bytes_total(refund_bytes);
                }
                if n > 0 {
                    let n_to_charge = n as u64;

                    if let Some(remaining) = remaining_before {
                        if should_immediate_quota_check(remaining, n_to_charge) {
                            this.quota_bytes_since_check = 0;
                        } else {
                            this.quota_bytes_since_check =
                                this.quota_bytes_since_check.saturating_add(n_to_charge);
                            let interval = quota_adaptive_interval_bytes(remaining);
                            if this.quota_bytes_since_check >= interval {
                                this.quota_bytes_since_check = 0;
                            }
                        }
                    }
                    if let Some(limit) = this.quota_limit
                        && this.user_stats.quota_used() >= limit
                    {
                        this.quota_exceeded.store(true, Ordering::Release);
                    }

                    // C→S: client sent data
                    this.counters
                        .c2s_bytes
                        .fetch_add(n_to_charge, Ordering::Relaxed);
                    this.counters.c2s_ops.fetch_add(1, Ordering::Relaxed);
                    this.counters.touch(Instant::now(), this.epoch);

                    this.stats
                        .add_user_traffic_from_handle(this.user_stats.as_ref(), n_to_charge);
                    if this.traffic_lease.is_some() {
                        this.c2s_rate_debt_bytes =
                            this.c2s_rate_debt_bytes.saturating_add(n_to_charge);
                        let _ = this.settle_c2s_rate_debt(cx);
                    }

                    trace!(user = %this.user, bytes = n, "C->S");
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                if reserved_read_bytes > 0 {
                    refund_reserved_quota_bytes(this.user_stats.as_ref(), reserved_read_bytes);
                    this.stats.add_quota_refund_bytes_total(reserved_read_bytes);
                }
                Poll::Pending
            }
            Poll::Ready(Err(err)) => {
                if reserved_read_bytes > 0 {
                    refund_reserved_quota_bytes(this.user_stats.as_ref(), reserved_read_bytes);
                    this.stats.add_quota_refund_bytes_total(reserved_read_bytes);
                }
                Poll::Ready(Err(err))
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StatsIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.quota_exceeded.load(Ordering::Acquire) {
            return Poll::Ready(Err(quota_io_error()));
        }

        let mut shaper_reserved_bytes = 0u64;
        let mut write_buf = buf;
        if let Some(lease) = this.traffic_lease.as_ref() {
            if !buf.is_empty() {
                loop {
                    let consume = lease.try_consume(RateDirection::Down, buf.len() as u64);
                    if consume.granted > 0 {
                        shaper_reserved_bytes = consume.granted;
                        if consume.granted < buf.len() as u64 {
                            write_buf = &buf[..consume.granted as usize];
                        }
                        let _ = Self::poll_wait(
                            &mut this.s2c_wait,
                            cx,
                            Some(lease),
                            RateDirection::Down,
                        );
                        break;
                    }

                    Self::arm_wait(
                        &mut this.s2c_wait,
                        consume.blocked_user,
                        consume.blocked_cidr,
                    );
                    if Self::poll_wait(&mut this.s2c_wait, cx, Some(lease), RateDirection::Down)
                        .is_pending()
                    {
                        return Poll::Pending;
                    }
                }
            } else {
                let _ = Self::poll_wait(&mut this.s2c_wait, cx, Some(lease), RateDirection::Down);
            }
        }

        let mut remaining_before = None;
        let mut reserved_bytes = 0u64;
        if let Some(limit) = this.quota_limit {
            if !write_buf.is_empty() {
                let mut reserve_rounds = 0usize;
                while reserved_bytes == 0 {
                    let used_before = this.user_stats.quota_used();
                    let remaining = limit.saturating_sub(used_before);
                    if remaining == 0 {
                        if let Some(lease) = this.traffic_lease.as_ref() {
                            lease.refund(RateDirection::Down, shaper_reserved_bytes);
                        }
                        this.quota_exceeded.store(true, Ordering::Release);
                        return Poll::Ready(Err(quota_io_error()));
                    }
                    remaining_before = Some(remaining);

                    let desired = remaining.min(write_buf.len() as u64);
                    let mut saw_contention = false;
                    for _ in 0..QUOTA_RESERVE_SPIN_RETRIES {
                        match this.user_stats.quota_try_reserve(desired, limit) {
                            Ok(_) => {
                                reserved_bytes = desired;
                                write_buf = &write_buf[..desired as usize];
                                break;
                            }
                            Err(crate::stats::QuotaReserveError::LimitExceeded) => {
                                break;
                            }
                            Err(crate::stats::QuotaReserveError::Contended) => {
                                this.stats.increment_quota_contention_total();
                                saw_contention = true;
                            }
                        }
                    }

                    if reserved_bytes == 0 {
                        reserve_rounds = reserve_rounds.saturating_add(1);
                        if reserve_rounds >= QUOTA_RESERVE_MAX_ROUNDS {
                            this.stats.increment_quota_contention_timeout_total();
                            if let Some(lease) = this.traffic_lease.as_ref() {
                                lease.refund(RateDirection::Down, shaper_reserved_bytes);
                            }
                            let _ = this.arm_quota_wait(cx);
                            return Poll::Pending;
                        } else if saw_contention {
                            std::hint::spin_loop();
                        }
                    }
                }
            } else {
                let used_before = this.user_stats.quota_used();
                let remaining = limit.saturating_sub(used_before);
                if remaining == 0 {
                    if let Some(lease) = this.traffic_lease.as_ref() {
                        lease.refund(RateDirection::Down, shaper_reserved_bytes);
                    }
                    this.quota_exceeded.store(true, Ordering::Release);
                    return Poll::Ready(Err(quota_io_error()));
                }
                remaining_before = Some(remaining);
            }
        }

        match Pin::new(&mut this.inner).poll_write(cx, write_buf) {
            Poll::Ready(Ok(n)) => {
                if reserved_bytes > n as u64 {
                    let refund_bytes = reserved_bytes - n as u64;
                    refund_reserved_quota_bytes(this.user_stats.as_ref(), refund_bytes);
                    this.stats.add_quota_refund_bytes_total(refund_bytes);
                }
                if shaper_reserved_bytes > n as u64
                    && let Some(lease) = this.traffic_lease.as_ref()
                {
                    lease.refund(RateDirection::Down, shaper_reserved_bytes - n as u64);
                }
                if n > 0 {
                    if let Some(lease) = this.traffic_lease.as_ref() {
                        Self::record_wait(&mut this.s2c_wait, Some(lease), RateDirection::Down);
                    }
                    let n_to_charge = n as u64;

                    // S→C: data written to client
                    this.counters
                        .s2c_bytes
                        .fetch_add(n_to_charge, Ordering::Relaxed);
                    this.counters.s2c_ops.fetch_add(1, Ordering::Relaxed);
                    this.counters.touch(Instant::now(), this.epoch);

                    this.stats
                        .add_user_traffic_to_handle(this.user_stats.as_ref(), n_to_charge);

                    if let (Some(limit), Some(remaining)) = (this.quota_limit, remaining_before) {
                        if should_immediate_quota_check(remaining, n_to_charge) {
                            this.quota_bytes_since_check = 0;
                            if this.user_stats.quota_used() >= limit {
                                this.quota_exceeded.store(true, Ordering::Release);
                            }
                        } else {
                            this.quota_bytes_since_check =
                                this.quota_bytes_since_check.saturating_add(n_to_charge);
                            let interval = quota_adaptive_interval_bytes(remaining);
                            if this.quota_bytes_since_check >= interval {
                                this.quota_bytes_since_check = 0;
                                if this.user_stats.quota_used() >= limit {
                                    this.quota_exceeded.store(true, Ordering::Release);
                                }
                            }
                        }
                    }

                    trace!(user = %this.user, bytes = n, "S->C");
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                if reserved_bytes > 0 {
                    refund_reserved_quota_bytes(this.user_stats.as_ref(), reserved_bytes);
                    this.stats.add_quota_refund_bytes_total(reserved_bytes);
                }
                if shaper_reserved_bytes > 0
                    && let Some(lease) = this.traffic_lease.as_ref()
                {
                    lease.refund(RateDirection::Down, shaper_reserved_bytes);
                }
                Poll::Ready(Err(err))
            }
            Poll::Pending => {
                if reserved_bytes > 0 {
                    refund_reserved_quota_bytes(this.user_stats.as_ref(), reserved_bytes);
                    this.stats.add_quota_refund_bytes_total(reserved_bytes);
                }
                if shaper_reserved_bytes > 0
                    && let Some(lease) = this.traffic_lease.as_ref()
                {
                    lease.refund(RateDirection::Down, shaper_reserved_bytes);
                }
                Poll::Pending
            }
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
