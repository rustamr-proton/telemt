use super::*;

impl UserIpTracker {
    /// Queues a deferred active IP cleanup for a later async drain.
    pub fn enqueue_cleanup(&self, user: String, ip: IpAddr) {
        self.observe_cleanup_poison_for_tests();
        let shard_idx = Self::shard_idx(&user);
        let cleanup_shard = &self.cleanup_shards[shard_idx];
        match cleanup_shard.queue.lock() {
            Ok(mut queue) => {
                let user_queue = queue.entry(user).or_default();
                let count = user_queue.entry(ip).or_insert(0);
                if *count == 0 {
                    self.cleanup_queue_len.fetch_add(1, Ordering::Relaxed);
                }
                *count = count.saturating_add(1);
                self.cleanup_deferred_releases
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(poisoned) => {
                let mut queue = poisoned.into_inner();
                let user_queue = queue.entry(user.clone()).or_default();
                let count = user_queue.entry(ip).or_insert(0);
                if *count == 0 {
                    self.cleanup_queue_len.fetch_add(1, Ordering::Relaxed);
                }
                *count = count.saturating_add(1);
                self.cleanup_deferred_releases
                    .fetch_add(1, Ordering::Relaxed);
                cleanup_shard.queue.clear_poison();
                tracing::warn!(
                    "UserIpTracker cleanup_queue lock poisoned; recovered and enqueued IP cleanup for {} ({})",
                    user,
                    ip
                );
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn cleanup_queue_len_for_tests(&self) -> usize {
        self.cleanup_queue_len.load(Ordering::Relaxed) as usize
    }

    #[cfg(test)]
    pub(crate) fn cleanup_queue_mutex_for_tests(
        &self,
    ) -> Arc<Mutex<HashMap<(String, IpAddr), usize>>> {
        Arc::clone(&self.cleanup_queue_poison_probe)
    }

    pub(crate) async fn drain_cleanup_queue(&self) {
        if self.cleanup_queue_len.load(Ordering::Relaxed) == 0 {
            return;
        }
        for shard_idx in 0..USER_IP_TRACKER_SHARDS {
            self.drain_cleanup_shard(shard_idx).await;
        }
    }

    pub(super) async fn drain_cleanup_for_user(&self, user: &str) {
        if self.cleanup_queue_len.load(Ordering::Relaxed) == 0 {
            return;
        }
        let shard_idx = Self::shard_idx(user);
        let cleanup_shard = &self.cleanup_shards[shard_idx];
        let to_remove = match cleanup_shard.queue.lock() {
            Ok(mut queue) => queue.remove(user).unwrap_or_default(),
            Err(poisoned) => {
                let mut queue = poisoned.into_inner();
                let drained = queue.remove(user).unwrap_or_default();
                cleanup_shard.queue.clear_poison();
                drained
            }
        };
        if to_remove.is_empty() {
            return;
        }
        self.cleanup_queue_len
            .fetch_sub(to_remove.len() as u64, Ordering::Relaxed);
        let mut shard = self.shards[shard_idx].write().await;
        let mut removed_active_entries = 0usize;
        for (ip, pending_count) in to_remove {
            removed_active_entries = removed_active_entries.saturating_add(
                Self::apply_active_cleanup(&mut shard.active_ips, user, ip, pending_count),
            );
        }
        Self::decrement_counter(&self.active_entry_count, removed_active_entries);
    }

    pub(super) async fn drain_cleanup_shard(&self, shard_idx: usize) {
        let Ok(_drain_guard) = self.cleanup_drain_locks[shard_idx].try_lock() else {
            return;
        };

        let cleanup_shard = &self.cleanup_shards[shard_idx];
        let to_remove = {
            match cleanup_shard.queue.lock() {
                Ok(mut queue) => {
                    if queue.is_empty() {
                        return;
                    }
                    let mut drained =
                        HashMap::with_capacity(queue.len().min(CLEANUP_DRAIN_BATCH_LIMIT));
                    for _ in 0..CLEANUP_DRAIN_BATCH_LIMIT {
                        let Some((user, ip, count)) = Self::pop_one_cleanup(&mut queue) else {
                            break;
                        };
                        self.cleanup_queue_len.fetch_sub(1, Ordering::Relaxed);
                        drained.insert((user, ip), count);
                    }
                    drained
                }
                Err(poisoned) => {
                    let mut queue = poisoned.into_inner();
                    if queue.is_empty() {
                        cleanup_shard.queue.clear_poison();
                        return;
                    }
                    let mut drained =
                        HashMap::with_capacity(queue.len().min(CLEANUP_DRAIN_BATCH_LIMIT));
                    for _ in 0..CLEANUP_DRAIN_BATCH_LIMIT {
                        let Some((user, ip, count)) = Self::pop_one_cleanup(&mut queue) else {
                            break;
                        };
                        self.cleanup_queue_len.fetch_sub(1, Ordering::Relaxed);
                        drained.insert((user, ip), count);
                    }
                    cleanup_shard.queue.clear_poison();
                    drained
                }
            }
        };
        drop(_drain_guard);
        if to_remove.is_empty() {
            return;
        }

        let mut shard = self.shards[shard_idx].write().await;
        let mut removed_active_entries = 0usize;
        for ((user, ip), pending_count) in to_remove {
            removed_active_entries = removed_active_entries.saturating_add(
                Self::apply_active_cleanup(&mut shard.active_ips, &user, ip, pending_count),
            );
        }
        Self::decrement_counter(&self.active_entry_count, removed_active_entries);
    }
}
