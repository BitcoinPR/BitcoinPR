use serde::Serialize;
use tokio::sync::broadcast;

/// Notifications broadcast to all subscribers (web UI, mining gateway, Electrum, etc.)
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum NodeNotification {
    NewBlock {
        hash: String,
        height: u32,
    },
    NewTx {
        txid: String,
    },
    MempoolUpdate {
        size: usize,
        total_fees: u64,
    },
    MiningShare {
        worker: String,
        accepted: bool,
        hashrate: f64,
        difficulty: f64,
    },
    MiningStats {
        hashrate: f64,
        shares_accepted: u64,
        shares_rejected: u64,
        connected_workers: u32,
        best_share_difficulty: f64,
        blocks_found: u64,
        uptime_secs: u64,
    },
    DatumConnected {
        pool_name: String,
    },
    DatumDisconnected {
        reason: String,
    },
    DatumShareSubmitted {
        accepted: bool,
        difficulty: f64,
    },
    DatumPayout {
        txid: String,
        amount: u64,
    },
}

pub struct EventBus {
    sender: broadcast::Sender<NodeNotification>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        EventBus { sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NodeNotification> {
        self.sender.subscribe()
    }

    pub fn publish(&self, event: NodeNotification) {
        let _ = self.sender.send(event);
    }

    pub fn sender(&self) -> broadcast::Sender<NodeNotification> {
        self.sender.clone()
    }
}
