//! Sim-to-real transfer metrics: the numbers that decide whether a simulator
//! backend is evidence or decoration.
//!
//! Two metrics, both pinned to a [`SimManifest`](super::SimManifest) digest:
//! - [`spearman_rank_correlation`]: do policies that rank well in sim rank
//!   well in reality (per-policy success vectors, average-rank ties)?
//! - [`replay_error`]: open-loop replay of logged actions in sim — how far
//!   does the simulated trajectory drift (ATE RMSE + max error)?
//!
//! [`TransferReport::is_comparable`] refuses to compare runs evaluated under
//! different manifests: a number without its digest is not a measurement.

use anyhow::Result;

/// Spearman rank correlation in [-1, 1] with average-rank ties.
///
/// `sim[i]` / `real[i]` are per-policy success scores. Errors (never silent
/// `0.0`) when `n < 3` or either side has zero variance — a constant series
/// carries no ranking information.
pub fn spearman_rank_correlation(sim: &[f64], real: &[f64]) -> Result<f64> {
    if sim.len() != real.len() {
        anyhow::bail!("sim and real series must pair up");
    }
    if sim.len() < 3 {
        anyhow::bail!("need at least 3 paired samples, got {}", sim.len());
    }
    let ranks = |xs: &[f64]| -> Vec<f64> {
        let mut order: Vec<usize> = (0..xs.len()).collect();
        order.sort_by(|&a, &b| xs[a].partial_cmp(&xs[b]).unwrap_or(std::cmp::Ordering::Equal));
        let mut ranks = vec![0.0; xs.len()];
        let mut i = 0;
        while i < order.len() {
            let mut j = i;
            while j + 1 < order.len() && xs[order[j + 1]] == xs[order[i]] {
                j += 1;
            }
            // Average rank over the tied run (1-based ranks).
            let avg = (i + 1 + j + 1) as f64 / 2.0;
            for k in i..=j {
                ranks[order[k]] = avg;
            }
            i = j + 1;
        }
        ranks
    };
    let rs = ranks(sim);
    let rr = ranks(real);
    let n = rs.len() as f64;
    let mean = |v: &[f64]| v.iter().sum::<f64>() / n;
    let (ms, mr) = (mean(&rs), mean(&rr));
    let (mut num, mut ds, mut dr) = (0.0, 0.0, 0.0);
    for i in 0..rs.len() {
        num += (rs[i] - ms) * (rr[i] - mr);
        ds += (rs[i] - ms).powi(2);
        dr += (rr[i] - mr).powi(2);
    }
    if ds == 0.0 || dr == 0.0 {
        anyhow::bail!("zero variance: ranking is undefined");
    }
    Ok(num / (ds.sqrt() * dr.sqrt()))
}

/// Open-loop replay divergence between two equal-length trajectories.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplayError {
    /// Root-mean-square Euclidean distance per paired step.
    pub ate_rmse: f64,
    /// Worst single-step Euclidean distance.
    pub max_err: f64,
    pub n: usize,
}

/// Pairwise Euclidean drift between simulated and real trajectories.
/// The trajectories must use the same state dimension; pairing is by index.
pub fn replay_error(sim_traj: &[[f64; 3]], real_traj: &[[f64; 3]]) -> Result<ReplayError> {
    if sim_traj.len() != real_traj.len() {
        anyhow::bail!("trajectories must pair up step-by-step");
    }
    if sim_traj.is_empty() {
        anyhow::bail!("need at least one paired step");
    }
    let mut sum_sq = 0.0;
    let mut max_err: f64 = 0.0;
    for (s, r) in sim_traj.iter().zip(real_traj.iter()) {
        let d = ((s[0] - r[0]).powi(2) + (s[1] - r[1]).powi(2) + (s[2] - r[2]).powi(2)).sqrt();
        sum_sq += d.powi(2);
        max_err = max_err.max(d);
    }
    Ok(ReplayError {
        ate_rmse: (sum_sq / sim_traj.len() as f64).sqrt(),
        max_err,
        n: sim_traj.len(),
    })
}

/// One transfer evaluation, pinned to the manifests that produced it.
#[derive(Debug, Clone)]
pub struct TransferReport {
    pub srcc: f64,
    pub ate_rmse: f64,
    pub n: usize,
    pub sim_digest: String,
    pub real_digest: String,
}

impl TransferReport {
    /// Comparable only under equal digests: different simulator properties
    /// (or different real conditions) make the numbers incommensurable.
    pub fn is_comparable(&self, other: &TransferReport) -> bool {
        self.sim_digest == other.sim_digest && self.real_digest == other.real_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_series_correlate_perfectly() {
        let s = vec![0.1, 0.4, 0.9, 0.7, 0.2];
        assert!((spearman_rank_correlation(&s, &s).unwrap() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn reversed_series_anticorrelate() {
        let sim = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let real = vec![5.0, 4.0, 3.0, 2.0, 1.0];
        assert!((spearman_rank_correlation(&sim, &real).unwrap() + 1.0).abs() < 1e-12);
    }

    #[test]
    fn ties_resolve_to_mid_ranks() {
        // sim ranks: 1.0→1, 2.0→(2+3)/2=2.5, 2.0→2.5, 3.0→4.
        let sim = vec![1.0, 2.0, 2.0, 3.0];
        let real = vec![1.0, 2.0, 3.0, 4.0];
        let rho = spearman_rank_correlation(&sim, &real).unwrap();
        assert!(rho > 0.9 && rho <= 1.0, "got {rho}");
    }

    #[test]
    fn constant_series_errors_instead_of_zero() {
        assert!(spearman_rank_correlation(&[1.0, 1.0, 1.0], &[1.0, 2.0, 3.0]).is_err());
        assert!(spearman_rank_correlation(&[1.0, 2.0], &[1.0, 2.0]).is_err());
        assert!(spearman_rank_correlation(&[1.0, 2.0, 3.0], &[1.0, 2.0]).is_err());
    }

    #[test]
    fn replay_identical_is_zero() {
        let t = vec![[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]];
        let e = replay_error(&t, &t).unwrap();
        assert_eq!(e.ate_rmse, 0.0);
        assert_eq!(e.max_err, 0.0);
        assert_eq!(e.n, 2);
    }

    #[test]
    fn replay_measures_drift() {
        let sim = vec![[0.0, 0.0, 0.0], [1.0, 0.0, 0.0]];
        let real = vec![[0.0, 0.0, 0.0], [2.0, 0.0, 0.0]];
        let e = replay_error(&sim, &real).unwrap();
        assert!((e.ate_rmse - (0.5f64).sqrt()).abs() < 1e-12);
        assert_eq!(e.max_err, 1.0);
    }

    #[test]
    fn comparability_requires_equal_digests() {
        let mk = |s: &str, r: &str| TransferReport {
            srcc: 1.0,
            ate_rmse: 0.0,
            n: 3,
            sim_digest: s.to_string(),
            real_digest: r.to_string(),
        };
        assert!(mk("a", "b").is_comparable(&mk("a", "b")));
        assert!(!mk("a", "b").is_comparable(&mk("aX", "b")));
        assert!(!mk("a", "b").is_comparable(&mk("a", "bX")));
    }
}
