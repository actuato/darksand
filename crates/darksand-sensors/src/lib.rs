//! Sensor & Actuator Tooling for Darksand Runtime
//!
//! Provides interfaces for interacting with hardware sensors and actuators
//! commonly used in robotics and edge AI applications.
//!
//! # Supported Hardware
//! - **GPIO:** Digital input/output via rppal (Raspberry Pi and compatible SBCs)
//! - **Camera:** Image capture via V4L2 or simulated input
//! - **LIDAR:** Point cloud data via serial or UDP
//! - **Actuators:** Motor control with safety whitelisting
//!
//! # Safety
//! All actuator operations are subject to whitelisting and permission checks
//! to prevent unintended hardware damage or safety violations.
//!
//! # Example
//! ```no_run
//! use darksand_sensors::{SensorManager, SensorConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = SensorConfig::default();
//!     let manager = SensorManager::new(config).await?;
//!
//!     // Read camera frame
//!     let frame = manager.read_camera().await?;
//!     println!("Captured frame: {} bytes", frame.data.len());
//!
//!     Ok(())
//! }
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Sensor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorConfig {
    /// Enable GPIO support
    pub enable_gpio: bool,

    /// Enable camera support
    pub enable_camera: bool,

    /// Enable LIDAR support
    pub enable_lidar: bool,

    /// Camera device path (e.g., /dev/video0)
    pub camera_device: String,

    /// Camera resolution (width x height)
    pub camera_width: u32,
    pub camera_height: u32,

    /// LIDAR connection type (serial, udp, tcp)
    pub lidar_connection: String,

    /// LIDAR device/address (e.g., /dev/ttyUSB0 or 192.168.1.100:8080)
    pub lidar_address: String,

    /// Whitelisted GPIO pins for output
    pub gpio_output_whitelist: Vec<u8>,

    /// Whitelisted actuator actions
    pub actuator_whitelist: HashSet<String>,

    /// Safety mode (if true, actuators require confirmation)
    pub safety_mode: bool,
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            enable_gpio: false,
            enable_camera: false,
            enable_lidar: false,
            camera_device: "/dev/video0".to_string(),
            camera_width: 640,
            camera_height: 480,
            lidar_connection: "serial".to_string(),
            lidar_address: "/dev/ttyUSB0".to_string(),
            gpio_output_whitelist: vec![],
            actuator_whitelist: HashSet::new(),
            safety_mode: true,
        }
    }
}

/// Where a sensor reading came from. Synthetic data must never be mistaken
/// for hardware truth downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataSource {
    Synthetic,
    Hardware,
}

/// Camera frame data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CameraFrame {
    pub timestamp: u64,
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub data: Vec<u8>,
    /// Always [`DataSource::Synthetic`] until a V4L2 backend exists.
    pub origin: DataSource,
}

impl CameraFrame {
    /// Encode frame as base64 for transmission
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::prelude::BASE64_STANDARD.encode(&self.data)
    }
}

/// LIDAR point cloud data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LidarScan {
    pub timestamp: u64,
    pub points: Vec<LidarPoint>,
    pub scan_rate_hz: f32,
    /// Always [`DataSource::Synthetic`] until a serial/UDP backend exists.
    pub origin: DataSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LidarPoint {
    pub angle_deg: f32,
    pub distance_m: f32,
    pub intensity: u8,
}

/// GPIO pin state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinState {
    Low = 0,
    High = 1,
}

/// Destination of an actuation command.
///
/// The contract is strict: success is only ever reported alongside an effect
/// (a recorded sim command or a hardware acknowledgement). A backend that
/// cannot act MUST return `Err` — a fabricated `Ok(())` is how robots drive
/// off tables in testing.
pub trait ActuatorBackend: Send + Sync {
    fn apply(&self, action: &str, params: &serde_json::Value) -> Result<ActuationRecord>;
    fn name(&self) -> &str;
}

/// Proof that a command reached a backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActuationRecord {
    pub backend: String,
    pub action: String,
    pub params: serde_json::Value,
    pub applied_at_ms: u64,
}

/// No hardware attached: every command fails honestly.
pub struct NoHardwareBackend;

impl ActuatorBackend for NoHardwareBackend {
    fn apply(&self, action: &str, _params: &serde_json::Value) -> Result<ActuationRecord> {
        Err(anyhow::anyhow!(
            "no actuator hardware attached: cannot execute '{action}'"
        ))
    }

    fn name(&self) -> &str {
        "no-hardware"
    }
}

/// In-memory backend for simulation and tests: records every command.
pub struct SimActuatorBackend {
    log: std::sync::Mutex<Vec<ActuationRecord>>,
}

impl SimActuatorBackend {
    pub fn new() -> Self {
        Self {
            log: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn commands(&self) -> Vec<ActuationRecord> {
        self.log.lock().unwrap().clone()
    }
}

impl Default for SimActuatorBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ActuatorBackend for SimActuatorBackend {
    fn apply(&self, action: &str, params: &serde_json::Value) -> Result<ActuationRecord> {
        let record = ActuationRecord {
            backend: self.name().to_string(),
            action: action.to_string(),
            params: params.clone(),
            applied_at_ms: now_ms(),
        };
        self.log.lock().unwrap().push(record.clone());
        Ok(record)
    }

    fn name(&self) -> &str {
        "sim"
    }
}

/// A prepared (not yet executed) actuation. Single-use: confirmation consumes
/// the token, and expired tokens are rejected, so replays fail closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingActuation {
    pub token: u64,
    pub action: String,
    pub params: serde_json::Value,
    pub expires_at_ms: u64,
}

/// Confirmation window for a prepared actuation.
pub const CONFIRM_TTL_MS: u64 = 60_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Contact phase for one force/torque sample. Contact-rich transfer fails
/// first on missing contact observability, so the phase travels with the
/// data even though no backend produces it yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContactPhase {
    NonContact,
    PreContact,
    Contact,
}

/// One force/torque sample with contact phase.
///
/// Schema-only today: every backend returns synthetic data or nothing, so
/// there is deliberately NO `read_force` on `SensorManager` yet — adding the
/// reader without a real sensor would fabricate contact data, the exact
/// failure this schema exists to prevent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForceSample {
    pub timestamp: u64,
    /// Newtons in the sensor frame.
    pub force_n: [f32; 3],
    /// Newton-meters in the sensor frame.
    pub torque_nm: [f32; 3],
    pub phase: ContactPhase,
}

/// Sensor Manager
pub struct SensorManager {
    config: SensorConfig,

    // GPIO state (pin number -> state)
    gpio_state: Arc<RwLock<std::collections::HashMap<u8, PinState>>>,

    // Camera state
    camera_active: Arc<RwLock<bool>>,

    // LIDAR state
    lidar_active: Arc<RwLock<bool>>,

    // Pending two-phase actuations (token -> request)
    pending: Arc<RwLock<std::collections::HashMap<u64, PendingActuation>>>,
    next_token: Arc<std::sync::atomic::AtomicU64>,

    // Where confirmed commands go. Defaults to [`NoHardwareBackend`]:
    // without hardware, actuation fails instead of pretending.
    backend: Arc<RwLock<Arc<dyn ActuatorBackend>>>,
}

impl SensorManager {
    /// Create a new sensor manager
    pub async fn new(config: SensorConfig) -> Result<Self> {
        info!("Initializing sensor manager");

        let manager = Self {
            config: config.clone(),
            gpio_state: Arc::new(RwLock::new(std::collections::HashMap::new())),
            camera_active: Arc::new(RwLock::new(false)),
            lidar_active: Arc::new(RwLock::new(false)),
            pending: Arc::new(RwLock::new(std::collections::HashMap::new())),
            next_token: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            backend: Arc::new(RwLock::new(Arc::new(NoHardwareBackend) as Arc<dyn ActuatorBackend>)),
        };

        // Initialize GPIO if enabled
        if config.enable_gpio {
            manager.init_gpio().await?;
        }

        // Initialize camera if enabled
        if config.enable_camera {
            manager.init_camera().await?;
        }

        // Initialize LIDAR if enabled
        if config.enable_lidar {
            manager.init_lidar().await?;
        }

        info!("Sensor manager initialized");
        Ok(manager)
    }

    /// Initialize GPIO subsystem
    async fn init_gpio(&self) -> Result<()> {
        info!("Initializing GPIO");

        #[cfg(feature = "gpio")]
        {
            // In production with rppal:
            // let gpio = Gpio::new()?;
            // Store gpio handle
            debug!("GPIO initialized with rppal");
        }

        #[cfg(not(feature = "gpio"))]
        {
            debug!("GPIO stub initialization (rppal feature disabled)");
        }

        Ok(())
    }

    /// Initialize camera subsystem
    async fn init_camera(&self) -> Result<()> {
        info!("Initializing camera: {}", self.config.camera_device);

        // In production, this would:
        // 1. Open V4L2 device
        // 2. Set format and resolution
        // 3. Start streaming

        let mut active = self.camera_active.write().await;
        *active = true;

        Ok(())
    }

    /// Initialize LIDAR subsystem
    async fn init_lidar(&self) -> Result<()> {
        info!(
            "Initializing LIDAR via {} at {}",
            self.config.lidar_connection, self.config.lidar_address
        );

        // In production, this would:
        // 1. Open serial/UDP/TCP connection
        // 2. Send initialization commands
        // 3. Start scan loop

        let mut active = self.lidar_active.write().await;
        *active = true;

        Ok(())
    }

    /// Read GPIO pin state
    pub async fn read_gpio(&self, pin: u8) -> Result<PinState> {
        if !self.config.enable_gpio {
            return Err(anyhow::anyhow!("GPIO is disabled"));
        }

        debug!("Reading GPIO pin {}", pin);

        #[cfg(feature = "gpio")]
        {
            // In production: read actual pin state via rppal
            // let pin = gpio.get(pin)?.into_input();
            // Ok(if pin.is_high() { PinState::High } else { PinState::Low })
        }

        // For now, return cached state or default
        let state = self.gpio_state.read().await;
        Ok(state.get(&pin).copied().unwrap_or(PinState::Low))
    }

    /// Write GPIO pin state
    pub async fn write_gpio(&self, pin: u8, state: PinState) -> Result<()> {
        if !self.config.enable_gpio {
            return Err(anyhow::anyhow!("GPIO is disabled"));
        }

        // Check whitelist
        if !self.config.gpio_output_whitelist.contains(&pin) {
            return Err(anyhow::anyhow!("GPIO pin {} not in whitelist", pin));
        }

        info!("Writing GPIO pin {} to {:?}", pin, state);

        #[cfg(feature = "gpio")]
        {
            // In production: write actual pin state via rppal
            // let mut pin = gpio.get(pin)?.into_output();
            // if state == PinState::High {
            //     pin.set_high();
            // } else {
            //     pin.set_low();
            // }
        }

        // Update cached state
        let mut gpio_state = self.gpio_state.write().await;
        gpio_state.insert(pin, state);

        Ok(())
    }

    /// Read camera frame
    pub async fn read_camera(&self) -> Result<CameraFrame> {
        if !self.config.enable_camera {
            return Err(anyhow::anyhow!("Camera is disabled"));
        }

        let active = self.camera_active.read().await;
        if !*active {
            return Err(anyhow::anyhow!("Camera is not active"));
        }

        debug!("Capturing camera frame");

        // In production, this would:
        // 1. Grab frame from V4L2 buffer
        // 2. Convert to RGB/JPEG
        // 3. Return frame data

        // For now, generate a test pattern
        let width = self.config.camera_width;
        let height = self.config.camera_height;
        let data = Self::generate_test_pattern(width, height);

        Ok(CameraFrame {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as u64,
            width,
            height,
            format: "RGB8".to_string(),
            data,
            origin: DataSource::Synthetic,
        })
    }

    /// Generate test pattern for camera simulation
    fn generate_test_pattern(width: u32, height: u32) -> Vec<u8> {
        let mut data = Vec::with_capacity((width * height * 3) as usize);

        for y in 0..height {
            for x in 0..width {
                // Simple gradient pattern
                let r = ((x as f32 / width as f32) * 255.0) as u8;
                let g = ((y as f32 / height as f32) * 255.0) as u8;
                let b = 128;
                data.extend_from_slice(&[r, g, b]);
            }
        }

        data
    }

    /// Read LIDAR scan
    pub async fn read_lidar(&self) -> Result<LidarScan> {
        if !self.config.enable_lidar {
            return Err(anyhow::anyhow!("LIDAR is disabled"));
        }

        let active = self.lidar_active.read().await;
        if !*active {
            return Err(anyhow::anyhow!("LIDAR is not active"));
        }

        debug!("Reading LIDAR scan");

        // In production, this would:
        // 1. Read raw data from serial/UDP
        // 2. Parse LIDAR protocol (e.g., RPLIDAR, YDLIDAR)
        // 3. Return point cloud

        // For now, generate simulated scan
        let points = Self::generate_test_lidar_scan();

        Ok(LidarScan {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as u64,
            points,
            scan_rate_hz: 10.0,
            origin: DataSource::Synthetic,
        })
    }

    /// Generate test LIDAR scan
    fn generate_test_lidar_scan() -> Vec<LidarPoint> {
        let mut points = Vec::new();

        for i in 0..360 {
            let angle_deg = i as f32;
            let distance_m = 2.0 + (angle_deg.to_radians().sin() * 0.5);
            let intensity = ((angle_deg / 360.0) * 255.0) as u8;

            points.push(LidarPoint {
                angle_deg,
                distance_m,
                intensity,
            });
        }

        points
    }

    /// Execute actuator action (with safety checks)
    ///
    /// Legacy single call: with `safety_mode` on this always fails (use
    /// [`Self::prepare_actuation`] + [`Self::confirm_actuation`] instead);
    /// with it off the command goes to the attached backend — which fails
    /// honestly when no hardware is attached instead of reporting a
    /// fabricated `Ok(())`.
    pub async fn execute_actuator(&self, action: &str, params: serde_json::Value) -> Result<ActuationRecord> {
        // Check whitelist
        if !self.config.actuator_whitelist.contains(action) {
            return Err(anyhow::anyhow!(
                "Actuator action '{}' not in whitelist",
                action
            ));
        }

        if self.config.safety_mode {
            warn!(
                "Actuator action '{}' requires confirmation (safety mode enabled)",
                action
            );
            return Err(anyhow::anyhow!(
                "Actuator action blocked by safety mode: prepare then confirm"
            ));
        }

        info!(
            "Executing actuator action: {} with params: {}",
            action, params
        );

        let backend = self.backend.read().await.clone();
        backend.apply(action, &params)
    }

    /// Attach the backend confirmed commands are applied to (default:
    /// [`NoHardwareBackend`]).
    pub async fn set_backend(&self, backend: Arc<dyn ActuatorBackend>) {
        *self.backend.write().await = backend;
    }

    /// Phase one of confirmed actuation: whitelist-check `action` and mint a
    /// single-use token valid for [`CONFIRM_TTL_MS`]. Nothing moves yet.
    pub async fn prepare_actuation(
        &self,
        action: &str,
        params: serde_json::Value,
    ) -> Result<PendingActuation> {
        if !self.config.actuator_whitelist.contains(action) {
            return Err(anyhow::anyhow!(
                "Actuator action '{}' not in whitelist",
                action
            ));
        }
        let token = self
            .next_token
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pending = PendingActuation {
            token,
            action: action.to_string(),
            params,
            expires_at_ms: now_ms().saturating_add(CONFIRM_TTL_MS),
        };
        self.pending.write().await.insert(token, pending.clone());
        Ok(pending)
    }

    /// Phase two: consume `token` and apply the command to the backend.
    /// Unknown, already-consumed, or expired tokens fail closed.
    pub async fn confirm_actuation(&self, token: u64) -> Result<ActuationRecord> {
        let pending = self
            .pending
            .write()
            .await
            .remove(&token)
            .ok_or_else(|| anyhow::anyhow!("unknown or already-consumed actuation token"))?;
        if now_ms() > pending.expires_at_ms {
            return Err(anyhow::anyhow!("actuation token expired"));
        }
        let backend = self.backend.read().await.clone();
        backend.apply(&pending.action, &pending.params)
    }

    /// Shutdown sensor manager
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down sensor manager");

        if self.config.enable_camera {
            let mut active = self.camera_active.write().await;
            *active = false;
        }

        if self.config.enable_lidar {
            let mut active = self.lidar_active.write().await;
            *active = false;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sensor_manager_init() {
        let config = SensorConfig::default();
        let manager = SensorManager::new(config).await;
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_camera_capture() {
        let mut config = SensorConfig::default();
        config.enable_camera = true;

        let manager = SensorManager::new(config).await.unwrap();
        let frame = manager.read_camera().await.unwrap();

        assert_eq!(frame.width, 640);
        assert_eq!(frame.height, 480);
        assert_eq!(frame.data.len(), 640 * 480 * 3);
    }

    #[tokio::test]
    async fn test_lidar_scan() {
        let mut config = SensorConfig::default();
        config.enable_lidar = true;

        let manager = SensorManager::new(config).await.unwrap();
        let scan = manager.read_lidar().await.unwrap();

        assert_eq!(scan.points.len(), 360);
        assert!(scan.scan_rate_hz > 0.0);
    }

    #[tokio::test]
    async fn test_gpio_whitelist() {
        let mut config = SensorConfig::default();
        config.enable_gpio = true;
        config.gpio_output_whitelist = vec![17, 27];

        let manager = SensorManager::new(config).await.unwrap();

        // Allowed pin
        let result = manager.write_gpio(17, PinState::High).await;
        assert!(result.is_ok());

        // Blocked pin
        let result = manager.write_gpio(99, PinState::High).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_actuator_safety() {
        let mut config = SensorConfig::default();
        config.safety_mode = true;
        config.actuator_whitelist.insert("move_forward".to_string());

        let manager = SensorManager::new(config).await.unwrap();

        // Should be blocked by safety mode
        let result = manager
            .execute_actuator("move_forward", serde_json::json!({"speed": 0.5}))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn actuator_confirmation_flow() {
        let mut config = SensorConfig::default();
        config.safety_mode = true;
        config.actuator_whitelist.insert("move".to_string());
        let manager = SensorManager::new(config).await.unwrap();
        let backend = Arc::new(SimActuatorBackend::new());
        manager
            .set_backend(backend.clone() as Arc<dyn ActuatorBackend>)
            .await;

        // No token: refused even though whitelisted.
        assert!(manager
            .execute_actuator("move", serde_json::json!({}))
            .await
            .is_err());

        // Prepare then confirm: exactly one recorded effect.
        let pending = manager
            .prepare_actuation("move", serde_json::json!({"v": 1}))
            .await
            .unwrap();
        let outcome = manager.confirm_actuation(pending.token).await.unwrap();
        assert_eq!(outcome.action, "move");
        assert_eq!(backend.commands().len(), 1);

        // Same token replayed: consumed already.
        assert!(manager.confirm_actuation(pending.token).await.is_err());
        assert_eq!(backend.commands().len(), 1);
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let mut config = SensorConfig::default();
        config.actuator_whitelist.insert("move".to_string());
        let manager = SensorManager::new(config).await.unwrap();
        let pending = manager
            .prepare_actuation("move", serde_json::json!({}))
            .await
            .unwrap();
        // Backdate the stored request past its TTL.
        {
            let mut map = manager.pending.write().await;
            let entry = map.get_mut(&pending.token).unwrap();
            entry.expires_at_ms = entry.expires_at_ms.saturating_sub(CONFIRM_TTL_MS + 1);
        }
        assert!(manager.confirm_actuation(pending.token).await.is_err());
    }

    #[tokio::test]
    async fn safety_off_without_hardware_fails_honestly() {
        let mut config = SensorConfig::default();
        config.safety_mode = false;
        config.actuator_whitelist.insert("move".to_string());
        let manager = SensorManager::new(config).await.unwrap();
        // The old code returned Ok(()) here having touched nothing.
        assert!(manager
            .execute_actuator("move", serde_json::json!({}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn synthetic_origin_is_labeled() {
        let mut config = SensorConfig::default();
        config.enable_camera = true;
        config.enable_lidar = true;
        let manager = SensorManager::new(config).await.unwrap();
        // Camera/lidar need init flags; enable them directly for the test.
        *manager.camera_active.write().await = true;
        *manager.lidar_active.write().await = true;
        assert_eq!(manager.read_camera().await.unwrap().origin, DataSource::Synthetic);
        assert_eq!(manager.read_lidar().await.unwrap().origin, DataSource::Synthetic);
    }

    #[test]
    fn force_sample_schema_roundtrips() {
        let sample = ForceSample {
            timestamp: 1,
            force_n: [0.0, 0.0, -9.81],
            torque_nm: [0.0, 0.0, 0.0],
            phase: ContactPhase::Contact,
        };
        let back: ForceSample =
            serde_json::from_str(&serde_json::to_string(&sample).unwrap()).unwrap();
        assert_eq!(back.phase, ContactPhase::Contact);
        assert_eq!(back.force_n[2], -9.81);
    }
}
