# Darksand — standalone robotics stack

Extracted from `Igris` (`igris-runtime` + `igris-overture`) at commit
`7e6098ef9`, 2026-10-04, under owner authorization. Both repos are MIT
licensed; original copyright headers are preserved in extracted files.

## Layout

* `crates/` — buildable Rust workspace (default features, no ROS2 hardware):
  * `igris-safety` — containment: `ViolationEventBus`, `ContainmentGuard`,
    `RoboticsContext`, violation records (`src/violation.rs`, `src/event_bus.rs`)
  * `igris-ros2` — ROS2 node (`r2r`, feature-gated), Nav2
    (`navigate_to_pose`, `/navigate_to_pose`), `/cmd_vel` safety publisher,
    `containment_bridge` (20ms Nav2 cancel + 3s zero-velocity loop)
  * `igris-recovery` — Nav2 recovery: spin / backup / clear-costmap
    (`ros2` feature is optional)
  * `igris-fleet` — fleet agent: register / config-sync / telemetry upload
    against `POST|GET /api/fleet/*`. `.igris/` key material was
    deliberately NOT extracted — each deployment generates its own keys.
  * `igris-swarm`, `igris-sensors`, `igris-simulation` — coordination,
    GPIO/camera/lidar, `virtual_swarm|gazebo|isaac_sim` test envs
* `reference/btree-ros/` — verbatim behavior-tree ROS nodes
  (`RosTopicPublish`, `RosTopicSubscribe`, `RosServiceCall`) plus the full
  BT source they were taken from. NOT a workspace member: the source tree
  is missing its `core` module and `Cargo.toml` upstream
  (`src/lib.rs:60` declares `pub mod core`, no `core/` dir exists), so it
  cannot compile standalone until that gap is closed.
* `reference/server-integration/ros2_integration.rs` — verbatim
  `Ros2Manager` startup wiring. The `robotics-platform` dispatch branches
  in igris `task_executor.rs` (~lines 1414, 4149–4319, 5410, 6826+) were
  intentionally not duplicated (7k-line file); reimplement dispatch here
  against `Ros2Node` instead of porting that file.
* `policy/` — Go reference: robotics policy lifecycle API
  (`routes_robotics_policy.go`), fleet push routes, audit export,
  `fleet_crypto.go`, and SQL migrations `001,020,022,025,026,036–042`.
  Requires the Overture harness (Fiber, Postgres, BetterAuth middleware)
  to build; included as the contract to reimplement, not as a module.
* `config/robotics.example.json5` — `ros2/sensors/swarm/fleet/simulation`
  sections, all disabled by default.
* `docs/*.mdx` — technical-preview docs, unchanged.
* `.github/workflows/ros2-hil.yml` — hardware-in-loop CI (self-hosted
  `ros2-hil` runner, `--features ros2`).

## Build

```sh
cargo check --workspace   # stub ROS2, no hardware required
cargo check -p igris-ros2 --features ros2   # needs ROS2 + r2r env
cargo test --workspace
```

## Safety invariants carried over

Server-side authz, tenant-scoped state, deny-by-default outbound targets,
no blind replay of uncertain effects, Ed25519-signed policy commands with
nonce replay protection, no secrets in logs. Fleet private keys are never
committed (see `.gitignore`: `.igris/`).
