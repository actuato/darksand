# Darksand — governed execution for physical systems

Action → Run → Proof for robots: deterministic behavior-tree missions with a
safety containment halt, signed run policy, and a fleet control plane.

Extracted from `igris` (`igris-runtime` + `igris-overture`) at commit
`7e6098ef9`, 2026-10-04, under owner authorization. Both repos are MIT
licensed; original copyright headers are preserved in extracted files.

## Layout

* `crates/darksand-safety` — containment: `ViolationEventBus`,
  `ContainmentGuard`, `RoboticsContext`, signed violation records.
* `crates/darksand-ros2` — ROS2 node (`r2r`, feature-gated), Nav2
  (`navigate_to_pose` → `/navigate_to_pose`), `/cmd_vel` safety publisher,
  containment bridge (20ms Nav2 cancel + 3s zero-velocity loop).
* `crates/darksand-btree` — deterministic mission core reconstructed
  standalone (upstream was missing its `core` module): Sequence, Selector,
  Parallel, Inverter, Repeat, Retry, Timeout, blackboard conditions, and
  the ROS topic/service action nodes (`ros2` = stub, `ros2-live` = real
  `r2r` bindings). Executor keeps max-ticks, deadline, cancel, and the
  per-tick JSON observer. Deferred: LLM planners, mission-file parser,
  WAL checkpoints, tool actions.
* `crates/darksand-recovery` — Nav2 recovery behaviors (spin, backup,
  clear-costmap) plus generic retry classification.
* `crates/darksand-policy` — standalone policy service (SQLite, no
  Overture/Clerk/Postgres): versioned robot-mode policies
  (`supervised|active|disabled`), runtime allow-lists, Ed25519-signed
  lifecycle commands with nonce replay protection, audit trail.
  Run: `DARKSAND_POLICY_KEYS="tenant:key" cargo run -p darksand-policy`.
* `crates/darksand-fleet` — fleet agent: register / config-sync / signed
  telemetry upload. Reports real system stats (mock values only in
  explicit `mock_mode`); `.igris/` key material is never committed.
* `crates/darksand-swarm`, `darksand-sensors`, `darksand-simulation` —
  coordination primitives, GPIO/camera/lidar, sim envs
  (`virtual_swarm` implemented; `gazebo`/`isaac_sim` are config names only).
* `reference/` — verbatim upstream sources not yet promoted: full BT tree
  (`btree-ros/`), server `Ros2Manager` wiring, Go policy routes + SQL
  migrations (`policy/`), preview docs.
* `config/robotics.example.json5` — all sections disabled by default.
* `docker/Dockerfile.ros2` — ROS Humble build + stub-test gate.

## Build

```sh
cargo check --workspace && cargo test --workspace   # stub ROS2, no hardware
cargo test -p darksand-btree --features ros2        # ROS nodes vs stub
docker build -f docker/Dockerfile.ros2 .            # real r2r bindings
```

## Roadmap

* **Phase 0 — Repair (this branch):** fleet honesty fixes, standalone BT
  core, standalone policy service, ROS2 Docker CI, `darksand-*` renames.
* **Phase 1 — Single-robot MVP:** JSON mission files → BT + Nav2 under
  containment, signed run receipts, Gazebo sim-in-loop.
* **Phase 2 — Fleet control plane:** registration, config push, real
  telemetry dashboards, policy governance per robot mode.
* **Phase 3 — Swarm + HIL:** multi-host transport (today likely
  in-memory — verify first), Isaac Sim, self-hosted HIL rig.

Not building: LLM planners as product surface, marketplace, workflow
builder, new protocols — frozen until Phase 1 ships.

## Safety invariants

Server-side authz (bearer tenants; all v1 key-holders are admin — see
`darksand-policy` docs), tenant-scoped state, deny-by-default targets, no
blind replay of uncertain effects, signed commands with 5-minute skew +
nonce replay windows, no secrets in logs or git.
