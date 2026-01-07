# IncubaCloud Core

**IncubaCloud** is an open-source platform designed to simplify, standardize and automate the deployment and management of **Odoo instances on remote infrastructure**.

It provides a **visual and structured interface inside Odoo** to orchestrate tools such as **Doodba**, Docker-based environments and VPS servers over SSH, reducing manual DevOps work for Odoo partners and implementers.

IncubaCloud Core is the **foundation layer** of the platform.

---

## What problem does IncubaCloud solve?

Deploying and managing Odoo environments typically requires:
- Manual server provisioning
- SSH access
- Deep knowledge of Docker, Git, Doodba and Linux
- Custom scripts and undocumented processes

IncubaCloud transforms this workflow into:
- A **controlled, repeatable and auditable process**
- Managed directly from Odoo
- With a modular and extensible architecture

---

## Core principles

- **Odoo-first**: IncubaCloud runs *inside Odoo* as native modules
- **Tool-agnostic**: Doodba is supported, but not hardcoded as the only option
- **Remote by design**: All operations are executed on external VPS servers via SSH
- **Composable architecture**: Each responsibility is isolated into clear modules
- **Open Core**: A strong OSS foundation with optional enterprise extensions

---

## What is included in IncubaCloud Core?

IncubaCloud Core provides the essential building blocks required to operate the platform:

- Project and environment definitions
- Secure SSH connection management
- Remote execution and orchestration layer
- Integration with Doodba-based projects
- Base logging and execution tracking
- Extensible service and provider abstractions

These modules are intended to be:
- Stable
- Transparent
- Reusable by the community

---

## Typical use cases

- Odoo partners managing multiple customer environments
- Technical teams standardizing deployment processes
- Training and staging environments without Odoo.sh costs
- Local or cloud-based VPS orchestration
- Foundations for managed Odoo services

---

## Architecture overview
```
Odoo (IncubaCloud UI)
|
| SSH / API
v
Remote VPS
├─ Git repositories
├─ Doodba projects
├─ Docker services
└─ Logs & execution context
```

IncubaCloud acts as the **control plane**, not the runtime.

---

## Licensing

IncubaCloud Core is licensed under the **GNU Affero General Public License v3 (AGPL-3.0)**.

This means:
- You are free to use, modify and distribute the software
- Any network-accessible modifications must be published under the same license

Enterprise modules are distributed under a **separate commercial license**.

See the `LICENSE` file for full details.

---

## Roadmap (high level)

- Stable core APIs
- Provider abstraction (VPS, cloud, local)
- Pluggable orchestration backends
- Improved observability hooks
- Community-driven extensions

The roadmap prioritizes **stability over features**.

---

## Status

🚧 **Active development**

The project is under active development and not yet production-ready.
Breaking changes may occur until a first stable release is published.

---

## Contributing

Contributions are welcome.

If you are an Odoo partner or developer:
- Bug reports
- Architectural discussions
- New providers or integrations

Please open an issue before submitting major changes.

---

## Vision

IncubaCloud aims to become a **neutral, open and extensible control plane** for Odoo infrastructure — empowering partners without locking them into a single hosting or deployment model.

---

## Contact

Project maintained by the IncubaCloud team.

Enterprise features, support and partnerships:
📩 contact@incubacloud.io
