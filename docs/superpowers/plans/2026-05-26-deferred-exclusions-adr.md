# Deferred Exclusions — Architecture Decision Records

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Document why each intentional exclusion from the Azure Key Vault parity audit is a deliberate non-goal, so future contributors understand the boundaries of the project.

**Architecture:** No code changes. This plan produces only documentation — one ADR section per excluded feature. Each ADR follows the standard format: Context, Decision, Consequences.

**Tech Stack:** Markdown. No code.

---

## ADR-1: HSM-Backed Keys

**Status:** Rejected (intentional non-goal)

**Context:**
Azure Key Vault supports Hardware Security Module-backed key types (RSA-HSM, EC-HSM, oct-HSM, and Azure Managed HSM) that store private key material inside tamper-resistant hardware, preventing extraction even by privileged operators. Implementing equivalent functionality in RocketVault would require PKCS#11 driver integration or a dedicated HSM SDK, plus hardware procurement and provisioning workflows.

**Decision:**
RocketVault is a software-only, self-hosted service by design. Hardware integration introduces mandatory infrastructure dependencies that conflict with the project's goal of being deployable anywhere with a single Go binary and a database.

**Consequences:**
- Operators lose the ability to guarantee that private key material never exists in software-accessible memory.
- Operators requiring HSM-level key protection should use Azure Key Vault directly, HashiCorp Vault Enterprise with a supported HSM seal, or a PKCS#11-capable key management appliance.
- This decision should be revisited if a funded PKCS#11 integration or cloud-HSM backend (such as AWS CloudHSM or Google Cloud HSM) is scoped as a first-class feature.

---

## ADR-2: VNet Service Endpoints, Private Link, Trusted Services Bypass, and Network Security Perimeter

**Status:** Rejected (intentional non-goal)

**Context:**
Azure Key Vault supports network access restrictions enforced at the Azure platform layer: VNet service endpoints, Private Link (private IP routing), Trusted Services bypass (whitelisting first-party Azure services), and the Network Security Perimeter. These controls restrict which networks and services can reach the vault at the hypervisor and software-defined networking layer, below the application itself.

**Decision:**
A self-hosted Go service has no access to Azure's SDN primitives. These controls are not implementable inside the application layer; the equivalent responsibility belongs to the operator's infrastructure.

**Consequences:**
- Operators lose a single Azure-native control plane for network access policy.
- Operators should enforce equivalent isolation using firewall rules, Kubernetes NetworkPolicy, an Istio/Envoy service mesh, or a reverse proxy (such as nginx or Traefik) with mutual TLS and allowlist rules placed in front of RocketVault.
- This decision should be revisited only if RocketVault is ever deployed as a managed hosted service where the project controls the surrounding network infrastructure.

---

## ADR-3: Conditional Access, Privileged Identity Management (PIM), and Just-In-Time (JIT) Access

**Status:** Rejected (intentional non-goal)

**Context:**
Azure Key Vault integrates with Microsoft Entra ID for Conditional Access policies (device compliance, location restrictions), Privileged Identity Management (time-bound role elevation with approval workflows), and Just-In-Time access grants. These features require a live connection to a cloud identity provider and its policy evaluation engine.

**Decision:**
RocketVault uses a local identity model with JWT-based sessions and RBAC. It has no dependency on an external identity provider, and introducing one would break the self-contained deployment model. The existing short-lived JWT TTLs and role-based access control already provide a functional, if simpler, equivalent.

**Consequences:**
- Operators lose automated policy-based access restrictions tied to device health, network location, or approval workflows.
- Operators should approximate JIT access by issuing short-TTL JWTs for privileged operations and using RocketVault's RBAC to scope roles narrowly. Approval workflows must be handled outside RocketVault (for example, via a secrets-request ticketing system that calls the RocketVault API after approval).
- This decision should be revisited if RocketVault adds OIDC or Entra ID integration as an identity backend.

---

## ADR-4: Azure Monitor-Integrated Metrics and SIEM Forwarding

**Status:** Rejected (intentional non-goal)

**Context:**
Azure Key Vault natively pushes diagnostic logs, audit events, and metrics to Azure Monitor, which can route data to Log Analytics workspaces, Event Hubs, and third-party SIEM systems. This tight platform integration means operators get audit trails with zero additional tooling in an Azure environment.

**Decision:**
Azure Monitor is a hosted-cloud concern with no self-hosted equivalent. Building a native Azure Monitor emitter into RocketVault would create an Azure-specific dependency in a product designed to run anywhere. RocketVault already emits structured JSON logs and file-based audit logs, which are the standard interface for operator-managed log pipelines.

**Consequences:**
- Operators do not get out-of-the-box SIEM integration; they must configure their own log shipping pipeline.
- Operators should use a log shipper such as Fluentd, Vector, or Filebeat to tail RocketVault's structured log output and forward it to their SIEM or observability platform (Splunk, Elastic, Datadog, etc.).
- This decision should be revisited if operators request an OpenTelemetry exporter, which would provide a vendor-neutral push mechanism without creating an Azure-specific dependency.

---

## ADR-5: Cross-Vault Restore Semantics (Same Subscription/Region Required)

**Status:** Rejected (intentional non-goal)

**Context:**
Azure Key Vault enforces that backup blobs are region-bound and subscription-bound; restoring a key or secret to a different region or subscription is blocked to prevent cross-region key exfiltration. Implementing the same restriction in RocketVault would require embedding geographic or tenancy metadata into backup blobs and validating it on restore.

**Decision:**
RocketVault backups are intentionally portable. Backup blobs are encrypted with AES-256-GCM using a config-managed master key and carry no region or subscription binding. This is a deliberate advantage for self-hosted deployments where operators may need to restore to any node in any data centre. The operator is responsible for protecting the master key.

**Consequences:**
- Operators do not get platform-enforced cross-region exfiltration prevention built into the backup format.
- Operators must protect the master encryption key through their own controls (for example, storing it in a secrets manager, using restricted file permissions, or rotating it on a schedule). Backup portability without adequate master-key protection is a security risk that the operator assumes.
- This decision should be revisited if RocketVault introduces a multi-region or multi-tenant model where cross-tenant restore prevention becomes a product requirement rather than an operator responsibility.

---

## ADR-6: Vault-Level Soft-Delete

**Status:** Rejected (intentional non-goal)

**Context:**
Azure Key Vault supports soft-deleting the entire vault namespace as an object, placing it in a recoverable deleted state for a configurable retention window before permanent purge. This protects against accidental deletion of the vault container itself in multi-vault Azure subscriptions.

**Decision:**
RocketVault is a single-vault system. There is no vault-namespace concept — the running process is the vault. Soft-deleting the vault would be equivalent to stopping and archiving the entire service, which is an infrastructure-level operation outside the application's scope. The feature has no meaningful analogue in the current architecture.

**Consequences:**
- Operators have no application-level recovery window if the RocketVault data store is accidentally deleted.
- Operators should protect the underlying database and data directory using infrastructure-level tools: filesystem snapshots, database point-in-time recovery, or the per-item backup and restore functionality already implemented in RocketVault.
- This decision should be revisited if RocketVault adds a multi-vault namespace model, at which point vault-level lifecycle management (including soft-delete) becomes a meaningful product concern.

---

## Revisiting These Decisions

These decisions should be revisited if:
- RocketVault adds a multi-tenant or multi-vault namespace model (unlocks vault-level soft-delete)
- A PKCS#11 / cloud-HSM integration is funded (unlocks HSM keys)
- An OIDC/Entra ID identity provider is added (unlocks Conditional Access and PIM)
- Operators request Azure Monitor native push (consider an OpenTelemetry exporter instead)
