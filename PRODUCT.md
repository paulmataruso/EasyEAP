# Product

<!-- impeccable:product-schema 1 -->

> Interview substitution: the user directed a fully autonomous build ("no stopping, no asking"). Facts below come from the written brief and three answered questions (tenancy, critique scope, enrollment). Items marked *(inferred)* were not separately confirmed.

## Platform

web

## Stack

React + TypeScript + Tailwind CSS frontend (user-specified); Python FastAPI backend, PostgreSQL, FreeRADIUS 3.2, OpenBao PKI, Docker Compose (delegated: chosen by Claude and documented in ARCHITECTURE.md).

## Users

- **MSP technicians** who deploy and run EasyEAP for several customer organisations from one console. They visit any single tenant infrequently, so every screen must re-orient them quickly. *(inferred from "MSP or IT administrator")*
- **Customer IT administrators** with co-managed, tenant-scoped access. Network generalists, not PKI engineers.
- **Auditors** with read-only access.
- **End users** who open a one-time enrollment link on their own device to install a Wi-Fi certificate.

## Product Purpose

EasyEAP is a dedicated EAP-TLS Wi-Fi authentication and certificate management platform: an internal PKI, Active Directory-driven authorization, FreeRADIUS authentication with dynamic VLAN assignment, and per-device certificate enrollment for Windows, macOS, iOS/iPadOS, Android and Linux.

Success: an administrator finds an AD user, clicks **Issue Wi-Fi Certificate**, and the user receives a platform-specific package; the device connects to EAP-TLS Wi-Fi and lands on the VLAN their AD groups dictate.

## Positioning

"Cisco ISE Lite": EAP-TLS, PKI and RADIUS only, not general NAC. Deployable with Docker Compose and operated entirely through the GUI; no hand-edited OpenSSL or FreeRADIUS configuration.

## Operating Context

- Multi-tenant MSP console: each tenant has its own Root CA (offline) and issuing CA, AD connection, access policies, VLANs, RADIUS clients and audit trail.
- Wireless controllers: Cisco WLC (AireOS and Catalyst 9800) and Ubiquiti UniFi Network.
- Default RADIUS ports UDP 1812/1813; CoA towards controllers on UDP 3799 (1700 on Catalyst 9800 by default).

## Capabilities and Constraints

- RADIUS keeps authenticating when the web UI or API restarts.
- Fail securely: missing or stale authorization data, AD errors and policy errors deny.
- Explicit deny rules win over allow rules; every decision records which rule decided it.
- One certificate per device; certificates are individually revocable.
- Private keys: generated on the end user's device by default; server-side generation is an opt-in, per-tenant admin mode with encrypted one-time retrieval.
- Never log private keys, passwords, RADIUS shared secrets, enrollment secrets or PKCS#12 passwords.
- Production screens show real backend data only; demonstration data exists only in the design prototypes and is labelled synthetic.

## Brand Commitments

- Name: **EasyEAP**. Tagline: **Enterprise Wi-Fi Authentication, Simplified.**
- Visual direction pinned by the brief: dark glassmorphism. Deep charcoal/midnight grounds, layered translucent surfaces, refined borders, controlled gradients, premium typography; no excessive blur, glow, gradients or over-rounded cards.
- No generic shield-and-lock logo.

## Evidence on Hand

None: no customers, testimonials or benchmarks exist. Do not invent any.

## Product Principles

1. The issue-a-certificate workflow is the heart of the product; everything else supports it.
2. Explain, don't just report: translate RADIUS/TLS failures and policy decisions into plain language, with technical detail one click away.
3. Secure by default, honest about limits (e.g. revocation latency with controller caches).
4. Re-orient fast: tenant context, system readiness and what needs attention are always visible.

## Accessibility & Inclusion

WCAG 2.2 AA for the admin console and enrollment portal *(inferred)*: 4.5:1 text contrast on glass surfaces, full keyboard operation, visible focus, reduced-motion support.
