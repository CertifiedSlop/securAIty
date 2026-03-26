# ADR-001: Event-Driven Architecture with NATS

## Status

Accepted

## Date

2026-03-26

## Context

The securAIty platform requires a communication mechanism between distributed security agents that can handle:

- High-throughput security event streaming (1000+ events/second)
- Reliable message delivery with persistence for audit trails
- Decoupled producer-consumer architecture for agent independence
- Support for both fire-and-forget events and request-response patterns
- Horizontal scaling of agent instances
- Resilience to network partitions and component failures

The system includes multiple specialized AI agents (Antivirus, Pentester, Analyst, Engineer, Auditor) that must coordinate security operations while maintaining autonomy.

### Requirements

1. **Performance**: Sub-10ms message latency for real-time threat response
2. **Reliability**: Guaranteed delivery with at-least-once semantics
3. **Persistence**: Event storage for compliance and forensic analysis
4. **Scalability**: Support for 100+ concurrent agent instances
5. **Security**: TLS encryption and authentication for all communications

## Decision

We selected **NATS with JetStream** as the event bus for securAIty.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         securAIty Platform                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐      │
│  │Antivirus │    │Pentester │    │ Analyst  │    │ Engineer │      │
│  │  Agent   │    │  Agent   │    │  Agent   │    │  Agent   │      │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘      │
│       │               │               │               │            │
│       │               │               │               │            │
│       └───────────────┴───────┬───────┴───────────────┘            │
│                               │                                    │
│                    ┌──────────▼──────────┐                         │
│                    │   NATS JetStream    │                         │
│                    │   ┌─────────────┐   │                         │
│                    │   │  SECURITY   │   │                         │
│                    │   │   EVENTS    │   │                         │
│                    │   │   Stream    │   │                         │
│                    │   └─────────────┘   │                         │
│                    └──────────┬──────────┘                         │
│                               │                                    │
│       ┌───────────────────────┼───────────────────────┐           │
│       │                       │                       │           │
│  ┌────▼─────┐          ┌──────▼──────┐         ┌─────▼─────┐      │
│  │ Auditor  │          │Orchestrator │         │   API     │      │
│  │  Agent   │          │   Manager   │         │  Gateway  │      │
│  └──────────┘          └─────────────┘         └───────────┘      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### NATS Configuration

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Stream Name | `SECURITY_EVENTS` | Dedicated stream for all security events |
| Storage Type | File (production) / Memory (dev) | Persistence for audit, memory for development |
| Retention Policy | Limits | Retain messages based on age/count limits |
| Max Messages per Subject | 100,000 | Prevent unbounded growth per event type |
| Max Age | 86,400 seconds (24h) | Automatic cleanup of old events |
| Ack Policy | Explicit | Guaranteed delivery confirmation |

### Event Subjects

```
SECURITY_EVENTS.THREAT_DETECTED      # Real-time threat alerts
SECURITY_EVENTS.VULNERABILITY_FOUND  # Vulnerability scan results
SECURITY_EVENTS.POLICY_VIOLATION     # Compliance violations
SECURITY_EVENTS.INCIDENT_CREATED     # New security incidents
SECURITY_EVENTS.AGENT_STATUS         # Agent health updates
SECURITY_EVENTS.AUDIT_LOG            # Audit trail events
```

### Message Format

All events follow a standardized schema:

```json
{
  "event_id": "evt_<uuid>",
  "event_type": "THREAT_DETECTED",
  "timestamp": "2026-03-26T10:30:00Z",
  "source": "antivirus_agent",
  "severity": "HIGH",
  "payload": {
    "threat_name": "Trojan.Generic",
    "file_path": "/tmp/suspicious.exe",
    "file_hash": "sha256:abc123..."
  },
  "correlation_id": "corr_<uuid>"
}
```

## Consequences

### Positive

1. **Decoupling**: Agents can be developed, deployed, and scaled independently
2. **Performance**: NATS achieves sub-millisecond latency for pub/sub patterns
3. **Reliability**: JetStream provides message persistence and replay capability
4. **Observability**: Centralized event stream enables comprehensive monitoring
5. **Flexibility**: Supports multiple communication patterns (pub/sub, request/reply, queue groups)
6. **Audit Trail**: Persistent event storage meets compliance requirements

### Negative

1. **Complexity**: Additional infrastructure component (NATS server) to manage
2. **Learning Curve**: Team must learn NATS-specific concepts and tooling
3. **Debugging**: Distributed tracing required to follow event flows
4. **Resource Overhead**: JetStream persistence requires disk I/O and storage

### Trade-offs

| Alternative | Why Not Selected |
|-------------|------------------|
| **RabbitMQ** | Higher latency (~10ms vs <1ms), more complex clustering |
| **Apache Kafka** | Overkill for our scale, higher operational complexity |
| **Redis Pub/Sub** | No built-in persistence, message loss on disconnect |
| **AWS SQS/SNS** | Vendor lock-in, higher latency, cost at scale |
| **ZeroMQ** | No built-in broker, more complex deployment |

## Implementation Details

### Connection Management

```python
from securAIty.events.bus import EventBus, EventBusConfig

config = EventBusConfig(
    servers=["nats://natss:4222"],
    cluster_id="security-cluster",
    client_id="antivirus_agent",
    jetstream_enabled=True,
    jetstream_stream="SECURITY_EVENTS",
)

async with EventBus(config) as bus:
    await bus.publish(event)
    await bus.subscribe(["THREAT_DETECTED"], handler)
```

### Error Handling

- Automatic reconnection with exponential backoff (2s base, max 10 attempts)
- Message acknowledgment required before removal from stream
- Dead letter queue for poison messages (future enhancement)
- Circuit breaker pattern for downstream service calls

### Security Controls

1. **TLS 1.3**: All NATS connections use TLS in production
2. **Authentication**: Token-based authentication for client connections
3. **Authorization**: Subject-based access control (planned)
4. **Network Isolation**: NATS only accessible on internal Docker network

## Compliance Mapping

This decision supports the following compliance requirements:

- **SOC2 CC6.6**: Security event logging and monitoring
- **ISO27001 A.12.4**: Logging and monitoring controls
- **NIST AU-1**: Audit and accountability policy
- **PCI DSS 10.1**: Audit trail implementation

## References

- [NATS Documentation](https://docs.nats.io/)
- [JetStream Technical Documentation](https://docs.nats.io/nats-server/nats_server#jetstream)
- [NATS Performance Benchmarks](https://docs.nats.io/reference/reference-protocols/nats-tcpnats-performance)
- [Event-Driven Architecture Best Practices](https://aws.amazon.com/event-driven-architecture/)

## Related ADRs

- [ADR-002: Agent Communication Patterns](002-agent-communication-patterns.md)
- [ADR-003: Security Model](003-security-model.md)
- [ADR-005: Python Async Design](005-python-async-design.md)
