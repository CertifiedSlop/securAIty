# ADR-002: Agent Communication Patterns

**Author:** CertifiedSlop

## Status

Accepted

## Date

2026-03-26

## Context

The securAIty platform orchestrates multiple specialized AI agents that must coordinate complex security operations. The communication patterns between agents determine system responsiveness, fault tolerance, and operational complexity.

### Agent Types

| Agent | Responsibility | Interaction Pattern |
|-------|---------------|---------------------|
| Antivirus | Malware detection | Event publisher, task executor |
| Pentester | Vulnerability assessment | Request/response, event publisher |
| Analyst | Incident investigation | Event subscriber, analyst |
| Engineer | Security hardening | Task executor, config publisher |
| Auditor | Compliance auditing | Event subscriber, report generator |
| Orchestrator | Task routing | Message router, state manager |

### Communication Requirements

1. **Synchronous**: Request-response for immediate task execution
2. **Asynchronous**: Event streaming for status updates and alerts
3. **Broadcast**: One-to-many for system-wide announcements
4. **Point-to-Point**: One-to-one for specific task delegation
5. **Fan-out**: One-to-many for parallel processing

## Decision

We implement a **hybrid communication model** using NATS with multiple orchestration patterns:

### Pattern 1: Sequential Workflow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│Orchestrator │───▶│  Antivirus  │───▶│   Analyst   │───▶│  Engineer   │
│             │    │   (scan)    │    │  (analyze)  │    │  (remediate)│
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
     │                   │                   │                   │
     │  Task Request     │                   │                   │
     ├──────────────────▶│                   │                   │
     │                   │  Scan Result      │                   │
     │◀──────────────────┤                   │                   │
     │                   │                   │                   │
     │                   │  Threat Event     │                   │
     │                   ├──────────────────▶│                   │
     │                   │                   │  Analysis Result  │
     │                   │                   ├──────────────────▶│
     │                   │                   │                   │
     │                   │                   │                   │  Action
     │                   │                   │                   │◀─────
```

**Use Case**: Malware response workflow
- Orchestrator initiates scan request
- Antivirus detects threat, publishes event
- Analyst evaluates threat severity
- Engineer implements remediation

### Pattern 2: Concurrent Execution

```
┌─────────────┐
│Orchestrator │
└──────┬──────┘
       │  Scan Request (broadcast)
       ├────────────────────────────────────┐
       │                                    │
       ▼                                    ▼
┌─────────────┐                      ┌─────────────┐
│  Antivirus  │                      │  Pentester  │
│   (files)   │                      │  (network)  │
└──────┬──────┘                      └──────┬──────┘
       │                                    │
       │  File Scan Results                 │  Network Scan Results
       │                                    │
       └────────────────┬───────────────────┘
                        │
                        ▼
                 ┌─────────────┐
                 │   Analyst   │
                 │  (correlate)│
                 └─────────────┘
```

**Use Case**: Comprehensive security assessment
- Parallel scanning reduces total execution time
- Analyst correlates findings from multiple sources
- Enables holistic threat assessment

### Pattern 3: Handoff (Chain of Responsibility)

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Level 1 │───▶│  Level 2 │───▶│  Level 3 │───▶│  Level 4 │
│  Triage  │    │ Analyst  │    │ Engineer │    │  Escalate│
└──────────┘    └──────────┘    └──────────┘    └──────────┘
     │               │               │               │
     │ Can auto-     │ Needs         │ Needs         │ Human
     │ resolve       │ investigation │ remediation   │ review
     ▼               ▼               ▼               ▼
  Auto-close    Investigate     Remediate      Escalate to
  low-priority  medium-priority high-priority   security team
```

**Use Case**: Incident triage and escalation
- Each agent handles what it can
- Complex issues escalate to next level
- Clear escalation path with context preservation

### Pattern 4: Group Chat (Collaborative)

```
                    ┌─────────────────┐
                    │  Shared Context │
                    │  (Incident #42) │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│   Antivirus   │   │   Pentester   │   │    Analyst    │
│               │   │               │   │               │
│ "Found Trojan"|   │"Exploit path" |   │"Correlating..."│
└───────┬───────┘   └───────┬───────┘   └───────┬───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                    All agents see
                    all messages
```

**Use Case**: Complex incident investigation
- All agents share context
- Collaborative problem-solving
- Real-time information sharing

### Pattern 5: Magentic (AI-Orchestrated)

```
┌─────────────────────────────────────────────────────────────┐
│                    Qwen AI Orchestrator                      │
│                                                              │
│  Input: "Investigate suspicious activity on web-server-01"  │
│                                                              │
│  Plan Generation:                                           │
│  1. Antivirus: Scan server for malware                      │
│  2. Pentester: Check for vulnerabilities                    │
│  3. Analyst: Correlate findings                             │
│  4. Engineer: Apply fixes if needed                         │
│                                                              │
│  Dynamic Replanning:                                        │
│  - If malware found → skip to remediation                   │
│  - If clean → continue with vuln scan                       │
└─────────────────────────────────────────────────────────────┘
```

**Use Case**: Natural language security operations
- AI interprets intent and creates execution plan
- Dynamic replanning based on intermediate results
- Reduces human cognitive load

## Implementation

### Pattern Selection Matrix

| Scenario | Recommended Pattern | Rationale |
|----------|-------------------|-----------|
| Malware response | Sequential | Clear workflow with dependencies |
| Security assessment | Concurrent | Maximize parallelism |
| Incident triage | Handoff | Appropriate escalation |
| Complex investigation | Group Chat | Collaborative analysis |
| Natural language ops | Magentic | AI planning and adaptation |

### State Management

```python
from securAIty.orchestrator.state_manager import StateManager

class WorkflowState:
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    WAITING_ON_AGENT = "waiting_on_agent"
    COMPLETED = "completed"
    FAILED = "failed"

state_manager = StateManager()
await state_manager.set_workflow_state(workflow_id, WorkflowState.IN_PROGRESS)
await state_manager.set_agent_result(workflow_id, "antivirus", scan_result)
```

### Correlation Context

```python
from securAIty.events.correlation import CorrelationContext

context = CorrelationContext(
    correlation_id="corr_abc123",
    workflow_id="wf_xyz789",
    incident_id="inc_001",
)

# Context automatically propagated with events
await event_bus.publish(event, context=context)
```

### Task Routing

```python
from securAIty.orchestrator.task_router import TaskRouter

router = TaskRouter()

router.register_capability(
    capability="scan_file",
    agent="antivirus_agent",
    priority=10,
)

router.register_capability(
    capability="vulnerability_scan",
    agent="pentester_agent",
    priority=10,
)

# Route task to appropriate agent
task = TaskRequest(
    capability="scan_file",
    input_data={"file_path": "/tmp/suspicious.exe"},
)
result = await router.route_task(task)
```

## Consequences

### Positive

1. **Flexibility**: Different patterns for different scenarios
2. **Resilience**: No single point of failure in communication
3. **Scalability**: Patterns support horizontal scaling
4. **Observability**: Centralized state tracking enables monitoring
5. **Maintainability**: Clear patterns reduce cognitive load

### Negative

1. **Complexity**: Multiple patterns increase learning curve
2. **Debugging**: Tracing across patterns requires tooling
3. **State Management**: Distributed state adds complexity
4. **Testing**: Each pattern requires specific test strategies

### Trade-offs

| Approach | Why Not Selected |
|----------|------------------|
| **Pure Pub/Sub** | No request/response, hard to track task completion |
| **Pure Request/Reply** | Tight coupling, no event streaming |
| **Centralized Orchestrator** | Single point of failure, bottleneck |
| **Pure Peer-to-Peer** | Complex coordination, no central state |

## Error Handling

### Timeout Handling

```python
from securAIty.orchestrator.patterns.concurrent import execute_concurrent

tasks = [
    {"agent": "antivirus", "task": scan_files},
    {"agent": "pentester", "task": scan_network},
]

results = await execute_concurrent(
    tasks=tasks,
    timeout_seconds=300,
    on_timeout="continue",  # or "fail" or "partial"
)
```

### Retry Logic

```python
from securAIty.orchestrator.patterns.sequential import execute_with_retry

result = await execute_with_retry(
    task=scan_task,
    max_retries=3,
    backoff_seconds=2,
    retryable_exceptions=[ConnectionError, TimeoutError],
)
```

### Circuit Breaker

```python
from securAIty.orchestrator.policy_engine import CircuitBreaker

breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=30,
    half_open_requests=3,
)

async with breaker.context():
    result = await agent.execute(task)
```

## References

- [Enterprise Integration Patterns](https://www.enterpriseintegrationpatterns.com/)
- [NATS Request-Reply Pattern](https://docs.nats.io/nats-concepts/core-nats/request-reply)
- [Orchestration vs Choreography](https://microservices.io/patterns/data/saga.html)
- [Chain of Responsibility Pattern](https://refactoring.guru/design-patterns/chain-of-responsibility)

## Related ADRs

- [ADR-001: Event-Driven Architecture](001-event-driven-architecture.md)
- [ADR-003: Security Model](003-security-model.md)
- [ADR-005: Python Async Design](005-python-async-design.md)

---

&copy; 2026 CertifiedSlop. All rights reserved.
