# ADR-005: Python Async/Await Design

## Status

Accepted

## Date

2026-03-26

## Context

The securAIty platform requires high-throughput, low-latency processing for security operations:

- Concurrent agent task execution (100+ simultaneous tasks)
- Non-blocking I/O for NATS, database, and Vault connections
- Real-time event streaming and processing
- Efficient resource utilization under load

### Performance Requirements

| Metric | Target | Rationale |
|--------|--------|-----------|
| Event Processing Latency | < 10ms | Real-time threat response |
| Task Execution Throughput | 1000+ tasks/minute | Handle security scan bursts |
| Connection Concurrency | 100+ concurrent connections | Support agent fleet |
| Memory Usage | < 512MB per agent | Container resource limits |

### Synchronous vs Asynchronous

| Operation | Sync Time | Async Time | Impact |
|-----------|-----------|------------|--------|
| NATS Publish | 5ms (blocked) | 0.1ms (yield) | 50x improvement |
| Database Query | 50ms (blocked) | 0.5ms (yield) | 100x improvement |
| File Scan (I/O) | 100ms (blocked) | 1ms (yield) | 100x improvement |
| HTTP Request | 200ms (blocked) | 1ms (yield) | 200x improvement |

## Decision

We adopt **async/await throughout the codebase** using Python 3.12+'s asyncio framework.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Async Architecture                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Event Loop (uvloop)                      │   │
│  │  ┌────────────────────────────────────────────────┐  │   │
│  │  │              Task Scheduler                     │  │   │
│  │  └────────────────────────────────────────────────┘  │   │
│  │          │              │              │              │   │
│  │          ▼              ▼              ▼              │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐     │   │
│  │  │  Agent 1   │  │  Agent 2   │  │  Agent N   │     │   │
│  │  │  (async)   │  │  (async)   │  │  (async)   │     │   │
│  │  └────────────┘  └────────────┘  └────────────┘     │   │
│  │          │              │              │              │   │
│  │          └──────────────┼──────────────┘              │   │
│  │                         │                             │   │
│  │          ┌──────────────▼──────────────┐             │   │
│  │          │    Async I/O Multiplexer    │             │   │
│  │          └──────────────┬──────────────┘             │   │
│  └─────────────────────────┼─────────────────────────────┘   │
│                            │                                  │
│         ┌──────────────────┼──────────────────┐              │
│         │                  │                  │              │
│  ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐       │
│  │   NATS      │   │  PostgreSQL │   │   Vault     │       │
│  │  (async)    │   │  (asyncpg)  │   │  (httpx)    │       │
│  └─────────────┘   └─────────────┘   └─────────────┘       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Async Patterns

#### Pattern 1: Concurrent Task Execution

```python
import asyncio
from typing import List

async def execute_agent_tasks(
    tasks: List[TaskRequest],
    timeout: float = 300.0,
) -> List[TaskResult]:
    """Execute multiple agent tasks concurrently."""
    
    async def execute_with_timeout(task: TaskRequest) -> TaskResult:
        try:
            agent = get_agent_for_task(task.capability)
            return await asyncio.wait_for(
                agent.execute(task),
                timeout=task.timeout or timeout,
            )
        except asyncio.TimeoutError:
            return TaskResult.failure(
                task_id=task.task_id,
                error_message=f"Task timed out after {timeout}s",
            )
        except Exception as e:
            return TaskResult.failure(
                task_id=task.task_id,
                error_message=str(e),
            )
    
    # Execute all tasks concurrently
    results = await asyncio.gather(
        *[execute_with_timeout(task) for task in tasks],
        return_exceptions=True,
    )
    
    return results
```

#### Pattern 2: Async Context Managers

```python
from contextlib import asynccontextmanager

class DatabaseSession:
    """Async context manager for database sessions."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.session = None
    
    async def __aenter__(self) -> AsyncSession:
        await self.db_manager.initialize()
        self.session = await self.db_manager.session()
        return self.session
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
        if exc_type is not None:
            await self.db_manager.rollback()

# Usage
async with DatabaseSession(db_manager) as session:
    agents = await session.query(AgentModel).all()
```

#### Pattern 3: Async Iterator for Streaming

```python
from typing import AsyncIterator

async def stream_security_events(
    event_bus: EventBus,
    event_types: List[str],
) -> AsyncIterator[SecurityEvent]:
    """Stream security events as async iterator."""
    
    queue = asyncio.Queue(maxsize=1000)
    
    async def event_handler(event: SecurityEvent):
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("Event queue full, dropping event")
    
    subscription_id = await event_bus.subscribe(
        event_types=event_types,
        handler=event_handler,
    )
    
    try:
        while True:
            event = await queue.get()
            yield event
            queue.task_done()
    finally:
        await event_bus.unsubscribe(subscription_id)

# Usage
async for event in stream_security_events(bus, ["THREAT_DETECTED"]):
    await process_event(event)
```

#### Pattern 4: Semaphore for Concurrency Control

```python
class AntivirusAgent(BaseAgent):
    """Agent with controlled concurrency."""
    
    MAX_CONCURRENT_SCANS = 10
    
    def __init__(self):
        super().__init__()
        self._scan_semaphore = asyncio.Semaphore(
            self.MAX_CONCURRENT_SCANS
        )
    
    async def scan_file(self, file_path: str) -> ScanResult:
        """Scan file with concurrency limiting."""
        async with self._scan_semaphore:
            # Only 10 scans can execute concurrently
            return await self._perform_scan(file_path)
```

#### Pattern 5: Task Group for Structured Concurrency

```python
async def perform_security_assessment(
    target: dict,
) -> AssessmentResult:
    """Perform comprehensive security assessment."""
    
    async with asyncio.TaskGroup() as tg:
        # All tasks run concurrently
        vuln_task = tg.create_task(
            pentester.vulnerability_scan(target)
        )
        malware_task = tg.create_task(
            antivirus.scan_directory(target["path"])
        )
        config_task = tg.create_task(
            engineer.audit_config(target["host"])
        )
    
    # All tasks completed (or one raised exception)
    vuln_results = vuln_task.result()
    malware_results = malware_task.result()
    config_results = config_task.result()
    
    return AssessmentResult(
        vulnerabilities=vuln_results,
        malware=malware_results,
        config_issues=config_results,
    )
```

### Library Selection

| Purpose | Library | Rationale |
|---------|---------|-----------|
| **Async Framework** | FastAPI | Native async support, auto-validation |
| **Database Driver** | asyncpg | Fastest PostgreSQL async driver |
| **ORM** | SQLAlchemy 2.0 | Async session support, type safety |
| **HTTP Client** | httpx | Async HTTP/2 support |
| **Message Queue** | nats-py | Official NATS async client |
| **Event Loop** | uvloop | 2-4x faster than default loop |

### Error Handling

```python
from functools import wraps

def async_retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    exceptions: tuple = (Exception,),
):
    """Decorator for async retry logic."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        await asyncio.sleep(delay * (2 ** attempt))
            raise last_exception
        return wrapper
    return decorator

@async_retry(
    max_attempts=3,
    delay=0.5,
    exceptions=(ConnectionError, TimeoutError),
)
async def connect_to_nats():
    return await nats.connect("nats://localhost:4222")
```

### Timeout Handling

```python
async def execute_with_timeout(
    coro,
    timeout: float,
    timeout_result: Any = None,
) -> Any:
    """Execute coroutine with timeout."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning(f"Operation timed out after {timeout}s")
        return timeout_result

# Usage
result = await execute_with_timeout(
    agent.execute(task),
    timeout=300.0,
    timeout_result=TaskResult.failure(task_id, "Timeout"),
)
```

## Implementation

### Event Loop Configuration

```python
import asyncio
import uvloop

def setup_event_loop():
    """Configure optimal event loop settings."""
    # Use uvloop for better performance
    uvloop.install()
    
    # Get event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # Configure debug mode (development only)
    if os.getenv("DEBUG"):
        loop.set_debug(True)
    
    return loop

# Application startup
loop = setup_event_loop()
try:
    loop.run_until_complete(main())
finally:
    loop.run_until_complete(loop.shutdown_asyncgens())
    loop.close()
```

### Async Application Factory

```python
from fastapi import FastAPI
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    await db_manager.initialize()
    await event_bus.connect()
    await vault_client.connect()
    
    for agent in agents:
        await agent.initialize()
    
    yield
    
    # Shutdown
    for agent in agents:
        await agent.shutdown()
    
    await event_bus.disconnect()
    await vault_client.disconnect()
    await db_manager.close()

app = FastAPI(lifespan=lifespan)
```

### Testing Async Code

```python
import pytest
import pytest_asyncio

@pytest_asyncio.fixture
async def db_session():
    """Async fixture for database session."""
    await db_manager.initialize()
    async with db_manager.session() as session:
        yield session
    await db_manager.close()

@pytest.mark.asyncio
async def test_agent_execution(db_session):
    """Test agent task execution."""
    agent = AntivirusAgent()
    await agent.initialize()
    
    task = TaskRequest(
        capability="scan_file",
        input_data={"file_path": "/tmp/test.exe"},
    )
    
    result = await agent.execute(task)
    
    assert result.success is True
    assert "threats_detected" in result.output_data
    
    await agent.shutdown()
```

## Consequences

### Positive

1. **Performance**: 10-100x improvement in I/O-bound operations
2. **Scalability**: Handle 1000+ concurrent connections efficiently
3. **Resource Efficiency**: Lower memory footprint than threading
4. **Responsiveness**: No blocking, system remains responsive under load
5. **Modern Python**: Leverages latest Python 3.12+ features

### Negative

1. **Complexity**: Async/await mental model differs from sync code
2. **Debugging**: Stack traces can be harder to follow
3. **Library Support**: Some libraries lack async implementations
4. **Testing**: Requires async test fixtures and patterns
5. **CPU-Bound Tasks**: No benefit for CPU-intensive operations

### Trade-offs

| Alternative | Why Not Selected |
|-------------|------------------|
| **Threading** | GIL limits, higher memory, context switch overhead |
| **Multiprocessing** | High memory overhead, complex IPC |
| **Sync + Workers** | Limited concurrency, blocking I/O |
| **Trio** | Smaller ecosystem, less mature than asyncio |

## Performance Benchmarks

### Throughput Comparison

| Pattern | Requests/sec | Latency (p99) | Memory |
|---------|-------------|---------------|--------|
| Sync Flask | 500 | 200ms | 256MB |
| Async FastAPI | 5000 | 20ms | 128MB |
| Async + uvloop | 8000 | 15ms | 128MB |

### Concurrency Scaling

```
Concurrent Connections vs Response Time:

Sync:     10 → 50ms    100 → 500ms    1000 → 5000ms
Async:    10 → 15ms    100 → 20ms     1000 → 25ms
```

## Best Practices

### DO

```python
# Use async context managers
async with get_session() as session:
    result = await session.execute(query)

# Use asyncio.gather for concurrent execution
results = await asyncio.gather(task1(), task2(), task3())

# Use asyncio.wait_for for timeouts
result = await asyncio.wait_for(coro, timeout=30.0)

# Use semaphores for concurrency limits
async with semaphore:
    await process()
```

### DON'T

```python
# Don't block the event loop
time.sleep(1)      # ❌ Blocks everything
await asyncio.sleep(1)  # ✅ Yields control

# Don't use synchronous I/O
with open("file.txt") as f:  # ❌ Blocking
    data = f.read()

async with aiofiles.open("file.txt") as f:  # ✅ Async
    data = await f.read()

# Don't catch Exception broadly
try:
    await operation()
except SpecificError as e:  # ✅ Specific
    handle(e)
```

## References

- [Python asyncio Documentation](https://docs.python.org/3/library/asyncio.html)
- [FastAPI Async Patterns](https://fastapi.tiangolo.com/async/)
- [SQLAlchemy Async ORM](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html)
- [uvloop Documentation](https://magic.io/blog/uvloop-blazing-fast-python-networking/)

## Related ADRs

- [ADR-001: Event-Driven Architecture](001-event-driven-architecture.md)
- [ADR-002: Agent Communication Patterns](002-agent-communication-patterns.md)
- [ADR-004: Storage Pattern](004-storage-pattern.md)
