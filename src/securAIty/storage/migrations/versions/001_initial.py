"""Initial migration for securAIty storage layer

Revision ID: 001_initial
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create enums first
    op.execute("""
        CREATE TYPE event_type_enum AS ENUM (
            'authentication_failure', 'authentication_success',
            'authorization_failure', 'data_access', 'data_modification',
            'system_error', 'configuration_change', 'threat_detected',
            'policy_violation', 'custom'
        )
    """)
    
    op.execute("""
        CREATE TYPE severity_level_enum AS ENUM (
            'low', 'medium', 'high', 'critical'
        )
    """)
    
    op.execute("""
        CREATE TYPE incident_status_enum AS ENUM (
            'open', 'investigating', 'contained', 'resolved', 'closed', 'escalated'
        )
    """)
    
    op.execute("""
        CREATE TYPE incident_severity_enum AS ENUM (
            'low', 'medium', 'high', 'critical'
        )
    """)
    
    op.execute("""
        CREATE TYPE incident_priority_enum AS ENUM (
            'p1', 'p2', 'p3', 'p4'
        )
    """)
    
    op.execute("""
        CREATE TYPE agent_type_enum AS ENUM (
            'detector', 'analyzer', 'responder', 'collector', 'enricher', 'custom'
        )
    """)
    
    op.execute("""
        CREATE TYPE agent_status_enum AS ENUM (
            'idle', 'running', 'busy', 'paused', 'error', 'stopped', 'unreachable'
        )
    """)
    
    op.execute("""
        CREATE TYPE audit_action_type_enum AS ENUM (
            'create', 'read', 'update', 'delete', 'execute', 'access',
            'modify', 'configure', 'authenticate', 'authorize',
            'export', 'import', 'custom'
        )
    """)
    
    op.execute("""
        CREATE TYPE audit_status_enum AS ENUM (
            'success', 'failure', 'pending', 'partial'
        )
    """)

    # Security Events table
    op.create_table(
        'security_events',
        sa.Column('event_id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('event_type', sa.Enum(name='event_type_enum'), nullable=False),
        sa.Column('severity', sa.Enum(name='severity_level_enum'), nullable=False),
        sa.Column('source', sa.String(255), nullable=False),
        sa.Column('title', sa.String(500), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('processed', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('correlation_id', sa.String(255), nullable=True),
        sa.Column('actor_id', sa.String(255), nullable=True),
        sa.Column('resource_id', sa.String(255), nullable=True),
        sa.Column('resource_type', sa.String(255), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('event_id'),
    )
    op.create_index('ix_security_events_event_type', 'security_events', ['event_type'])
    op.create_index('ix_security_events_severity', 'security_events', ['severity'])
    op.create_index('ix_security_events_source', 'security_events', ['source'])
    op.create_index('ix_security_events_timestamp', 'security_events', ['timestamp'])
    op.create_index('ix_security_events_processed', 'security_events', ['processed'])
    op.create_index('ix_security_events_correlation_id', 'security_events', ['correlation_id'])
    op.create_index('ix_security_events_actor_id', 'security_events', ['actor_id'])
    op.create_index('idx_security_events_composite', 'security_events', ['event_type', 'severity', 'timestamp'])
    op.create_index('idx_security_events_actor_timestamp', 'security_events', ['actor_id', 'timestamp'])
    op.create_index('idx_security_events_resource', 'security_events', ['resource_type', 'resource_id'])

    # Incidents table
    op.create_table(
        'incidents',
        sa.Column('incident_id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.Enum(name='incident_severity_enum'), nullable=False),
        sa.Column('status', sa.Enum(name='incident_status_enum'), nullable=False, server_default="'open'"),
        sa.Column('priority', sa.Enum(name='incident_priority_enum'), nullable=False, server_default="'p3'"),
        sa.Column('timeline', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('assigned_to', sa.String(255), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('contained_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('root_cause', sa.Text(), nullable=True),
        sa.Column('resolution', sa.Text(), nullable=True),
        sa.Column('related_event_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('external_id', sa.String(255), nullable=True),
        sa.Column('source_system', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('incident_id'),
        sa.UniqueConstraint('external_id'),
    )
    op.create_index('ix_incidents_severity', 'incidents', ['severity'])
    op.create_index('ix_incidents_status', 'incidents', ['status'])
    op.create_index('ix_incidents_assigned_to', 'incidents', ['assigned_to'])
    op.create_index('ix_incidents_external_id', 'incidents', ['external_id'])
    op.create_index('idx_incidents_status_severity', 'incidents', ['status', 'severity'])
    op.create_index('idx_incidents_detected_at', 'incidents', ['detected_at'])
    op.create_index('idx_incidents_assigned', 'incidents', ['assigned_to', 'status'])

    # Incident Notes table
    op.create_table(
        'incident_notes',
        sa.Column('note_id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('incident_id', sa.BigInteger(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('author', sa.String(255), nullable=False),
        sa.Column('is_internal', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('note_id'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.incident_id'], ondelete='CASCADE'),
    )
    op.create_index('ix_incident_notes_incident_id', 'incident_notes', ['incident_id'])
    op.create_index('idx_incident_notes_incident', 'incident_notes', ['incident_id', 'created_at'])

    # Agents table
    op.create_table(
        'agents',
        sa.Column('agent_id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('agent_type', sa.Enum(name='agent_type_enum'), nullable=False),
        sa.Column('status', sa.Enum(name='agent_status_enum'), nullable=False, server_default="'idle'"),
        sa.Column('version', sa.String(50), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('capabilities', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('last_heartbeat', sa.DateTime(timezone=True), nullable=True),
        sa.Column('registered_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('last_error_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('tasks_completed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('tasks_failed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('host', sa.String(255), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('endpoint', sa.String(500), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('agent_id'),
        sa.UniqueConstraint('name'),
    )
    op.create_index('ix_agents_name', 'agents', ['name'])
    op.create_index('ix_agents_agent_type', 'agents', ['agent_type'])
    op.create_index('ix_agents_status', 'agents', ['status'])
    op.create_index('ix_agents_last_heartbeat', 'agents', ['last_heartbeat'])
    op.create_index('idx_agents_type_status', 'agents', ['agent_type', 'status'])
    op.create_index('idx_agents_heartbeat', 'agents', ['last_heartbeat'])

    # Agent Tasks table
    op.create_table(
        'agent_tasks',
        sa.Column('task_id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('agent_id', sa.BigInteger(), nullable=False),
        sa.Column('task_type', sa.String(255), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default="'pending'"),
        sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('result', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('timeout_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('task_id'),
    )
    op.create_index('ix_agent_tasks_agent_id', 'agent_tasks', ['agent_id'])
    op.create_index('ix_agent_tasks_task_type', 'agent_tasks', ['task_type'])
    op.create_index('ix_agent_tasks_status', 'agent_tasks', ['status'])
    op.create_index('idx_agent_tasks_agent_status', 'agent_tasks', ['agent_id', 'status'])

    # Audit Logs table
    op.create_table(
        'audit_logs',
        sa.Column('log_id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('action', sa.Enum(name='audit_action_type_enum'), nullable=False),
        sa.Column('actor', sa.String(255), nullable=False),
        sa.Column('actor_type', sa.String(100), nullable=False, server_default="'user'"),
        sa.Column('status', sa.Enum(name='audit_status_enum'), nullable=False, server_default="'success'"),
        sa.Column('resource_type', sa.String(255), nullable=False),
        sa.Column('resource_id', sa.String(255), nullable=True),
        sa.Column('resource_name', sa.String(500), nullable=True),
        sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('changes', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('session_id', sa.String(255), nullable=True),
        sa.Column('request_id', sa.String(255), nullable=True),
        sa.Column('tenant_id', sa.String(255), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('log_id'),
    )
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_actor', 'audit_logs', ['actor'])
    op.create_index('ix_audit_logs_status', 'audit_logs', ['status'])
    op.create_index('ix_audit_logs_resource_type', 'audit_logs', ['resource_type'])
    op.create_index('ix_audit_logs_resource_id', 'audit_logs', ['resource_id'])
    op.create_index('ix_audit_logs_session_id', 'audit_logs', ['session_id'])
    op.create_index('ix_audit_logs_request_id', 'audit_logs', ['request_id'])
    op.create_index('ix_audit_logs_tenant_id', 'audit_logs', ['tenant_id'])
    op.create_index('ix_audit_logs_timestamp', 'audit_logs', ['timestamp'])
    op.create_index('idx_audit_logs_actor_action', 'audit_logs', ['actor', 'action'])
    op.create_index('idx_audit_logs_resource', 'audit_logs', ['resource_type', 'resource_id'])
    op.create_index('idx_audit_logs_timestamp_status', 'audit_logs', ['timestamp', 'status'])
    op.create_index('idx_audit_logs_tenant', 'audit_logs', ['tenant_id', 'timestamp'])


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('agent_tasks')
    op.drop_table('agents')
    op.drop_table('incident_notes')
    op.drop_table('incidents')
    op.drop_table('security_events')
    
    op.execute('DROP TYPE audit_status_enum')
    op.execute('DROP TYPE audit_action_type_enum')
    op.execute('DROP TYPE agent_status_enum')
    op.execute('DROP TYPE agent_type_enum')
    op.execute('DROP TYPE incident_priority_enum')
    op.execute('DROP TYPE incident_severity_enum')
    op.execute('DROP TYPE incident_status_enum')
    op.execute('DROP TYPE severity_level_enum')
    op.execute('DROP TYPE event_type_enum')
