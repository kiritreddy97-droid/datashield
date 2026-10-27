"""initial schema

Revision ID: 0001
Revises: 
Create Date: 2026-10-26
"""
import sqlalchemy as sa
from alembic import op

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('audit_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('person_id', sa.Integer(), nullable=True),
    sa.Column('action', sa.String(length=40), nullable=False),
    sa.Column('subject_type', sa.String(length=20), nullable=True),
    sa.Column('subject_id', sa.Integer(), nullable=True),
    sa.Column('detail', sa.String(length=300), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_events'))
    )
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_events_person_id'), ['person_id'], unique=False)

    op.create_table('people',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('full_name', sa.Text(), nullable=True),
    sa.Column('email', sa.Text(), nullable=True),
    sa.Column('email_hash', sa.String(length=64), nullable=True),
    sa.Column('email_verified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('phone', sa.Text(), nullable=True),
    sa.Column('phone_hash', sa.String(length=64), nullable=True),
    sa.Column('phone_verified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('scan_consent_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('scan_consent_revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_people'))
    )
    with op.batch_alter_table('people', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_people_email_hash'), ['email_hash'], unique=True)
        batch_op.create_index(batch_op.f('ix_people_phone_hash'), ['phone_hash'], unique=True)

    op.create_table('findings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('person_id', sa.Integer(), nullable=False),
    sa.Column('source', sa.String(length=120), nullable=False),
    sa.Column('url', sa.Text(), nullable=False),
    sa.Column('data_types', sa.String(length=200), nullable=False),
    sa.Column('contact_email', sa.String(length=200), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('found_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['person_id'], ['people.id'], name=op.f('fk_findings_person_id_people'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_findings'))
    )
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_findings_person_id'), ['person_id'], unique=False)

    op.create_table('otp_challenges',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('channel', sa.String(length=10), nullable=False),
    sa.Column('purpose', sa.String(length=10), nullable=False),
    sa.Column('identifier_hash', sa.String(length=64), nullable=False),
    sa.Column('person_id', sa.Integer(), nullable=True),
    sa.Column('code_hash', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['person_id'], ['people.id'], name=op.f('fk_otp_challenges_person_id_people'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_otp_challenges'))
    )
    with op.batch_alter_table('otp_challenges', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_otp_challenges_identifier_hash'), ['identifier_hash'], unique=False)

    op.create_table('removal_consents',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('finding_id', sa.Integer(), nullable=False),
    sa.Column('granted_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], name=op.f('fk_removal_consents_finding_id_findings'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_removal_consents')),
    sa.UniqueConstraint('finding_id', name=op.f('uq_removal_consents_finding_id'))
    )
    op.create_table('removal_requests',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('finding_id', sa.Integer(), nullable=False),
    sa.Column('kind', sa.String(length=20), nullable=False),
    sa.Column('state', sa.String(length=20), nullable=False),
    sa.Column('body', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('follow_up_due', sa.DateTime(timezone=True), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('last_error', sa.String(length=300), nullable=True),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], name=op.f('fk_removal_requests_finding_id_findings'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_removal_requests'))
    )
    with op.batch_alter_table('removal_requests', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_removal_requests_finding_id'), ['finding_id'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('removal_requests', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_removal_requests_finding_id'))

    op.drop_table('removal_requests')
    op.drop_table('removal_consents')
    with op.batch_alter_table('otp_challenges', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_otp_challenges_identifier_hash'))

    op.drop_table('otp_challenges')
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_findings_person_id'))

    op.drop_table('findings')
    with op.batch_alter_table('people', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_people_phone_hash'))
        batch_op.drop_index(batch_op.f('ix_people_email_hash'))

    op.drop_table('people')
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_events_person_id'))

    op.drop_table('audit_events')
