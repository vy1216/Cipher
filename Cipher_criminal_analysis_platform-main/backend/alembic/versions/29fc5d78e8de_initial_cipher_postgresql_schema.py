"""initial_cipher_postgresql_schema

Revision ID: 29fc5d78e8de
Revises: 
Create Date: 2026-09-15 15:22:30.086221

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '29fc5d78e8de'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()

    if 'review_queue' in tables:
        op.drop_table('review_queue')

    # Helper to check if column exists
    def col_exists(table, col):
        if table not in tables:
            return False
        return any(c['name'] == col for c in inspector.get_columns(table))

    if not col_exists('documents', 'error_message'):
        op.add_column('documents', sa.Column('error_message', sa.Text(), nullable=True))
    if not col_exists('documents', 'file_size_bytes'):
        op.add_column('documents', sa.Column('file_size_bytes', sa.Integer(), nullable=True))
    if not col_exists('documents', 'mime_type'):
        op.add_column('documents', sa.Column('mime_type', sa.String(length=100), nullable=True))
    if not col_exists('entities', 'merged_into_id'):
        op.add_column('entities', sa.Column('merged_into_id', sa.Integer(), nullable=True))
    if not col_exists('entities', 'reviewed_by'):
        op.add_column('entities', sa.Column('reviewed_by', sa.Integer(), nullable=True))
    if not col_exists('entities', 'reviewed_at'):
        op.add_column('entities', sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True))
    if not col_exists('entities', 'review_reason'):
        op.add_column('entities', sa.Column('review_reason', sa.Text(), nullable=True))

    if not col_exists('relationships', 'reviewed_by'):
        op.add_column('relationships', sa.Column('reviewed_by', sa.Integer(), nullable=True))
    if not col_exists('relationships', 'reviewed_at'):
        op.add_column('relationships', sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True))
    if not col_exists('relationships', 'review_reason'):
        op.add_column('relationships', sa.Column('review_reason', sa.Text(), nullable=True))

    dialect_name = bind.dialect.name
    if dialect_name != 'sqlite':
        op.alter_column('entities', 'id',
                   existing_type=sa.INTEGER(),
                   nullable=False,
                   autoincrement=True)
        op.alter_column('entities', 'entity_type',
                   existing_type=sa.TEXT(),
                   type_=sa.String(length=50),
                   existing_nullable=False)
        op.alter_column('entities', 'label',
                   existing_type=sa.TEXT(),
                   type_=sa.String(length=200),
                   existing_nullable=False)
        op.alter_column('entities', 'extraction_method',
                   existing_type=sa.TEXT(),
                   type_=sa.String(length=50),
                   existing_nullable=True,
                   existing_server_default=sa.text("'AI_EXTRACTION'"))
        op.alter_column('entities', 'confidence_score',
                   existing_type=sa.REAL(),
                   type_=sa.Float(),
                   nullable=False,
                   existing_server_default=sa.text('(0.95)'))
        op.alter_column('entities', 'verification_status',
                   existing_type=sa.TEXT(),
                   type_=sa.String(length=30),
                   nullable=False,
                   existing_server_default=sa.text("'verified'"))
        op.alter_column('entities', 'latitude',
                   existing_type=sa.REAL(),
                   type_=sa.Float(),
                   existing_nullable=True)
        op.alter_column('entities', 'longitude',
                   existing_type=sa.REAL(),
                   type_=sa.Float(),
                   existing_nullable=True)
        op.alter_column('entities', 'created_at',
                   existing_type=sa.TEXT(),
                   type_=sa.DateTime(timezone=True),
                   existing_nullable=True,
                   existing_server_default=sa.text("(datetime('now'))"))
        op.create_index(op.f('ix_entities_case_id'), 'entities', ['case_id'], unique=False)
        op.create_index(op.f('ix_entities_id'), 'entities', ['id'], unique=False)
        op.create_foreign_key(None, 'entities', 'users', ['reviewed_by'], ['id'])
        op.create_foreign_key(None, 'entities', 'entities', ['merged_into_id'], ['id'])
        op.create_foreign_key(None, 'entities', 'cases', ['case_id'], ['id'])
        op.alter_column('locations', 'id',
                   existing_type=sa.INTEGER(),
                   nullable=False,
                   autoincrement=True)
        op.alter_column('locations', 'label',
                   existing_type=sa.TEXT(),
                   type_=sa.String(length=200),
                   existing_nullable=False)
        op.alter_column('locations', 'latitude',
                   existing_type=sa.REAL(),
                   type_=sa.Float(),
                   existing_nullable=False)
        op.alter_column('locations', 'longitude',
                   existing_type=sa.REAL(),
                   type_=sa.Float(),
                   existing_nullable=False)
        op.alter_column('locations', 'location_type',
                   existing_type=sa.TEXT(),
                   type_=sa.String(length=50),
                   nullable=False,
                   existing_server_default=sa.text("'sighting'"))
        op.alter_column('locations', 'verification_status',
                   existing_type=sa.TEXT(),
                   type_=sa.String(length=30),
                   nullable=False,
                   existing_server_default=sa.text("'verified'"))
        op.alter_column('locations', 'created_at',
                   existing_type=sa.TEXT(),
                   type_=sa.DateTime(timezone=True),
                   existing_nullable=True,
                   existing_server_default=sa.text("(datetime('now'))"))
        op.create_index(op.f('ix_locations_case_id'), 'locations', ['case_id'], unique=False)
        op.create_index(op.f('ix_locations_id'), 'locations', ['id'], unique=False)
        op.create_foreign_key(None, 'locations', 'cases', ['case_id'], ['id'])
        op.create_foreign_key(None, 'locations', 'entities', ['entity_id'], ['id'])
        if col_exists('locations', 'event_timestamp'):
            op.drop_column('locations', 'event_timestamp')
        if col_exists('locations', 'source_document_id'):
            op.drop_column('locations', 'source_document_id')
        op.alter_column('relationships', 'id',
                   existing_type=sa.INTEGER(),
                   nullable=False,
                   autoincrement=True)
        op.alter_column('relationships', 'relationship_type',
                   existing_type=sa.TEXT(),
                   type_=sa.String(length=100),
                   existing_nullable=False)
        op.alter_column('relationships', 'confidence_score',
                   existing_type=sa.REAL(),
                   type_=sa.Float(),
                   nullable=False,
                   existing_server_default=sa.text('(0.90)'))
        op.alter_column('relationships', 'verification_status',
                   existing_type=sa.TEXT(),
                   type_=sa.String(length=30),
                   nullable=False,
                   existing_server_default=sa.text("'verified'"))
        op.alter_column('relationships', 'created_at',
                   existing_type=sa.TEXT(),
                   type_=sa.DateTime(timezone=True),
                   existing_nullable=True,
                   existing_server_default=sa.text("(datetime('now'))"))
        op.create_index(op.f('ix_relationships_case_id'), 'relationships', ['case_id'], unique=False)
        op.create_index(op.f('ix_relationships_id'), 'relationships', ['id'], unique=False)
        op.create_foreign_key(None, 'relationships', 'users', ['reviewed_by'], ['id'])
        op.create_foreign_key(None, 'relationships', 'entities', ['source_entity_id'], ['id'])
        op.create_foreign_key(None, 'relationships', 'entities', ['target_entity_id'], ['id'])
        op.create_foreign_key(None, 'relationships', 'cases', ['case_id'], ['id'])
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    # WARNING: constraint name is None; this directive will fail as
    # rendered.  Add a name, or use a naming convention; see
    # https://alembic.sqlalchemy.org/en/latest/naming.html
    op.drop_constraint(None, 'relationships', type_='foreignkey')
    # WARNING: constraint name is None; this directive will fail as
    # rendered.  Add a name, or use a naming convention; see
    # https://alembic.sqlalchemy.org/en/latest/naming.html
    op.drop_constraint(None, 'relationships', type_='foreignkey')
    # WARNING: constraint name is None; this directive will fail as
    # rendered.  Add a name, or use a naming convention; see
    # https://alembic.sqlalchemy.org/en/latest/naming.html
    op.drop_constraint(None, 'relationships', type_='foreignkey')
    # WARNING: constraint name is None; this directive will fail as
    # rendered.  Add a name, or use a naming convention; see
    # https://alembic.sqlalchemy.org/en/latest/naming.html
    op.drop_constraint(None, 'relationships', type_='foreignkey')
    op.drop_index(op.f('ix_relationships_id'), table_name='relationships')
    op.drop_index(op.f('ix_relationships_case_id'), table_name='relationships')
    op.alter_column('relationships', 'created_at',
               existing_type=sa.DateTime(timezone=True),
               type_=sa.TEXT(),
               existing_nullable=True,
               existing_server_default=sa.text("(datetime('now'))"))
    op.alter_column('relationships', 'verification_status',
               existing_type=sa.String(length=30),
               type_=sa.TEXT(),
               nullable=True,
               existing_server_default=sa.text("'verified'"))
    op.alter_column('relationships', 'confidence_score',
               existing_type=sa.Float(),
               type_=sa.REAL(),
               nullable=True,
               existing_server_default=sa.text('(0.90)'))
    op.alter_column('relationships', 'relationship_type',
               existing_type=sa.String(length=100),
               type_=sa.TEXT(),
               existing_nullable=False)
    op.alter_column('relationships', 'id',
               existing_type=sa.INTEGER(),
               nullable=True,
               autoincrement=True)
    op.drop_column('relationships', 'review_reason')
    op.drop_column('relationships', 'reviewed_at')
    op.drop_column('relationships', 'reviewed_by')
    op.add_column('locations', sa.Column('source_document_id', sa.INTEGER(), nullable=True))
    op.add_column('locations', sa.Column('event_timestamp', sa.TEXT(), server_default=sa.text("(datetime('now'))"), nullable=True))
    # WARNING: constraint name is None; this directive will fail as
    # rendered.  Add a name, or use a naming convention; see
    # https://alembic.sqlalchemy.org/en/latest/naming.html
    op.drop_constraint(None, 'locations', type_='foreignkey')
    # WARNING: constraint name is None; this directive will fail as
    # rendered.  Add a name, or use a naming convention; see
    # https://alembic.sqlalchemy.org/en/latest/naming.html
    op.drop_constraint(None, 'locations', type_='foreignkey')
    op.drop_index(op.f('ix_locations_id'), table_name='locations')
    op.drop_index(op.f('ix_locations_case_id'), table_name='locations')
    op.alter_column('locations', 'created_at',
               existing_type=sa.DateTime(timezone=True),
               type_=sa.TEXT(),
               existing_nullable=True,
               existing_server_default=sa.text("(datetime('now'))"))
    op.alter_column('locations', 'verification_status',
               existing_type=sa.String(length=30),
               type_=sa.TEXT(),
               nullable=True,
               existing_server_default=sa.text("'verified'"))
    op.alter_column('locations', 'location_type',
               existing_type=sa.String(length=50),
               type_=sa.TEXT(),
               nullable=True,
               existing_server_default=sa.text("'sighting'"))
    op.alter_column('locations', 'longitude',
               existing_type=sa.Float(),
               type_=sa.REAL(),
               existing_nullable=False)
    op.alter_column('locations', 'latitude',
               existing_type=sa.Float(),
               type_=sa.REAL(),
               existing_nullable=False)
    op.alter_column('locations', 'label',
               existing_type=sa.String(length=200),
               type_=sa.TEXT(),
               existing_nullable=False)
    op.alter_column('locations', 'id',
               existing_type=sa.INTEGER(),
               nullable=True,
               autoincrement=True)
    # WARNING: constraint name is None; this directive will fail as
    # rendered.  Add a name, or use a naming convention; see
    # https://alembic.sqlalchemy.org/en/latest/naming.html
    op.drop_constraint(None, 'entities', type_='foreignkey')
    # WARNING: constraint name is None; this directive will fail as
    # rendered.  Add a name, or use a naming convention; see
    # https://alembic.sqlalchemy.org/en/latest/naming.html
    op.drop_constraint(None, 'entities', type_='foreignkey')
    # WARNING: constraint name is None; this directive will fail as
    # rendered.  Add a name, or use a naming convention; see
    # https://alembic.sqlalchemy.org/en/latest/naming.html
    op.drop_constraint(None, 'entities', type_='foreignkey')
    op.drop_index(op.f('ix_entities_id'), table_name='entities')
    op.drop_index(op.f('ix_entities_case_id'), table_name='entities')
    op.alter_column('entities', 'created_at',
               existing_type=sa.DateTime(timezone=True),
               type_=sa.TEXT(),
               existing_nullable=True,
               existing_server_default=sa.text("(datetime('now'))"))
    op.alter_column('entities', 'longitude',
               existing_type=sa.Float(),
               type_=sa.REAL(),
               existing_nullable=True)
    op.alter_column('entities', 'latitude',
               existing_type=sa.Float(),
               type_=sa.REAL(),
               existing_nullable=True)
    op.alter_column('entities', 'verification_status',
               existing_type=sa.String(length=30),
               type_=sa.TEXT(),
               nullable=True,
               existing_server_default=sa.text("'verified'"))
    op.alter_column('entities', 'confidence_score',
               existing_type=sa.Float(),
               type_=sa.REAL(),
               nullable=True,
               existing_server_default=sa.text('(0.95)'))
    op.alter_column('entities', 'extraction_method',
               existing_type=sa.String(length=50),
               type_=sa.TEXT(),
               existing_nullable=True,
               existing_server_default=sa.text("'AI_EXTRACTION'"))
    op.alter_column('entities', 'label',
               existing_type=sa.String(length=200),
               type_=sa.TEXT(),
               existing_nullable=False)
    op.alter_column('entities', 'entity_type',
               existing_type=sa.String(length=50),
               type_=sa.TEXT(),
               existing_nullable=False)
    op.alter_column('entities', 'id',
               existing_type=sa.INTEGER(),
               nullable=True,
               autoincrement=True)
    op.drop_column('entities', 'review_reason')
    op.drop_column('entities', 'reviewed_at')
    op.drop_column('entities', 'reviewed_by')
    op.drop_column('entities', 'merged_into_id')
    op.drop_column('documents', 'mime_type')
    op.drop_column('documents', 'file_size_bytes')
    op.drop_column('documents', 'error_message')
    op.create_table('review_queue',
    sa.Column('id', sa.INTEGER(), nullable=True),
    sa.Column('case_id', sa.INTEGER(), nullable=False),
    sa.Column('item_type', sa.TEXT(), nullable=False),
    sa.Column('item_id', sa.INTEGER(), nullable=False),
    sa.Column('confidence_score', sa.REAL(), server_default=sa.text('(0.85)'), nullable=True),
    sa.Column('status', sa.TEXT(), server_default=sa.text("'PENDING'"), nullable=True),
    sa.Column('reviewed_by', sa.INTEGER(), nullable=True),
    sa.Column('reviewed_at', sa.TEXT(), nullable=True),
    sa.Column('created_at', sa.TEXT(), server_default=sa.text("(datetime('now'))"), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###
