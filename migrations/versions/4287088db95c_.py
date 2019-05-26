"""empty message

Revision ID: 4287088db95c
Revises: ba3a9034cd54
Create Date: 2019-05-26 19:37:14.264369

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4287088db95c'
down_revision = 'ba3a9034cd54'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('revoked_token',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('jti', sa.String(length=120), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    op.create_index(op.f('ix_revoked_token_jti'), 'revoked_token', ['jti'], unique=False)
    op.create_table('task',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('text', sa.String(length=64), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    op.create_table('todo_list',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=32), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=32), nullable=False),
    sa.Column('password', sa.String(length=128), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('tasks',
    sa.Column('todo_list_id', sa.Integer(), nullable=False),
    sa.Column('task_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['task_id'], ['task.id'], ),
    sa.ForeignKeyConstraint(['todo_list_id'], ['todo_list.id'], ),
    sa.PrimaryKeyConstraint('todo_list_id', 'task_id')
    )
    op.create_table('todo_lists',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('todo_list_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['todo_list_id'], ['todo_list.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('user_id', 'todo_list_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('todo_lists')
    op.drop_table('tasks')
    op.drop_table('user')
    op.drop_table('todo_list')
    op.drop_table('task')
    op.drop_index(op.f('ix_revoked_token_jti'), table_name='revoked_token')
    op.drop_table('revoked_token')
    # ### end Alembic commands ###
