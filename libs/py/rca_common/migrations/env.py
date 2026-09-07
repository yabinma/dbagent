from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from rca_common.db.models import Base
from rca_common.envcompat import reject_legacy_env

# design.md §11.2.3 C.3: fail closed on a legacy RCA_* name at module scope,
# before alembic reads any configuration.
reject_legacy_env()

config = context.config

if config.config_file_name is not None:
    # `disable_existing_loggers` defaults to True, which would silence every
    # logger the *calling* process had already created — migrations run
    # in-process (install hooks, and the functional/e2e tiers), so alembic's
    # own logging config must not reach outside alembic.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata

db_url = os.environ.get("DBAGENT_PG_DSN")
if db_url:
    config.set_main_option("sqlalchemy.url", db_url)


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
