"""Bounded cleanup retry for generated fixture readers, never production effects."""

import re
import time


def drop_fixture_reader(connection, role):
    import psycopg
    from psycopg import sql

    if (connection.autocommit is not True or type(role) is not str
            or not re.fullmatch(r"(?:review_reader_|sova_review_)[0-9a-f]{32}", role)):
        raise ValueError("Owned generated fixture reader and autocommit connection required")
    for attempt in range(3):
        try:
            # Both catalog changes roll back on deadlock; do not replay the test,
            # application operation, or any other SQL error.
            with connection.transaction():
                connection.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                connection.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
            return
        except psycopg.errors.DeadlockDetected:
            if attempt == 2:
                raise
            time.sleep(0.05 * (attempt + 1))
