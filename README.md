[![rebol-postgresql](https://github.com/user-attachments/assets/01be60b4-d2c3-4bb3-9718-11f4635a6209)](https://github.com/Oldes/Rebol-Postgres)

[![Rebol-Postgres CI](https://github.com/Oldes/Rebol-Postgres/actions/workflows/main.yml/badge.svg)](https://github.com/Oldes/Rebol-Postgres/actions/workflows/main.yml)
[![Gitter](https://badges.gitter.im/rebol3/community.svg)](https://gitter.im/rebol3/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# Rebol/Postgres


[PostgreSQL](https://www.postgresql.org/) protocol scheme for [Rebol3](https://github.com/Siskin-framework/Rebol)

Current state of the scheme is under development and may be changed in any moment.

## Usage

Open a connection using the `postgres://` scheme.

```rebol
pgsql: import %postgres.reb

; user/pass are taken from the URL, database is taken from the URL path:
pg: open postgres://postgres:password@localhost/postgres

res: write pg "SELECT current_user, current_database();"
probe res/rows
probe res/columns
print res/command-tag

close pg
```

### Error handling

On protocol/query errors `write` raises an error whose argument is a `map!` of server error fields
(including `sql-state`, `message`, `detail`, `hint`, etc. when present). The same map is also
available on the port as `pg/extra/last-error`.

```rebol
err: try [write pg {SELECT * FROM nonexistingtable;}]
if error? :err [
    probe err/arg1           ; map! with sql-state, message, ...
    probe pg/extra/last-error
]
```

### `write` result

`write` returns a `map!` with these keys:

- `rows`: block of row values (currently text-decoded)
- `columns`: block of column metadata maps (name, type oid, etc.)
- `command-tag`: command completion tag (e.g. `"SELECT 1"`)
- `notices`: notices received during the query
- `runtime`: collected runtime parameters (`ParameterStatus`)

## Examples and tests

For a fuller usage example (DDL/DML + error cases) see the test script: [`ci-test.r3`](ci-test.r3).
