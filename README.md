# Identity

Rust authentication service built with `salvo`, `sea-orm`, and `tera`.

## Run

```sh
cargo run
```

By default the app loads `config/development.yaml`.

Environment overrides:

- `APP_ENV` selects `config/<env>.yaml`
- `PORT` overrides `server.port`
- `HOST` overrides `server.binding`
- `DATABASE_URL` overrides `database.uri`

## Test

```sh
cargo test
```

## Seed

Run all seeds:

```sh
cargo run --bin tool -- seed
```
