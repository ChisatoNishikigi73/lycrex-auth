#!/bin/bash

export RUN_ENV=production
export RUST_LOG=info,sqlx=off,sqlx::query=off

cargo run --release 