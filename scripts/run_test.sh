#!/bin/bash

export RUN_ENV=test
export RUST_LOG=info,sqlx=off,sqlx::query=off

cargo run 