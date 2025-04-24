#!/bin/bash

export RUN_ENV=development
export RUST_LOG=debug,sqlx::query=warn

cargo run 