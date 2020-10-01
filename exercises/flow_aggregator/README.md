# Runtime Flow Aggregation

## Introduction

We are going to manually set monitor and aggregator switches, dynamically during runtime.

## Step 1: Mininet Setting

In your shell, run:
    ```bash
    make
    ```

This will generate a pod-topology network for you, however, since all switches are mal-functioning, you will fail at `ping`ing something
(e.g. `h1 ping h5`)

## Step 2: Install P4 Rules

In another shell, run
    ```bash
    ./config.py
    ```

This will install control-plane table for the switches (if nesscessary), you can now successfully ping someone (e.g. `h1 ping h5`)

> Notice that some (most) `ping` will fail because I didn't setup the route

## Step 3: Start Query, then Collecting Result
