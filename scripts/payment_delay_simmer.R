#!/usr/bin/env Rscript
# Payment Delay Simulation using simmer
# Measures the time taken for a payment to complete through the network

library(simmer)

# Create simulation environment
env <- simmer("payment_sim")

# Define payment trajectory
payment_traj <- trajectory("payment") %>%
  seize("network", 1) %>%
  # Average delay: 0.2 seconds (exponential distribution)
  timeout(function() rexp(1, rate = 1/0.2)) %>%
  release("network", 1)

# Add resource and run simulation
env %>%
  add_resource("network", capacity = 1) %>%
  # Generate one payment at t=0
  add_generator("payment", payment_traj, at(0)) %>%
  run()

# Extract and analyze results
arr <- get_mon_arrivals(env)
payment_time <- arr$end_time - arr$start_time

cat("=== Payment Simulation Results ===\n")
cat("Payment start time:", arr$start_time, "sec\n")
cat("Payment end time:", arr$end_time, "sec\n")
cat("Payment delay:", payment_time, "sec\n")
cat("=====================================\n")
