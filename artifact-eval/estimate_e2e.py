import math

# TODO: The following variables should be replaced with your own numbers
# ------------------------------------------
# Vector length
lengths = [1, 32, 128]

# Total number of bytes uploaded to aggregator during `submit` phase
total_client_upload_bytes = [36001408, 750241408, 2287531408]

# Wall clock time (s) of aggregator during `aggregate` phase
wall_clock_agg_s = [10.5, 46.91, 127]

# Wall clock time (ms) of decryptor during `aggregate` phase
wall_clock_dec_ms = [0.05, 0.1, 2.1]

# Number of cores on your aggregator machine
num_cores_agg = 16
# ------------------------------------------


if __name__ == "__main__":
    num_clients = 100_000
    target_clients = 10_000_000
    exp_cores_agg = 96
    exp_bandwidth_gbits = 15
   
    client_delta = target_clients / num_clients
    agg_core_delta = exp_cores_agg / num_cores_agg

    for (i, length) in enumerate(lengths):
        print(f"Simulated numbers for l={length}:")
        # Compute the simulated upload time
        sim_upload_bytes = total_client_upload_bytes[i] * client_delta
        sim_upload_gbit = (sim_upload_bytes * 8) / 1024**3
        sim_upload_time_s = sim_upload_gbit / exp_bandwidth_gbits
    
        # Compute the simulated server runtimes
        sim_wall_clock_agg_s = (wall_clock_agg_s[i] * client_delta) / agg_core_delta
        sim_agg_s = round(sim_upload_time_s + sim_wall_clock_agg_s, 2)
        print(f"\tSimulated aggregator wall clock time: {sim_agg_s}s")

        # Mask time remains the same, so the only difference is 
        # dropout key computation (single-thread)
        #
        # 5.151 is difference in dropout time recovery from 100_000 -> 10000000
        sim_wall_clock_dec_ms = wall_clock_dec_ms[i] + 5.151
        print(f"\tSimulated decryptor wall clock time: {sim_wall_clock_dec_ms}ms")
        
        # Compute the simulated server-to-server communication
        # NOTE: This doesn't scale linearly, so we just compute directly
        sim_server_comm_bytes = math.log2(target_clients) * 1_000_000 / 8 # Dropout
        sim_server_comm_bytes += 32 * length # decrypt mask
        sim_server_comm_kb = round(sim_server_comm_bytes / 1024, 2)

        print(f"\tSimulated aggregator egress: {sim_server_comm_kb}KB")
        print(f"\tSimulated decryptor egress: {round((32 * length) / 1024, 2)}KB")
