from itertools import cycle
import os
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import LogLocator

# Tell matplotlib that there's no GUI
matplotlib.use("Agg")


def _setup_style():
    plt.style.use("seaborn-v0_8-colorblind")
    # Commenting out since Ubuntu doesn't ship with Helvetica
    #plt.rcParams["font.family"] = "sans-serif"
    #plt.rcParams["font.sans-serif"] = "Helvetica"
    plt.rcParams["font.size"] = 20
    plt.rcParams["axes.titlesize"] = 20
    plt.rcParams["axes.labelsize"] = 20
    plt.rcParams["legend.fontsize"] = 14
    plt.rcParams["xtick.labelsize"] = 16
    plt.rcParams["ytick.labelsize"] = 16
    matplotlib.rcParams["pdf.fonttype"] = 42
    matplotlib.rcParams["ps.fonttype"] = 42
    plt.rc("axes.formatter", useoffset=False)


def _get_colors():
    color_cycle = cycle(plt.rcParams["axes.prop_cycle"].by_key()["color"])
    colors = [next(color_cycle) for _ in range(2)]
    colors.append("#CC5F2A")
    colors.append("#CC5F2A")
    next(color_cycle)
    colors.append(next(color_cycle))
    return colors


_NEW_CSVS = ("server_new.csv", "client_new.csv", "dropout_10_new.csv", "dropout_new.csv")


def run_all(out_dir, data_dir, use_bench_results=False):
    """Load CSVs from data_dir, generate fig1-16 (including dropout), save PDFs to out_dir.

    If use_bench_results is True, or all *_new.csv exist in data_dir, those are used (bench results).
    Otherwise the baseline CSVs (server.csv, etc.) are used and a warning is printed.
    """
    _setup_style()
    colors = _get_colors()

    use_new = use_bench_results or all(
        os.path.isfile(os.path.join(data_dir, n)) for n in _NEW_CSVS
    )
    if use_new:
        server_data = pd.read_csv(os.path.join(data_dir, "server_new.csv"), sep=r"\s+")
        client_data = pd.read_csv(os.path.join(data_dir, "client_new.csv"), sep=r"\s+")
        dropout_10_data = pd.read_csv(os.path.join(data_dir, "dropout_10_new.csv"), sep=r"\s+")
        dropout_data = pd.read_csv(os.path.join(data_dir, "dropout_new.csv"), sep=r"\s+")
        if not use_bench_results:
            print("Using bench results from data/*_new.csv")
    else:
        print("Warning: Using saved data (no data/*_new.csv from a bench run).")
        print("  Run: python code/artifact-eval/run.py  (or from code/: python artifact-eval/run.py)")
        print("  to regenerate *_new.csv and plots from benches.\n\n")
        server_data = pd.read_csv(os.path.join(data_dir, "server.csv"), sep=r"\s+")
        client_data = pd.read_csv(os.path.join(data_dir, "client.csv"), sep=r"\s+")
        dropout_10_data = pd.read_csv(os.path.join(data_dir, "dropout_10.csv"), sep=r"\s+")
        dropout_data = pd.read_csv(os.path.join(data_dir, "dropout.csv"), sep=r"\s+")

    def save(name, fig):
        path = os.path.join(out_dir, name)
        fig.savefig(path, bbox_inches="tight", format="pdf")
        plt.close(fig)

    # Plot 1: Server CPU costs of boolean aggregation
    fig1, ax = plt.subplots()
    data = server_data.loc[(server_data["bitwidth"] == 1) & (server_data["length"] == 1)].sort_values(by="clients")
    x = data["clients"].unique()
    ax.plot(x, data["unwrap"] + data["prio_v"] + data["prio_a"], color=colors[0], marker="o")
    ax.plot(x, data["unwrap"] + data["us_v"] + data["us_a"], color=colors[2], marker="o")
    ax.plot(x, data["decode"], color=colors[3], marker="o")
    ax.annotate("Prio", (x[3] * 2.5, 750), rotation=34, color=colors[0])
    ax.annotate("Heli (Heavy)", (3000, 2800), rotation=35, color=colors[2])
    ax.annotate("Heli (Light)", (3500, 0.11), color=colors[3])
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Number of clients")
    ax.set_ylabel("Server CPU (core-ms)")
    ax.grid(linestyle="--")
    save("server_cpu.pdf", fig1)

    # Plot 2: Server-to-server communication
    fig2, ax = plt.subplots()
    data = server_data.loc[(server_data["bitwidth"] == 1) & (server_data["length"] == 1)].sort_values(by="clients")
    x = data["clients"].unique()
    ax.plot(x, data["prio_c"], color=colors[0], marker="o")
    ax.plot(x, data["whisper_c"], color=colors[1], marker="o")
    ax.plot(x[1:], data["whisper_1_c"][1:], color=colors[1], marker="o")
    ax.plot(x, data["us_c"], color=colors[2], marker="o")
    ax.plot(x, data["us_c"] + dropout_10_data["comm"], color=colors[2], marker="o", markerfacecolor="none")
    ax.annotate("Prio", (1500, 700), rotation=34, color=colors[0])
    ax.annotate("Whisper", (1400, 0.17), color=colors[1])
    ax.annotate("Whisper", (3000, 12), rotation=34, color=colors[1])
    ax.annotate("(1% malicious)", (80000, 320), rotation=34, color=colors[1], fontsize=15)
    ax.annotate("Heli", (x[2] * 3, 0.006), color=colors[2])
    ax.annotate("10% dropout", (170000, 0.17), rotation=32, color=colors[2], fontsize=15)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_ylim([1 / 300, 10 ** 6.5])
    ax.yaxis.set_major_locator(LogLocator(base=10, numticks=10))
    ax.set_xlabel("Number of clients ($n$)")
    ax.set_ylabel("Server-to-Server Comm. (KB)")
    ax.grid(linestyle="--")
    save("server_comm.pdf", fig2)

    # Plot 3: Server CPU as bitwidth grows
    fig3, ax = plt.subplots()
    clients = 10 ** 7
    data = server_data.loc[(server_data["length"] == 1) & (server_data["clients"] == clients)]
    x = data["bitwidth"].unique().astype("int")
    ax.plot(x, (data["unwrap"] + data["prio_v"] + data["prio_a"]) / 1000.0, color=colors[0], marker="o")
    ax.plot(x, (data["unwrap"] + data["whisper_va"]) / 1000.0, color=colors[1], marker="o")
    ax.plot(x, (data["unwrap"] + data["ahe_v"]) / 1000.0, color=colors[4], marker="o")
    ax.plot(x, (data["unwrap"] + data["us_v"] + data["us_a"]) / 1000.0, color=colors[2], marker="o")
    ax.plot(x, (data["decode"]) / 1000.0, color=colors[3], marker="o")
    ax.annotate("Prio", (35, 200), color=colors[0])
    ax.annotate("Whisper", (33, 1600), color=colors[1])
    ax.annotate("Heli (Heavy)", (29, 6300), rotation=25, color=colors[2])
    ax.annotate("ElGamal", (30, 8550), rotation=28, color=colors[4])
    plt.annotate(
        "Heli (Light)",
        xy=(52, 0),
        xytext=(47, 2500),
        arrowprops=dict(arrowstyle="->", color=colors[2], linewidth=2, mutation_scale=15, connectionstyle="arc3,rad=0.3"),
        color=colors[2],
        fontsize=20,
    )
    ax.set_ylim([-90, 13400])
    ax.set_xlabel("Measurement bitwidth ($b$)")
    ax.set_ylabel("Server CPU (core-s)")
    ax.grid(linestyle="--")
    save("server_cpu_bitwidth.pdf", fig3)

    # Plot 4: Server CPU as length grows
    fig4, ax = plt.subplots()
    data = server_data.loc[(server_data["bitwidth"] == 1) & (server_data["clients"] == clients) & (server_data["length"] < 128)]
    x = data["length"].unique().astype("int")
    ax.plot(x, (data["unwrap"] + data["prio_v"] + data["prio_a"]) / 1000.0, color=colors[0], marker="o")
    ax.plot(x, (data["unwrap"] + data["whisper_va"]) / 1000.0, color=colors[1], marker="o")
    ax.plot(x, (data["unwrap"] + data["ahe_v"]) / 1000.0, color=colors[4], marker="o")
    ax.plot(x, (data["unwrap"] + data["us_v"] + data["us_a"]) / 1000.0, color=colors[2], marker="o")
    ax.plot(x, (data["decode"]) / 1000.0, color=colors[2], marker="o")
    ax.annotate("Prio", (20, 3000), color=colors[0])
    ax.annotate("Whisper", (35, 3000), color=colors[1])
    ax.annotate("Heli (Heavy)", (29, 24000), rotation=35, color=colors[2])
    ax.annotate("ElGamal", (29, 34500), rotation=37, color=colors[4])
    plt.annotate(
        "Heli (Light)",
        xy=(52, -80),
        xytext=(47, 8000),
        arrowprops=dict(arrowstyle="->", color=colors[2], linewidth=2, mutation_scale=15, connectionstyle="arc3,rad=0.3"),
        color=colors[2],
        fontsize=20,
    )
    ax.set_ylim([0, 72000])
    ax.set_xlabel("Number of measurements ($\\ell$)")
    ax.set_ylabel("Server CPU (core-s)")
    ax.grid(linestyle="--")
    save("server_cpu_length.pdf", fig4)

    # Plot 5: Encoding size vs bitwidth
    fig5, ax = plt.subplots()
    data = client_data.loc[client_data["length"] == 1]
    x = data["bitwidth"].unique().astype("int")
    ax.plot(x, data["prio_s"], color=colors[0], marker="o")
    ax.plot(x, data["whisper_s"], color=colors[1], marker="o")
    ax.plot(x, data["us_s"], color=colors[2], marker="o")
    ax.plot(x, data["ahe_s"], color=colors[4], marker="o")
    ax.annotate("Prio", (43, 1.38), rotation=15, color=colors[0])
    ax.annotate("Whisper", (40, 2.5), rotation=21, color=colors[1])
    ax.annotate("ElGamal", (42, 0.93), rotation=2, color=colors[4])
    ax.annotate("Heli", (45, 0.6), rotation=1, color=colors[2])
    ax.set_ylim([0, 3.2])
    ax.set_xlabel("Measurement bitwidth ($b$)")
    ax.set_ylabel("Encoding size (KB)")
    ax.grid(linestyle="--")
    save("encoding_size_bitwidth.pdf", fig5)

    # Plot 6: Encoding size vs length
    fig6, ax = plt.subplots()
    data = client_data.loc[client_data["bitwidth"] == 1]
    x = data["length"].unique().astype("int")
    ax.plot(x, data["prio_s"], color=colors[0], marker="o")
    ax.plot(x, data["whisper_s"], color=colors[1], marker="o")
    ax.plot(x, data["us_s"], color=colors[2], marker="o")
    ax.plot(x, data["ahe_s"], color=colors[4], marker="o")
    ax.annotate("Prio", (42, 0.35), rotation=3, color=colors[0])
    ax.annotate("Whisper", (38, 2.8), rotation=6, color=colors[1])
    ax.annotate("Heli", (39, 7.2), rotation=35, color=colors[2])
    ax.annotate("ElGamal", (34, 8), rotation=36, color=colors[4])
    ax.set_ylim([0, 14])
    ax.set_xlabel("Number of measurements ($\\ell$)")
    ax.set_ylabel("Encoding size (KB)")
    ax.grid(linestyle="--")
    save("encoding_size_length.pdf", fig6)

    # Plot 7: Encoding time vs bitwidth
    fig7, ax = plt.subplots()
    data = client_data.loc[client_data["length"] == 1]
    x = data["bitwidth"].unique().astype("int")
    ax.plot(x, data["prio_c"] + data["prio_e"], color=colors[0], marker="o")
    ax.plot(x, data["us_c"] + data["us_e"], color=colors[2], marker="o")
    ax.plot(x, data["ahe_c"] + data["us_e"], color=colors[4], marker="o")
    ax.annotate("Prio / Whisper", (26, 0.7), rotation=0, color=colors[0])
    ax.annotate("Heli", (36, 5.2), rotation=33, color=colors[2])
    ax.annotate("ElGamal", (30, 6.3), rotation=34, color=colors[4])
    ax.set_ylim([-0, 11])
    ax.set_xlabel("Measurement bitwidth ($b$)")
    ax.set_ylabel("Client CPU (core-ms)")
    ax.grid(linestyle="--")
    save("encoding_time_bitwidth.pdf", fig7)

    # Plot 8: Encoding time vs length
    fig8, ax = plt.subplots()
    data = client_data.loc[client_data["bitwidth"] == 1]
    x = data["length"].unique().astype("int")
    ax.plot(x, data["prio_c"] + data["prio_e"], color=colors[0], marker="o")
    ax.plot(x, data["us_c"] + data["us_e"], color=colors[2], marker="o")
    ax.plot(x, data["ahe_c"] + data["us_e"], color=colors[4], marker="o")
    ax.annotate("Prio / Whisper", (26, 1.5), rotation=0, color=colors[0])
    ax.annotate("Heli", (33, 19), rotation=37, color=colors[2])
    ax.annotate("ElGamal", (33.5, 13.5), rotation=37, color=colors[4])
    ax.set_ylim([-0.1, 33])
    ax.set_xlabel("Number of measurements ($\\ell$)")
    ax.set_ylabel("Client CPU (core-ms)")
    ax.grid(linestyle="--")
    save("encoding_time_length.pdf", fig8)

    # Plot 9: Server CPU with 10% dropout
    fig9, ax = plt.subplots()
    data = server_data.loc[(server_data["bitwidth"] == 1) & (server_data["length"] == 1)].sort_values(by="clients")
    x = data["clients"].unique()
    ax.plot(x, data["unwrap"] + data["prio_v"] + data["prio_a"], color=colors[0], marker="o")
    ax.plot(x, data["unwrap"] + data["us_v"] + data["us_a"], color=colors[2], marker="o")
    ax.plot(x, data["decode"], color=colors[3], marker="o")
    ax.plot(x[2:], dropout_10_data["cpu"][2:], color=colors[3], marker="o", markerfacecolor="none")
    ax.annotate("Prio / Whisper", (600, 13), rotation=35, color=colors[0])
    ax.annotate("Heli (Heavy)", (200, 250), rotation=35, color=colors[2])
    ax.annotate("Heli (Light)", (200, 0.1), color=colors[3])
    ax.annotate("10% dropout", (100000, 0.28), rotation=33, color=colors[3], fontsize=15)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Number of clients ($n$)")
    ax.set_ylabel("Server CPU (core-ms)")
    ax.grid(linestyle="--")
    save("server_cpu_dropout.pdf", fig9)

    # Plot 10: Server CPU length (log)
    fig10, ax = plt.subplots()
    data = server_data.loc[(server_data["bitwidth"] == 1) & (server_data["clients"] == clients) & (server_data["length"] < 128)]
    x = data["length"].unique().astype("int")
    dropout_cost = dropout_10_data[(dropout_10_data["clients"] == clients)]["comm"].values[0]
    dropout = data["decode"] + dropout_cost
    ax.plot(x, (data["unwrap"] + data["prio_v"] + data["prio_a"]) / 1000.0, color=colors[0], marker="o")
    ax.plot(x, (data["unwrap"] + data["whisper_va"]) / 1000.0, color=colors[1], marker="o")
    ax.plot(x, (data["unwrap"] + data["us_v"] + data["us_a"]) / 1000.0, color=colors[2], marker="o")
    ax.plot(x, (data["decode"]) / 1000.0, color=colors[2], marker="o")
    ax.plot(x, dropout / 1000.0, color=colors[2], marker="o", markerfacecolor="none")
    ax.annotate("Prio", (36, 200), color=colors[0])
    ax.annotate("Whisper", (35, 3000), color=colors[1])
    ax.annotate("Heli (Heavy)", (30, 70000), rotation=3, color=colors[2])
    ax.annotate("Heli (Light)", (34, 0.0002), rotation=2, color=colors[3])
    ax.annotate("(10% dropout)", (34, 0.009), color=colors[2], fontsize=15)
    ax.set_yscale("log")
    ax.set_ylim([0.00001, 600000])
    ax.set_xlabel("Number of measurements ($\\ell$)")
    ax.set_ylabel("Server CPU (core-s)")
    ax.grid(linestyle="--")
    save("server_cpu_length_log.pdf", fig10)

    # Plot 11: Server CPU bitwidth (log)
    fig11, ax = plt.subplots()
    data = server_data.loc[(server_data["length"] == 1) & (server_data["clients"] == clients)]
    x = data["bitwidth"].unique().astype("int")
    dropout_cost = dropout_10_data[(dropout_10_data["clients"] == clients)]["comm"].values[0]
    dropout = data["decode"] + dropout_cost
    ax.plot(x, (data["unwrap"] + data["prio_v"] + data["prio_a"]) / 1000.0, color=colors[0], marker="o")
    ax.plot(x, (data["unwrap"] + data["whisper_va"]) / 1000.0, color=colors[1], marker="o")
    ax.plot(x, (data["unwrap"] + data["us_v"] + data["us_a"]) / 1000.0, color=colors[2], marker="o")
    ax.plot(x, (data["decode"]) / 1000.0, color=colors[3], marker="o")
    ax.plot(x, (dropout) / 1000.0, color=colors[3], marker="o", markerfacecolor="none")
    ax.annotate("Prio", (37, 200), color=colors[0])
    ax.annotate("Whisper", (35, 2000), color=colors[1])
    ax.annotate("Heli (Heavy)", (33, 17000), rotation=2, color=colors[2])
    ax.annotate("Heli (Light)", (33, 0.00009), color=colors[3])
    ax.annotate("(10% dropout)", (34, 0.005), color=colors[2], fontsize=15)
    ax.set_yscale("log")
    ax.set_ylim([0.00002, 120000])
    ax.set_xlabel("Measurement bitwidth ($b$)")
    ax.set_ylabel("Server CPU (core-s)")
    ax.grid(linestyle="--")
    save("server_cpu_bitwidth_log.pdf", fig11)

    # Plot 12: Server comm length (log)
    fig12, ax = plt.subplots()
    data = server_data.loc[(server_data["bitwidth"] == 1) & (server_data["clients"] == clients) & (server_data["length"] < 128)]
    x = data["length"].unique().astype("int")
    dropout_cost = dropout_10_data[(dropout_10_data["clients"] == clients)]["comm"].values[0]
    ax.plot(x, data["prio_c"], color=colors[0], marker="o")
    ax.plot(x, data["whisper_c"], color=colors[1], marker="o")
    ax.plot(x, data["whisper_1_c"], color=colors[1], marker="o")
    ax.plot(x, data["us_c"], color=colors[2], marker="o")
    ax.plot(x, data["us_c"] + dropout_cost * 1024, color=colors[2], marker="o", markerfacecolor="none")
    ax.annotate("Prio", (35, 700000), rotation=1, color=colors[0])
    ax.annotate("Whisper", (35, 3), rotation=2, color=colors[1])
    ax.annotate("Whisper", (30, 35000), color=colors[1])
    ax.annotate("(1% malicious)", (45, 38000), color=colors[1], fontsize=15)
    ax.annotate("Heli", (37, 0.3), rotation=2, color=colors[2])
    ax.annotate("Heli", (30, 600), rotation=0, color=colors[2])
    ax.annotate("(10% dropout)", (37.5, 650), rotation=1, color=colors[2], fontsize=15)
    ax.set_yscale("log")
    ax.set_xlabel("Number of measurements ($\\ell$)")
    ax.set_ylabel("Server-to-Server Comm. (KB)")
    ax.grid(linestyle="--")
    save("server_comm_length_log.pdf", fig12)

    # Plot 13: Server comm bitwidth (log)
    fig13, ax = plt.subplots()
    data = server_data.loc[(server_data["length"] == 1) & (server_data["clients"] == clients)]
    x = data["bitwidth"].unique().astype("int")
    dropout_cost = dropout_10_data[(dropout_10_data["clients"] == clients)]["comm"].values[0]
    ax.plot(x, data["prio_c"], color=colors[0], marker="o")
    ax.plot(x, data["whisper_c"], color=colors[1], marker="o")
    ax.plot(x, data["whisper_1_c"], color=colors[1], marker="o")
    ax.plot(x, data["us_c"], color=colors[2], marker="o")
    ax.plot(x, data["us_c"] + dropout_cost * 1024, color=colors[2], marker="o", markerfacecolor="none")
    ax.annotate("Prio", (35, 700000), rotation=1, color=colors[0])
    ax.annotate("Whisper", (34, 0.2), color=colors[1])
    ax.annotate("Whisper", (30, 33000), color=colors[1])
    ax.annotate("(1% malicious)", (45, 38000), color=colors[1], fontsize=15)
    ax.annotate("Heli", (32, 500), color=colors[2])
    ax.annotate("(10% dropout)", (39.5, 600), color=colors[2], fontsize=15)
    ax.annotate("Heli", (35, 0.006), color=colors[2])
    ax.set_yscale("log")
    ax.set_ylim([0.003, 10000000])
    ax.set_xlabel("Measurement bitwidth ($b$)")
    ax.set_ylabel("Server-to-Server Comm. (KB)")
    ax.grid(linestyle="--")
    save("server_comm_bitwidth_log.pdf", fig13)

    # Plot 15: Dropout crossover (server CPU)
    fig15, ax = plt.subplots()
    data = dropout_data
    x = data["dropout_perc"].unique()
    # Keep numeric for x-axis (0, 10, 20, ..., 99, 99.995)
    x = np.asarray(x, dtype=float)
    ax.plot(x, data["prio"] / 1000.0, color=colors[0], marker="o")
    ax.plot(x, data["light"] / 1000.0, color=colors[3], marker="o")
    ax.annotate("Prio / Whisper", (45, 280), rotation=-38, color=colors[0])
    ax.annotate("Heli (Light)", (40, 40), color=colors[3])
    ax.set_ylim([-5, 970])
    ax.set_xlabel("Percentage of dropped-out clients (%)")
    ax.set_ylabel("Server CPU (core-s)")
    ax.grid(linestyle="--")
    save("dropout_crossover.pdf", fig15)

    # Plot 16: Dropout crossover (communication)
    fig16, ax = plt.subplots()
    data = dropout_data
    x = data["dropout_perc"].unique()
    x = np.asarray(x, dtype=float)[1:]
    ax.plot(x, data["prio_c"][1:] / 1024.0, color=colors[0], marker="o")
    ax.plot(x, data["whisper_c"][1:] / 1024.0, color=colors[1], marker="o")
    ax.plot(x, data["whisper_1_c"][1:] / 1024.0, color=colors[1], marker="o")
    ax.plot(x, data["light_c"][1:] / 1024.0, color=colors[3], marker="o")
    ax.annotate("Prio", (52, 580), rotation=-40, color=colors[0])
    ax.annotate("Whisper", (20, 150), rotation=-6, color=colors[1])
    ax.annotate("Heli", (15, 40), color=colors[3])
    ax.annotate("(1% malicious)", (40, 350), color=colors[1], fontsize=15)
    plt.annotate(
        "Whisper",
        xy=(47, -5),
        xytext=(19, 350),
        arrowprops=dict(arrowstyle="->", color=colors[1], linewidth=2, mutation_scale=15, connectionstyle="arc3,rad=-0.3"),
        color=colors[1],
        fontsize=20,
    )
    ax.set_ylim([-5, 1250])
    ax.set_xlabel("Percentage of dropped-out clients (%)")
    ax.set_ylabel("Server-to-Server Comm. (MB)")
    ax.grid(linestyle="--")
    save("dropout_crossover_comm.pdf", fig16)

    print("Plots saved to", out_dir)


if __name__ == "__main__":
    _script_dir = os.path.abspath(os.path.dirname(__file__))
    _plots_dir = os.path.join(_script_dir, "plots")
    os.makedirs(_plots_dir, exist_ok=True)
    run_all(out_dir=_plots_dir, data_dir=os.path.join(_script_dir, "data"))
