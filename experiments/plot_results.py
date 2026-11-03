"""Detection-rate chart from results/attack_summary.csv (+ clean_summary.csv for false positives).

Needs matplotlib (installed in the project's .venv):

    .venv/bin/python -m experiments.plot_results
"""

import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# Categorical slots 1-3 of the validated reference palette, in fixed order.
SERIES = {
    "baseline": ("#2a78d6", "Naive log (baseline)"),
    "harness": ("#eb6834", "Harness: agent edits its transcript"),
    "harness_logwrite": ("#1baf7a", "Harness: agent also writes audit log"),
}
SURFACE, TEXT, TEXT_2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"


def read_csv(path):
    with Path(path).open() as f:
        return list(csv.DictReader(f))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=Path("results"))
    args = ap.parse_args()

    summary = read_csv(args.results / "attack_summary.csv")
    clean_path = args.results / "clean_summary.csv"
    clean = {r["condition"]: r for r in read_csv(clean_path)} if clean_path.exists() else {}

    attacks = list(dict.fromkeys((r["attack"], r["attack_name"]) for r in summary))
    rate = {(r["attack"], r["sophistication"], r["condition"]): 100 * float(r["detection_rate"]) for r in summary}
    trials = summary[0]["trials"]

    plt.rcParams.update({"font.size": 10, "text.color": TEXT, "axes.labelcolor": TEXT_2})
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.6), sharey=True, facecolor=SURFACE)
    width, n = 0.26, len(SERIES)

    for ax, soph in zip(axes, ("simple", "careful")):
        ax.set_facecolor(SURFACE)
        for k, (cond, (color, label)) in enumerate(SERIES.items()):
            xs = [i + (k - (n - 1) / 2) * width for i in range(len(attacks))]
            ys = [rate.get((a, soph, cond), 0) for a, _ in attacks]
            # Draw zero as a sliver so "0% detected" is visibly a result, not missing data.
            ax.bar(xs, [max(y, 0.8) for y in ys], width - 0.04, color=color, label=label, zorder=3, linewidth=0)
        ax.set_xticks(range(len(attacks)))
        ax.set_xticklabels(["%s\n%s" % (a, name.replace(" ", "\n", 1)) for a, name in attacks], fontsize=8.5, color=TEXT_2)
        ax.set_ylim(0, 105)
        ax.set_yticks([0, 25, 50, 75, 100])
        ax.set_yticklabels(["%d%%" % v for v in (0, 25, 50, 75, 100)], color=TEXT_2)
        ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
        ax.tick_params(length=0)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color(GRID)
        title = "Simple attacker" if soph == "simple" else "Careful attacker (renumbers / recomputes hashes)"
        ax.set_title(title, loc="left", fontsize=11, color=TEXT, pad=10)
    axes[0].set_ylabel("Attacks detected")

    fig.suptitle(
        "Detection rate by attack (%s trials each)" % trials, x=0.01, y=0.98, ha="left", fontsize=13, fontweight="bold"
    )
    fig.legend(
        *axes[0].get_legend_handles_labels(),
        loc="upper left",
        bbox_to_anchor=(0.005, 0.925),
        ncol=3,
        frameon=False,
        fontsize=9,
    )
    if clean:
        fp = "   ".join(
            "%s: %s/%s" % (SERIES[c][1].split(":")[0].split(" (")[0], r["detected"], r["trials"]) for c, r in clean.items()
            if c != "harness_logwrite"
        )
        fig.text(0.01, 0.01, "False positives on untampered sessions -  " + fp, fontsize=8.5, color=TEXT_2)

    fig.tight_layout(rect=(0, 0.04, 1, 0.87))
    out = args.results / "detection_rates.png"
    fig.savefig(out, dpi=160, facecolor=SURFACE)
    print("wrote", out)


if __name__ == "__main__":
    main()
