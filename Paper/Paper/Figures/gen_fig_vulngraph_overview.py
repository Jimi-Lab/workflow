"""Generate the VulnGraph paper overview figure.

This script intentionally uses Matplotlib primitives instead of an image
generation model so that labels remain exact and the figure is reproducible.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle


OUT_DIR = Path(__file__).resolve().parent


COLORS = {
    "bg": "#FBFBFA",
    "ink": "#1F2933",
    "muted": "#52616B",
    "line": "#667085",
    "input": "#EEF2F6",
    "input_edge": "#9AA6B2",
    "c1": "#E8F1FF",
    "c1_edge": "#2F80ED",
    "c2": "#E7F8F2",
    "c2_edge": "#169B78",
    "judge": "#FFF3E0",
    "judge_edge": "#D97706",
    "c3": "#F1EBFF",
    "c3_edge": "#7C3AED",
    "out": "#FFEDE9",
    "out_edge": "#E76F51",
    "foundation": "#F5F7FA",
    "foundation_edge": "#64748B",
    "kg": "#FDF2F8",
    "kg_edge": "#C026D3",
}


def wrap(text: str, width: int) -> str:
    return "\n".join(textwrap.wrap(text, width=width, break_long_words=False))


def rounded_box(
    ax,
    x: float,
    y: float,
    w: float,
    h: float,
    *,
    title: str,
    body: str = "",
    fc: str,
    ec: str,
    title_size: float = 10.5,
    body_size: float = 8.0,
    title_color: str | None = None,
    lw: float = 1.45,
    radius: float = 0.08,
    zorder: int = 2,
):
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle=f"round,pad=0.02,rounding_size={radius}",
        linewidth=lw,
        edgecolor=ec,
        facecolor=fc,
        zorder=zorder,
    )
    ax.add_patch(patch)
    ax.text(
        x + w / 2,
        y + h - 2.2,
        title,
        ha="center",
        va="top",
        fontsize=title_size,
        fontweight="bold",
        color=title_color or ec,
        zorder=zorder + 1,
    )
    if body:
        ax.text(
            x + w / 2,
            y + h - 6.0,
            body,
            ha="center",
            va="top",
            fontsize=body_size,
            color=COLORS["ink"],
            linespacing=1.25,
            zorder=zorder + 1,
        )
    return patch


def small_box(
    ax,
    x: float,
    y: float,
    w: float,
    h: float,
    text: str,
    *,
    fc: str,
    ec: str,
    fontsize: float = 7.2,
    weight: str = "normal",
):
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.02,rounding_size=0.05",
        linewidth=1.0,
        edgecolor=ec,
        facecolor=fc,
        zorder=4,
    )
    ax.add_patch(patch)
    ax.text(
        x + w / 2,
        y + h / 2,
        text,
        ha="center",
        va="center",
        fontsize=fontsize,
        color=COLORS["ink"],
        fontweight=weight,
        linespacing=1.18,
        zorder=5,
    )
    return patch


def badge(ax, x: float, y: float, label: str, color: str):
    patch = FancyBboxPatch(
        (x, y),
        18.5,
        4.2,
        boxstyle="round,pad=0.025,rounding_size=0.08",
        linewidth=0,
        facecolor=color,
        alpha=0.98,
        zorder=7,
    )
    ax.add_patch(patch)
    ax.text(
        x + 9.25,
        y + 2.1,
        label,
        ha="center",
        va="center",
        fontsize=7.2,
        color="white",
        fontweight="bold",
        zorder=8,
    )


def arrow(
    ax,
    start: tuple[float, float],
    end: tuple[float, float],
    *,
    color: str = COLORS["line"],
    lw: float = 1.4,
    style: str = "-",
    rad: float = 0.0,
    label: str | None = None,
    label_offset: tuple[float, float] = (0, 0),
    mutation_scale: float = 11,
):
    arr = FancyArrowPatch(
        start,
        end,
        arrowstyle="-|>",
        mutation_scale=mutation_scale,
        linewidth=lw,
        linestyle=style,
        color=color,
        connectionstyle=f"arc3,rad={rad}",
        shrinkA=3,
        shrinkB=3,
        zorder=6,
    )
    ax.add_patch(arr)
    if label:
        mx = (start[0] + end[0]) / 2 + label_offset[0]
        my = (start[1] + end[1]) / 2 + label_offset[1]
        ax.text(
            mx,
            my,
            label,
            ha="center",
            va="center",
            fontsize=7.0,
            color=color,
            fontweight="bold",
            bbox=dict(boxstyle="round,pad=0.15", fc=COLORS["bg"], ec="none", alpha=0.92),
            zorder=9,
        )


def draw_overview():
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 8.0,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "savefig.dpi": 300,
        }
    )

    fig, ax = plt.subplots(figsize=(19.5, 8.4))
    fig.patch.set_facecolor(COLORS["bg"])
    ax.set_xlim(0, 220)
    ax.set_ylim(0, 100)
    ax.axis("off")

    def contribution_pill(x: float, y: float, w: float, text: str, color: str, *, fs: float = 7.6):
        patch = FancyBboxPatch(
            (x, y),
            w,
            4.7,
            boxstyle="round,pad=0.02,rounding_size=0.08",
            linewidth=0,
            facecolor=color,
            alpha=0.98,
            zorder=8,
        )
        ax.add_patch(patch)
        ax.text(
            x + w / 2,
            y + 2.35,
            text,
            ha="center",
            va="center",
            fontsize=fs,
            color="white",
            fontweight="bold",
            zorder=9,
        )

    # Title block with enough top margin; it should not touch the frame.
    ax.text(
        110,
        95.2,
        "VulnGraph: Attacker-Condition-Guided Affected-Version Identification",
        ha="center",
        va="center",
        fontsize=16.2,
        fontweight="bold",
        color=COLORS["ink"],
    )
    ax.text(
        110,
        91.6,
        "Evidence-constrained reconstruction of branch-specific vulnerability state over a Git DAG",
        ha="center",
        va="center",
        fontsize=10.4,
        color=COLORS["muted"],
    )

    # Contribution C1: attacker-condition reasoning, shown as a top semantic layer.
    rounded_box(
        ax,
        31,
        77.2,
        164,
        10.0,
        title="Attacker-Condition-Guided Reasoning",
        body="attacker-controlled input  |  trigger  |  exploit precondition  |  sink  |  reachability  |  impact",
        fc="#EEF6FF",
        ec=COLORS["c1_edge"],
        title_size=9.2,
        body_size=7.2,
        lw=1.1,
    )
    contribution_pill(74, 85.4, 78, "C1  Attacker-Condition-Guided Affected-Version Reasoning", COLORS["c1_edge"], fs=7.2)

    # Input and main pipeline.
    rounded_box(
        ax,
        5,
        47,
        20,
        22,
        title="Inputs",
        body="CVE report\nCWE\nfix commit(s)\nrepository\nrelease tags",
        fc=COLORS["input"],
        ec=COLORS["input_edge"],
        title_size=10.0,
        body_size=7.9,
    )

    # C2 banner spans anchor reconstruction through state propagation.
    contribution_pill(
        63,
        72.8,
        131,
        "C2  Evidence-Constrained Branch-Specific Vulnerability-State Reconstruction",
        COLORS["c2_edge"],
        fs=7.0,
    )

    rounded_box(
        ax,
        31,
        46,
        28,
        24,
        title="Root-Cause &\nPredicate Modeling",
        body="",
        fc=COLORS["c1"],
        ec=COLORS["c1_edge"],
        title_size=8.8,
    )
    small_box(ax, 34, 58.7, 22, 5.2, "RootCauseHypothesis\nVulnerablePredicate", fc="#FFFFFF", ec=COLORS["c1_edge"], fontsize=6.5)
    small_box(ax, 34, 51.5, 22, 5.2, "FixPredicate\nGitObservation refs", fc="#FFFFFF", ec=COLORS["c1_edge"], fontsize=6.5)

    rounded_box(
        ax,
        65,
        46,
        28,
        24,
        title="Evidence-Constrained\nAnchor Selection",
        body="",
        fc="#F0F9FF",
        ec=COLORS["c1_edge"],
        title_size=8.6,
    )
    small_box(ax, 68, 58.7, 22, 5.2, "pre-fix CodeAnchors\nwith evidence refs", fc="#FFFFFF", ec=COLORS["c1_edge"], fontsize=6.5)
    small_box(ax, 68, 51.5, 22, 5.2, "add-only / delete / modify\nrename / multi-fix", fc="#FFFFFF", ec=COLORS["c1_edge"], fontsize=6.2)

    rounded_box(
        ax,
        99,
        46,
        31,
        24,
        title="Adaptive History-Event\nReconstruction",
        body="",
        fc=COLORS["c2"],
        ec=COLORS["c2_edge"],
        title_size=8.5,
    )
    small_box(ax, 102, 58.7, 25, 5.2, "blame: normal, -w, -M, -C", fc="#FFFFFF", ec=COLORS["c2_edge"], fontsize=6.6)
    small_box(ax, 102, 51.5, 25, 5.2, "log -L, pickaxe -S/-G\n--follow, Fixes trailer", fc="#FFFFFF", ec=COLORS["c2_edge"], fontsize=6.3)

    rounded_box(
        ax,
        136,
        46,
        28,
        24,
        title="Evidence-Constrained\nJudge",
        body="",
        fc=COLORS["judge"],
        ec=COLORS["judge_edge"],
        title_size=8.7,
    )
    small_box(ax, 139, 58.7, 22, 5.2, "Top-k blind packet\nno labels, no GT", fc="#FFFFFF", ec=COLORS["judge_edge"], fontsize=6.5)
    small_box(ax, 139, 51.5, 22, 5.2, "introduction / prereq\nrefactor / fix-series\nboundary / uncertain", fc="#FFFFFF", ec=COLORS["judge_edge"], fontsize=5.9)

    rounded_box(
        ax,
        170,
        46,
        25,
        24,
        title="Branch-Specific\nState Propagation",
        body="",
        fc=COLORS["c3"],
        ec=COLORS["c3_edge"],
        title_size=8.7,
    )
    small_box(ax, 173, 58.7, 19, 5.2, "vulnerability / fix\nstate on Git DAG", fc="#FFFFFF", ec=COLORS["c3_edge"], fontsize=6.3)
    small_box(ax, 173, 51.5, 19, 5.2, "root boundary\nfeature-series\nbackport/reintro", fc="#FFFFFF", ec=COLORS["c3_edge"], fontsize=5.8)

    rounded_box(
        ax,
        201,
        46,
        15,
        24,
        title="Release\nProjection",
        body="",
        fc="#F8F5FF",
        ec=COLORS["c3_edge"],
        title_size=8.4,
    )
    small_box(ax, 203, 58.7, 11, 5.2, "formal\nrelease tags", fc="#FFFFFF", ec=COLORS["c3_edge"], fontsize=5.9)
    small_box(ax, 203, 51.5, 11, 5.2, "affected\nversions", fc="#FFFFFF", ec=COLORS["c3_edge"], fontsize=6.1, weight="bold")

    rounded_box(
        ax,
        191,
        27,
        25,
        11,
        title="Final Output",
        body="affected_versions\n+ evidence + uncertainty",
        fc=COLORS["out"],
        ec=COLORS["out_edge"],
        title_size=8.8,
        body_size=6.8,
    )

    # Main data flow: clean horizontal route, then output drop.
    arrow(ax, (25, 58), (31, 58), color=COLORS["line"], mutation_scale=10)
    arrow(ax, (59, 58), (65, 58), color=COLORS["line"], mutation_scale=10)
    arrow(ax, (93, 58), (99, 58), color=COLORS["line"], mutation_scale=10)
    arrow(ax, (130, 58), (136, 58), color=COLORS["line"], label="Top-k events", label_offset=(0, 4.8), mutation_scale=10)
    arrow(ax, (164, 58), (170, 58), color=COLORS["line"], mutation_scale=10)
    arrow(ax, (195, 58), (201, 58), color=COLORS["line"], mutation_scale=10)
    arrow(ax, (208.5, 46), (203.5, 38), color=COLORS["out_edge"], lw=1.5, mutation_scale=10)

    # C1 semantic condition guidance: short vertical arrows; no crossing over boxes.
    arrow(ax, (45, 77.2), (45, 70), color=COLORS["c1_edge"], style="--", mutation_scale=8)
    arrow(ax, (150, 77.2), (150, 70), color=COLORS["c1_edge"], style="--", mutation_scale=8)
    arrow(ax, (182, 77.2), (182, 70), color=COLORS["c1_edge"], style="--", mutation_scale=8)

    # Shared Git graph/evidence layer.
    rounded_box(
        ax,
        58,
        10,
        116,
        22,
        title="Shared Git Graph Index and Evidence Cache",
        body="Reusable repository facts: commit DAG, release-DAG view, fix-SHA coverage, and reproducible Git evidence.",
        fc=COLORS["foundation"],
        ec=COLORS["foundation_edge"],
        title_size=9.6,
        body_size=7.1,
    )
    small_box(ax, 63, 13.5, 23, 6.8, "Commit DAG\nparents, merges, roots", fc="#FFFFFF", ec=COLORS["foundation_edge"], fontsize=6.4)
    small_box(ax, 90, 13.5, 23, 6.8, "Git evidence cache\nblame, log, diff", fc="#FFFFFF", ec=COLORS["foundation_edge"], fontsize=6.4)
    small_box(ax, 117, 13.5, 23, 6.8, "Release DAG view\nformal tags only", fc="#FFFFFF", ec=COLORS["foundation_edge"], fontsize=6.4)
    small_box(ax, 144, 13.5, 24, 6.8, "Provenance keys\nreproducible queries", fc="#FFFFFF", ec=COLORS["foundation_edge"], fontsize=6.4)

    # C3 graph-backed adaptation as bottom-left layer, not mixed with DAG projection.
    rounded_box(
        ax,
        5,
        10,
        47,
        22,
        title="Graph-Backed Continual Adaptation",
        body="reviewed outcomes and failure patterns\nretrieved by repo, CWE, root-cause, patch, and attack pattern",
        fc=COLORS["kg"],
        ec=COLORS["kg_edge"],
        title_size=8.5,
        body_size=6.6,
    )
    contribution_pill(13, 30.2, 31, "C3  Graph-Backed Continual Adaptation", COLORS["kg_edge"], fs=6.3)

    # Evidence arrows use short vertical routes to avoid covering side notes.
    arrow(ax, (76, 32), (79, 46), color=COLORS["foundation_edge"], style="--", mutation_scale=8)
    arrow(ax, (101, 32), (114, 46), color=COLORS["foundation_edge"], style="--", mutation_scale=8)
    arrow(ax, (129, 32), (182, 46), color=COLORS["foundation_edge"], style="--", rad=-0.08, mutation_scale=8)
    arrow(ax, (156, 32), (150, 46), color=COLORS["foundation_edge"], style="--", mutation_scale=8)

    # Adaptation feedback is shown as scoped priors, not final labels.
    arrow(ax, (31, 32), (45, 46), color=COLORS["kg_edge"], style="--", rad=-0.06, mutation_scale=8)
    arrow(ax, (45, 32), (79, 46), color=COLORS["kg_edge"], style="--", rad=-0.08, mutation_scale=8)

    # Legend placed in unused lower-right space, away from flow arrows.
    legend_x, legend_y = 179, 13
    ax.text(legend_x, legend_y + 15.5, "Legend", fontsize=7.7, fontweight="bold", color=COLORS["ink"])
    for i, (name, color, ls) in enumerate(
        [
            ("main data flow", COLORS["line"], "-"),
            ("Git evidence", COLORS["foundation_edge"], "--"),
            ("condition / prior feedback", COLORS["kg_edge"], "--"),
        ]
    ):
        y = legend_y + 13.0 - i * 3.0
        ax.plot([legend_x, legend_x + 7.0], [y, y], color=color, lw=1.6, linestyle=ls)
        ax.text(legend_x + 7.8, y, name, va="center", fontsize=6.6, color=COLORS["muted"])

    ax.add_patch(Rectangle((1.2, 2.2), 217.6, 95.6, fill=False, edgecolor="#E5E7EB", linewidth=1.0))
    return fig
def main():
    fig = draw_overview()
    for ext in ("pdf", "svg", "png"):
        path = OUT_DIR / f"fig_vulngraph_overview.{ext}"
        fig.savefig(path, bbox_inches="tight", facecolor=fig.get_facecolor())
        print(path)
    plt.close(fig)


if __name__ == "__main__":
    main()

