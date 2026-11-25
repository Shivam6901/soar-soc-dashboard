"""Plotly timeline visualization and local timestamp helpers for the SOAR dashboard."""

import datetime

import pandas as pd
import plotly.graph_objects as go


def to_local_naive_dt(epoch_series: pd.Series) -> pd.Series:
    """Convert Unix epoch seconds to timezone-naive local datetime matching host clock."""
    local_tz = datetime.datetime.now().astimezone().tzinfo
    return (
        pd.to_datetime(epoch_series, unit="s", utc=True)
        .dt.tz_convert(local_tz)
        .dt.tz_localize(None)
    )


def build_incident_timeline_chart(
    packet_rates: pd.DataFrame,
    attacker_rates: pd.Series | None,
    top_attacker_ip: str | None,
    ddos_threshold: int,
    mitigation_log: list[dict],
) -> go.Figure:
    """Build a multi-curve SOC incident timeline with breach shading and event markers."""
    plot_df = packet_rates.tail(90).copy() if len(packet_rates) > 90 else packet_rates.copy()
    plot_df["Baseline"] = plot_df["Packet Rate"].rolling(window=6, min_periods=1).mean()

    fig = go.Figure()

    # 1. Shade attack breach intervals so the story is visible at a glance
    in_breach = False
    breach_start = None
    first_breach_dt = None
    for _, row in plot_df.iterrows():
        ts = row["Timestamp_dt"]
        over = row["Packet Rate"] > ddos_threshold
        if over and not in_breach:
            in_breach = True
            breach_start = ts
            if first_breach_dt is None:
                first_breach_dt = ts
        elif not over and in_breach:
            fig.add_vrect(
                x0=breach_start,
                x1=ts,
                fillcolor="rgba(244, 63, 94, 0.14)",
                line_width=0,
                layer="below",
            )
            in_breach = False
    if in_breach and breach_start is not None:
        fig.add_vrect(
            x0=breach_start,
            x1=plot_df["Timestamp_dt"].iloc[-1],
            fillcolor="rgba(244, 63, 94, 0.14)",
            line_width=0,
            layer="below",
        )

    # 2. Moving baseline curve
    fig.add_trace(
        go.Scatter(
            x=plot_df["Timestamp_dt"],
            y=plot_df["Baseline"],
            mode="lines",
            line=dict(color="#64748b", width=1.8, dash="dot", shape="spline", smoothing=0.9),
            name="Baseline Trend (6s avg)",
            hovertemplate="%{y:.0f} PPS<extra>Baseline Trend</extra>",
        )
    )

    # 3. Total traffic curve (smooth glowing cyan spline)
    fig.add_trace(
        go.Scatter(
            x=plot_df["Timestamp_dt"],
            y=plot_df["Packet Rate"],
            mode="lines",
            line=dict(color="#38bdf8", width=3, shape="spline", smoothing=0.85),
            fill="tozeroy",
            fillcolor="rgba(56, 189, 248, 0.12)",
            name="Total Traffic (PPS)",
            hovertemplate="%{y:.0f} PPS<extra>Total Traffic</extra>",
        )
    )

    # 4. Primary attacker traffic curve (amber/rose spline)
    if attacker_rates is not None and top_attacker_ip:
        att_y = attacker_rates.reindex(plot_df["Timestamp_dt"], fill_value=0)
        fig.add_trace(
            go.Scatter(
                x=plot_df["Timestamp_dt"],
                y=att_y.values,
                mode="lines",
                line=dict(color="#fb7185", width=2.4, shape="spline", smoothing=0.85),
                fill="tozeroy",
                fillcolor="rgba(244, 63, 94, 0.10)",
                name=f"Top Source ({top_attacker_ip})",
                hovertemplate="%{y:.0f} PPS<extra>Top Source</extra>",
            )
        )

    # 5. Threshold line
    fig.add_hline(
        y=ddos_threshold,
        line=dict(color="#fbbf24", dash="dash", width=1.5),
        annotation_text=f"Alert Limit: {ddos_threshold} PPS",
        annotation_position="top left",
        annotation_font=dict(color="#fbbf24", size=11),
    )

    # 6. Highlight Peak Attack Spike on timeline
    max_idx = plot_df["Packet Rate"].idxmax()
    peak_val = int(plot_df.loc[max_idx, "Packet Rate"])
    peak_ts = plot_df.loc[max_idx, "Timestamp_dt"]
    if peak_val > ddos_threshold:
        fig.add_trace(
            go.Scatter(
                x=[peak_ts],
                y=[peak_val],
                mode="markers+text",
                marker=dict(color="#f43f5e", size=10, line=dict(color="#ffffff", width=1.5)),
                text=[f"Peak: {peak_val} PPS"],
                textposition="top center",
                textfont=dict(color="#fda4af", size=11, family="JetBrains Mono"),
                showlegend=False,
                hoverinfo="skip",
            )
        )

    # 7. Mark Breach Start
    if first_breach_dt is not None:
        fig.add_vline(
            x=first_breach_dt,
            line=dict(color="#f43f5e", dash="dot", width=1.3),
        )
        fig.add_annotation(
            x=first_breach_dt,
            y=1.0,
            yref="paper",
            text="Attack Started",
            showarrow=False,
            xanchor="left",
            yanchor="bottom",
            font=dict(color="#fda4af", size=10.5, family="JetBrains Mono"),
        )

    # 8. Mark Firewall Block Event(s) inside visible window
    t_min, t_max = plot_df["Timestamp_dt"].min(), plot_df["Timestamp_dt"].max()
    for entry in mitigation_log:
        if not entry.get("Success", True):
            continue
        epoch = entry.get("Detection Epoch")
        if epoch:
            block_dt = to_local_naive_dt(pd.Series([epoch])).iloc[0]
            if t_min <= block_dt <= t_max:
                fig.add_vline(
                    x=block_dt,
                    line=dict(color="#10b981", dash="dash", width=1.8),
                )
                fig.add_annotation(
                    x=block_dt,
                    y=0.92,
                    yref="paper",
                    text=f"Blocked {entry['Attacking IP']}",
                    showarrow=False,
                    xanchor="left",
                    bgcolor="rgba(16, 185, 129, 0.18)",
                    bordercolor="#10b981",
                    borderwidth=1,
                    font=dict(color="#6ee7b7", size=10.5, family="JetBrains Mono"),
                )

    y_ceiling = max(peak_val * 1.25, ddos_threshold * 1.35, 30)
    fig.update_layout(
        height=330,
        margin=dict(l=12, r=16, t=34, b=12),
        paper_bgcolor="#0c1322",
        plot_bgcolor="#090f1c",
        hovermode="x unified",
        font=dict(color="#cbd5e1", family="Inter, sans-serif", size=12),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1.0,
            bgcolor="rgba(0,0,0,0)",
            font=dict(size=11.5),
        ),
        xaxis=dict(
            showgrid=True,
            gridcolor="#172338",
            zeroline=False,
            tickformat="%H:%M:%S",
            title=None,
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor="#172338",
            zeroline=False,
            title="Packets / Sec (PPS)",
            range=[0, y_ceiling],
        ),
    )
    return fig
