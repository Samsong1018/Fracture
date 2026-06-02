"""
Payload generators for Intruder / Turbo Intruder.

Pure-Python generator functions returning iterators of strings, plus a
PayloadGeneratorDialog that exposes them to the GUI. Catppuccin Mocha styled.

Generators:
  - numbers(start, stop, step, pad, fmt)
  - brute(charset, min_len, max_len)         (capped at 5_000_000)
  - iterator_csv(path, columns, separator)
  - usernames(first_names, last_names, styles)
"""

from __future__ import annotations

import csv
import itertools
import logging
from typing import Iterator, Optional

from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Catppuccin Mocha tokens
# ---------------------------------------------------------------------------

_BG = "#1e1e2e"
_SURFACE = "#181825"
_OVERLAY = "#313244"
_HIGHLIGHT = "#45475a"
_TEXT = "#cdd6f4"
_SUBTEXT = "#a6adc8"

_LINEEDIT_SS = (
    "QLineEdit { background: #181825; border: 1px solid #313244; padding: 4px; color: #cdd6f4; }"
)
_TEXTEDIT_SS = "QTextEdit { background: #181825; border: 1px solid #313244; color: #cdd6f4; }"
_BTN_SS = (
    "QPushButton { background: #313244; border: 1px solid #45475a; "
    "padding: 4px 10px; border-radius: 4px; color: #cdd6f4; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:disabled { color: #585b70; }"
)
_COMBO_SS = (
    "QComboBox { background: #181825; border: 1px solid #313244; padding: 4px; color: #cdd6f4; }"
    "QComboBox QAbstractItemView { background: #181825; color: #cdd6f4; "
    "selection-background-color: #45475a; }"
)
_SPIN_SS = (
    "QSpinBox { background: #181825; border: 1px solid #313244; padding: 4px; color: #cdd6f4; }"
)
_LABEL_SS = f"color: {_SUBTEXT}; font-size: 11px;"

BRUTE_CAP = 5_000_000


# ---------------------------------------------------------------------------
# Generator functions
# ---------------------------------------------------------------------------


def numbers(
    start: int,
    stop: int,
    step: int = 1,
    pad: int = 0,
    fmt: str = "dec",
) -> Iterator[str]:
    """Yield numeric payloads from start to stop (inclusive) by step.

    fmt is one of {"dec","hex","oct","bin"}. pad is minimum width (left-padded
    with zeros). step must be non-zero; direction is inferred from start/stop.
    """
    if step == 0:
        raise ValueError("step must not be zero")
    if start <= stop:
        rng = range(start, stop + 1, abs(step))
    else:
        rng = range(start, stop - 1, -abs(step))

    fmt = (fmt or "dec").lower()
    for n in rng:
        if fmt == "dec":
            s = str(n)
        elif fmt == "hex":
            s = format(n if n >= 0 else (n & 0xFFFFFFFF), "x")
        elif fmt == "oct":
            s = format(n if n >= 0 else (n & 0xFFFFFFFF), "o")
        elif fmt == "bin":
            s = format(n if n >= 0 else (n & 0xFFFFFFFF), "b")
        else:
            raise ValueError(f"unknown fmt: {fmt!r}")
        if pad > 0:
            s = s.zfill(pad)
        yield s


def brute(charset: str, min_len: int, max_len: int) -> Iterator[str]:
    """Yield every combination over charset for lengths in [min_len, max_len].

    Capped at BRUTE_CAP (5M) yielded items as a safety guard.
    """
    if not charset:
        return
    if min_len < 1 or max_len < min_len:
        raise ValueError("require 1 <= min_len <= max_len")

    count = 0
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            if count >= BRUTE_CAP:
                log.warning("brute(): hit BRUTE_CAP of %d items, stopping", BRUTE_CAP)
                return
            yield "".join(combo)
            count += 1


def iterator_csv(
    path: str,
    columns: Optional[list[int]] = None,
    separator: str = ",",
) -> Iterator[str]:
    """Yield cartesian product across selected columns of a CSV file.

    When columns is None, yields every cell of every row. When columns is a
    list of column indices, yields the cartesian product of all values seen in
    those columns (each unique row position) joined by the separator.

    If only one column is selected, simply yields each value in that column.
    """
    rows: list[list[str]] = []
    try:
        with open(path, "r", newline="", encoding="utf-8") as fh:
            reader = csv.reader(fh)
            for row in reader:
                rows.append(row)
    except OSError as exc:
        log.error("iterator_csv: cannot open %s: %s", path, exc)
        return

    if not rows:
        return

    if columns is None:
        for row in rows:
            for cell in row:
                if cell != "":
                    yield cell
        return

    # Collect values per requested column
    col_values: list[list[str]] = []
    for col in columns:
        seen: list[str] = []
        for row in rows:
            if col < len(row) and row[col] != "":
                seen.append(row[col])
        if seen:
            col_values.append(seen)

    if not col_values:
        return
    if len(col_values) == 1:
        for v in col_values[0]:
            yield v
        return

    for combo in itertools.product(*col_values):
        yield separator.join(combo)


def usernames(
    first_names: list[str],
    last_names: list[str],
    styles: list[str],
) -> Iterator[str]:
    """Yield generated usernames from first/last name lists for each style.

    Supported styles:
      - "first"           -> alice
      - "last"            -> smith
      - "first.last"      -> alice.smith
      - "first_last"      -> alice_smith
      - "firstlast"       -> alicesmith
      - "first-last"      -> alice-smith
      - "flast"           -> asmith
      - "firstl"          -> alices
      - "f.last"          -> a.smith
      - "first1"          -> alice1 .. alice9 (digits suffix)
      - "first.last99"    -> alice.smith01 .. alice.smith99 (sample)
      - "last.first"      -> smith.alice
    """
    digits_short = [str(i) for i in range(1, 10)]
    digits_long = [f"{i:02d}" for i in (1, 7, 99, 2024)]

    for f in first_names:
        for l in last_names:
            for style in styles:
                fl = f.lower()
                ll = l.lower()
                if style == "first":
                    yield fl
                elif style == "last":
                    yield ll
                elif style == "first.last":
                    yield f"{fl}.{ll}"
                elif style == "first_last":
                    yield f"{fl}_{ll}"
                elif style == "firstlast":
                    yield f"{fl}{ll}"
                elif style == "first-last":
                    yield f"{fl}-{ll}"
                elif style == "flast":
                    yield f"{fl[:1]}{ll}"
                elif style == "firstl":
                    yield f"{fl}{ll[:1]}"
                elif style == "f.last":
                    yield f"{fl[:1]}.{ll}"
                elif style == "last.first":
                    yield f"{ll}.{fl}"
                elif style == "first1":
                    for d in digits_short:
                        yield f"{fl}{d}"
                elif style == "first.last99":
                    for d in digits_long:
                        yield f"{fl}.{ll}{d}"
                else:
                    log.warning("usernames: unknown style %r", style)


# ---------------------------------------------------------------------------
# PayloadGeneratorDialog
# ---------------------------------------------------------------------------


class PayloadGeneratorDialog(QDialog):
    """Dialog that lets the user pick a generator type and produce payloads.

    Call .exec(); after Accept, .payloads() returns the produced list[str].
    """

    GENERATORS = ["Numbers", "Brute Force", "CSV", "Usernames"]

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Generate Payloads")
        self.setStyleSheet(f"QDialog {{ background: {_BG}; color: {_TEXT}; }} QLabel {{ color: {_TEXT}; }}")
        self.resize(540, 540)

        self._payloads: list[str] = []
        self._build_ui()

    # ----- public ----------------------------------------------------------

    def payloads(self) -> list[str]:
        """Return the most recently generated list (empty until generated)."""
        return list(self._payloads)

    # ----- UI construction -------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # Type selector
        type_row = QHBoxLayout()
        lbl = QLabel("Generator:")
        lbl.setStyleSheet(_LABEL_SS)
        type_row.addWidget(lbl)
        self.type_combo = QComboBox()
        self.type_combo.addItems(self.GENERATORS)
        self.type_combo.setStyleSheet(_COMBO_SS)
        self.type_combo.currentIndexChanged.connect(self._on_type_changed)
        type_row.addWidget(self.type_combo, 1)
        root.addLayout(type_row)

        # Stacked param panes
        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_numbers_pane())
        self.stack.addWidget(self._build_brute_pane())
        self.stack.addWidget(self._build_csv_pane())
        self.stack.addWidget(self._build_usernames_pane())
        root.addWidget(self.stack)

        # Preview
        prev_lbl = QLabel("Preview (first 200)")
        prev_lbl.setStyleSheet(_LABEL_SS)
        root.addWidget(prev_lbl)
        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setStyleSheet(_TEXTEDIT_SS)
        root.addWidget(self.preview, 1)

        # Status / count
        self.status_lbl = QLabel("Click Generate to produce payloads.")
        self.status_lbl.setStyleSheet(_LABEL_SS)
        root.addWidget(self.status_lbl)

        # Buttons
        btn_row = QHBoxLayout()
        gen_btn = QPushButton("Generate")
        gen_btn.setStyleSheet(_BTN_SS)
        gen_btn.clicked.connect(self._on_generate)
        btn_row.addWidget(gen_btn)
        btn_row.addStretch()
        bbox = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        for b in bbox.buttons():
            b.setStyleSheet(_BTN_SS)
        bbox.accepted.connect(self.accept)
        bbox.rejected.connect(self.reject)
        btn_row.addWidget(bbox)
        root.addLayout(btn_row)

    def _build_numbers_pane(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        self.num_start = QSpinBox()
        self.num_start.setRange(-10_000_000, 10_000_000)
        self.num_start.setValue(1)
        self.num_start.setStyleSheet(_SPIN_SS)
        self.num_stop = QSpinBox()
        self.num_stop.setRange(-10_000_000, 10_000_000)
        self.num_stop.setValue(100)
        self.num_stop.setStyleSheet(_SPIN_SS)
        self.num_step = QSpinBox()
        self.num_step.setRange(1, 1_000_000)
        self.num_step.setValue(1)
        self.num_step.setStyleSheet(_SPIN_SS)
        self.num_pad = QSpinBox()
        self.num_pad.setRange(0, 32)
        self.num_pad.setValue(0)
        self.num_pad.setStyleSheet(_SPIN_SS)
        self.num_fmt = QComboBox()
        self.num_fmt.addItems(["dec", "hex", "oct", "bin"])
        self.num_fmt.setStyleSheet(_COMBO_SS)
        form.addRow(_lbl("Start"), self.num_start)
        form.addRow(_lbl("Stop"), self.num_stop)
        form.addRow(_lbl("Step"), self.num_step)
        form.addRow(_lbl("Pad width"), self.num_pad)
        form.addRow(_lbl("Format"), self.num_fmt)
        return w

    def _build_brute_pane(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        self.brute_charset = QLineEdit("abc")
        self.brute_charset.setStyleSheet(_LINEEDIT_SS)
        self.brute_min = QSpinBox()
        self.brute_min.setRange(1, 12)
        self.brute_min.setValue(1)
        self.brute_min.setStyleSheet(_SPIN_SS)
        self.brute_max = QSpinBox()
        self.brute_max.setRange(1, 12)
        self.brute_max.setValue(3)
        self.brute_max.setStyleSheet(_SPIN_SS)
        form.addRow(_lbl("Charset"), self.brute_charset)
        form.addRow(_lbl("Min length"), self.brute_min)
        form.addRow(_lbl("Max length"), self.brute_max)
        return w

    def _build_csv_pane(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        path_row = QHBoxLayout()
        self.csv_path = QLineEdit()
        self.csv_path.setStyleSheet(_LINEEDIT_SS)
        path_row.addWidget(self.csv_path, 1)
        browse = QPushButton("Browse...")
        browse.setStyleSheet(_BTN_SS)
        browse.clicked.connect(self._on_browse_csv)
        path_row.addWidget(browse)
        container = QWidget()
        container.setLayout(path_row)
        self.csv_columns = QLineEdit()
        self.csv_columns.setPlaceholderText("e.g. 0,1   (blank for all cells)")
        self.csv_columns.setStyleSheet(_LINEEDIT_SS)
        self.csv_sep = QLineEdit(",")
        self.csv_sep.setStyleSheet(_LINEEDIT_SS)
        form.addRow(_lbl("CSV path"), container)
        form.addRow(_lbl("Columns"), self.csv_columns)
        form.addRow(_lbl("Join separator"), self.csv_sep)
        return w

    def _build_usernames_pane(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        self.un_first = QTextEdit("alice\nbob\ncarol")
        self.un_first.setStyleSheet(_TEXTEDIT_SS)
        self.un_first.setMaximumHeight(80)
        self.un_last = QTextEdit("smith\njones")
        self.un_last.setStyleSheet(_TEXTEDIT_SS)
        self.un_last.setMaximumHeight(80)
        self.un_styles = QLineEdit("first.last,flast,first_last,first1")
        self.un_styles.setStyleSheet(_LINEEDIT_SS)
        form.addRow(_lbl("First names (one per line)"), self.un_first)
        form.addRow(_lbl("Last names (one per line)"), self.un_last)
        form.addRow(_lbl("Styles (comma)"), self.un_styles)
        return w

    # ----- slots -----------------------------------------------------------

    def _on_type_changed(self, idx: int) -> None:
        self.stack.setCurrentIndex(idx)

    def _on_browse_csv(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open CSV", "", "CSV files (*.csv);;All files (*)")
        if path:
            self.csv_path.setText(path)

    def _on_generate(self) -> None:
        try:
            payloads = list(self._generate_for_current())
        except Exception as exc:
            log.exception("Payload generation failed")
            self.status_lbl.setText(f"Error: {exc}")
            self._payloads = []
            return
        self._payloads = payloads
        preview = "\n".join(payloads[:200])
        suffix = f"\n... (+{len(payloads) - 200} more)" if len(payloads) > 200 else ""
        self.preview.setPlainText(preview + suffix)
        self.status_lbl.setText(f"Generated {len(payloads)} payload(s).")

    def _generate_for_current(self) -> Iterator[str]:
        kind = self.type_combo.currentText()
        if kind == "Numbers":
            return numbers(
                self.num_start.value(),
                self.num_stop.value(),
                self.num_step.value(),
                self.num_pad.value(),
                self.num_fmt.currentText(),
            )
        if kind == "Brute Force":
            return brute(
                self.brute_charset.text(),
                self.brute_min.value(),
                self.brute_max.value(),
            )
        if kind == "CSV":
            cols_text = self.csv_columns.text().strip()
            cols: Optional[list[int]] = None
            if cols_text:
                cols = [int(x) for x in cols_text.split(",") if x.strip()]
            return iterator_csv(
                self.csv_path.text().strip(),
                cols,
                self.csv_sep.text() or ",",
            )
        if kind == "Usernames":
            firsts = [x.strip() for x in self.un_first.toPlainText().splitlines() if x.strip()]
            lasts = [x.strip() for x in self.un_last.toPlainText().splitlines() if x.strip()]
            styles = [x.strip() for x in self.un_styles.text().split(",") if x.strip()]
            return usernames(firsts, lasts, styles)
        return iter([])


def _lbl(text: str) -> QLabel:
    w = QLabel(text)
    w.setStyleSheet(_LABEL_SS)
    return w


__all__ = [
    "numbers",
    "brute",
    "iterator_csv",
    "usernames",
    "PayloadGeneratorDialog",
    "BRUTE_CAP",
]
