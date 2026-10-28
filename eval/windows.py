"""Context windows: the ±N lines around labelled lines that the deep scan reads."""

import os


def window_lines(units, counts, radius):
    """``{file: sorted line numbers}``: each unit's range widened by ``radius`` lines, merged per file."""
    wanted = {}
    for unit in units:
        lines = wanted.setdefault(unit.file, set())
        low = max(1, unit.start - radius)
        high = min(counts[unit.file], unit.end + radius)
        lines.update(range(low, high + 1))
    return {file: sorted(lines) for file, lines in wanted.items()}


def read_lines(root, file):
    with open(os.path.join(root, file), "rb") as handle:
        return handle.read().split(b"\n")


def write_blanked(root, out_root, windows):
    """Copy each file to ``out_root`` keeping only window lines (others blank, numbering intact).

    Gitleaks then sees the same lines at the same numbers as the deep scan
    does, under the same file name and extension. Returns the byte total of
    the kept lines (what the model will read).
    """
    kept_bytes = 0
    for file, lines in windows.items():
        source = read_lines(root, file)
        keep = set(lines)
        out = []
        for number, text in enumerate(source, start=1):
            if number in keep:
                out.append(text.rstrip(b"\r"))
                kept_bytes += len(text) + 1
            else:
                out.append(b"")
        target = os.path.join(out_root, file)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(b"\n".join(out))
    return kept_bytes


def additions(root, windows):
    """``[(file, line, bytes)]`` for the non-empty window lines: the deep scan's input."""
    result = []
    for file, lines in windows.items():
        source = read_lines(root, file)
        for number in lines:
            text = source[number - 1].rstrip(b"\r")
            if text.strip():
                result.append((file, number, text))
    return result
