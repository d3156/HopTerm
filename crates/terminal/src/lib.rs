//! VT/ANSI terminal engine backed by `alacritty_terminal` (spec §5.3).
//!
//! Raw bytes from the [`ShellChannel`](hopterm_domain::ShellChannel) are fed in;
//! the GUI pulls immutable [`Grid`] snapshots out. The GUI never sees an
//! alacritty type — only the domain's [`Grid`]/[`Cell`]/[`Color`] — so the VT
//! parser can be swapped without touching the UI (§7.2).
//!
//! Because `alacritty_terminal` correctly implements the xterm state machine,
//! full-screen TUIs (`vim`, `htop`, `tmux`, `less`, `nano`) render correctly
//! (acceptance criterion §14).

use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::Config;
use alacritty_terminal::vte::ansi::{
    Color as AnsiColor, CursorShape as AnsiCursorShape, NamedColor, Processor,
};
use alacritty_terminal::Term;

use hopterm_domain::{Attrs, Cell, Color, CursorShape, Grid, PtySize, TerminalBackend};

/// Minimal [`Dimensions`] describing the visible screen. Scrollback history is
/// grown by alacritty itself up to its configured maximum.
#[derive(Debug, Clone, Copy)]
struct Size {
    columns: usize,
    screen_lines: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.screen_lines
    }
    fn screen_lines(&self) -> usize {
        self.screen_lines
    }
    fn columns(&self) -> usize {
        self.columns
    }
}

/// We don't need terminal events (bells, clipboard, title) in the engine layer
/// for the MVP, so the listener is a no-op.
#[derive(Clone)]
struct NopListener;
impl EventListener for NopListener {
    fn send_event(&self, _event: Event) {}
}

/// The concrete [`TerminalBackend`].
pub struct AlacrittyTerminal {
    term: Term<NopListener>,
    parser: Processor,
    size: Size,
}

impl AlacrittyTerminal {
    pub fn new(size: PtySize) -> Self {
        let size = Size {
            columns: size.cols.max(1) as usize,
            screen_lines: size.rows.max(1) as usize,
        };
        let term = Term::new(Config::default(), &size, NopListener);
        Self {
            term,
            parser: Processor::new(),
            size,
        }
    }
}

impl TerminalBackend for AlacrittyTerminal {
    fn feed(&mut self, bytes: &[u8]) {
        self.parser.advance(&mut self.term, bytes);
    }

    fn resize(&mut self, size: PtySize) {
        self.size = Size {
            columns: size.cols.max(1) as usize,
            screen_lines: size.rows.max(1) as usize,
        };
        self.term.resize(self.size);
    }

    fn snapshot(&self) -> Grid {
        let cols = self.size.columns as u16;
        let rows = self.size.screen_lines as u16;
        let grid = self.term.grid();
        let mut cells = Vec::with_capacity(cols as usize * rows as usize);

        for row in 0..rows as i32 {
            let line = &grid[Line(row)];
            for col in 0..cols as usize {
                let c = &line[Column(col)];
                cells.push(Cell {
                    ch: c.c,
                    fg: map_color(c.fg),
                    bg: map_color(c.bg),
                    attrs: map_flags(c.flags),
                });
            }
        }

        let cursor_point = grid.cursor.point;
        let cursor = (cursor_point.column.0 as u16, cursor_point.line.0.max(0) as u16);

        Grid {
            cols,
            rows,
            cells,
            cursor,
            cursor_shape: map_cursor_shape(self.term.cursor_style().shape),
            title: None,
        }
    }

    fn selection_text(&self, start: (u16, u16), end: (u16, u16)) -> String {
        // Row-range plain-text extraction is sufficient for the MVP's
        // copy/paste; rectangular and semantic selection are post-MVP (§12).
        let snap = self.snapshot();
        let (mut lo, mut hi) = (start.1, end.1);
        if lo > hi {
            std::mem::swap(&mut lo, &mut hi);
        }
        (lo..=hi)
            .map(|r| snap.row_text(r))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn scroll(&mut self, delta_lines: i32) {
        self.term.scroll_display(Scroll::Delta(delta_lines));
    }
}

fn map_color(c: AnsiColor) -> Color {
    match c {
        AnsiColor::Spec(rgb) => Color::Rgb(rgb.r, rgb.g, rgb.b),
        AnsiColor::Indexed(i) => {
            if i < 16 {
                Color::Named(i)
            } else {
                Color::Indexed(i)
            }
        }
        AnsiColor::Named(named) => match named {
            NamedColor::Black => Color::Named(0),
            NamedColor::Red => Color::Named(1),
            NamedColor::Green => Color::Named(2),
            NamedColor::Yellow => Color::Named(3),
            NamedColor::Blue => Color::Named(4),
            NamedColor::Magenta => Color::Named(5),
            NamedColor::Cyan => Color::Named(6),
            NamedColor::White => Color::Named(7),
            NamedColor::BrightBlack => Color::Named(8),
            NamedColor::BrightRed => Color::Named(9),
            NamedColor::BrightGreen => Color::Named(10),
            NamedColor::BrightYellow => Color::Named(11),
            NamedColor::BrightBlue => Color::Named(12),
            NamedColor::BrightMagenta => Color::Named(13),
            NamedColor::BrightCyan => Color::Named(14),
            NamedColor::BrightWhite => Color::Named(15),
            // Foreground / Background / Cursor / dim variants -> theme default.
            _ => Color::Default,
        },
    }
}

fn map_flags(flags: Flags) -> Attrs {
    Attrs {
        bold: flags.contains(Flags::BOLD),
        italic: flags.contains(Flags::ITALIC),
        underline: flags.contains(Flags::UNDERLINE),
        strikethrough: flags.contains(Flags::STRIKEOUT),
        inverse: flags.contains(Flags::INVERSE),
        dim: flags.contains(Flags::DIM),
        hidden: flags.contains(Flags::HIDDEN),
    }
}

fn map_cursor_shape(shape: AnsiCursorShape) -> CursorShape {
    match shape {
        AnsiCursorShape::Block => CursorShape::Block,
        AnsiCursorShape::Underline => CursorShape::Underline,
        AnsiCursorShape::Beam => CursorShape::Beam,
        AnsiCursorShape::HollowBlock => CursorShape::Block,
        AnsiCursorShape::Hidden => CursorShape::Hidden,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_plain_text() {
        let mut t = AlacrittyTerminal::new(PtySize::new(20, 5));
        t.feed(b"hello");
        let snap = t.snapshot();
        assert_eq!(snap.cols, 20);
        assert_eq!(snap.rows, 5);
        assert_eq!(&snap.row_text(0), "hello");
    }

    #[test]
    fn handles_ansi_color_and_newline() {
        let mut t = AlacrittyTerminal::new(PtySize::new(20, 5));
        // Red "X", reset, then CR/LF + "Y".
        t.feed(b"\x1b[31mX\x1b[0m\r\nY");
        let snap = t.snapshot();
        assert_eq!(snap.cell(0, 0).unwrap().ch, 'X');
        assert_eq!(snap.cell(0, 0).unwrap().fg, Color::Named(1));
        assert_eq!(snap.cell(0, 1).unwrap().ch, 'Y');
    }
}
