//! Runtime-agnostic terminal snapshot types (spec §5.3).
//!
//! The terminal layer parses the raw VT/ANSI byte stream and exposes an
//! immutable [`Grid`] snapshot for the GUI to paint. The GUI knows nothing about
//! the parser — only about cells, colours and a cursor (spec §7.2).

use serde::{Deserialize, Serialize};

/// Terminal dimensions in cells plus the pixel size used to size the PTY so
/// full-screen TUIs (`vim`, `htop`, `tmux`) lay out correctly (spec §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtySize {
    pub cols: u16,
    pub rows: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl Default for PtySize {
    fn default() -> Self {
        Self {
            cols: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

impl PtySize {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            cols,
            rows,
            ..Default::default()
        }
    }
}

/// A terminal colour. Mirrors the three ways ANSI addresses colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Color {
    /// Default fg/bg — the theme decides the actual pixel value.
    Default,
    /// One of the 16 named ANSI colours (0..=15).
    Named(u8),
    /// 256-colour palette index.
    Indexed(u8),
    /// Truecolor.
    Rgb(u8, u8, u8),
}

impl Default for Color {
    fn default() -> Self {
        Color::Default
    }
}

/// Text attributes for a cell (spec §5.3 "атрибуты текста").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Attrs {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikethrough: bool,
    pub inverse: bool,
    pub dim: bool,
    pub hidden: bool,
}

/// One screen cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cell {
    pub ch: char,
    pub fg: Color,
    pub bg: Color,
    pub attrs: Attrs,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: ' ',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attrs::default(),
        }
    }
}

/// Cursor rendering style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CursorShape {
    Block,
    Underline,
    Beam,
    Hidden,
}

impl Default for CursorShape {
    fn default() -> Self {
        CursorShape::Block
    }
}

/// An immutable snapshot of the visible screen, handed to the GUI for painting.
///
/// `cells` is row-major, length `cols * rows`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grid {
    pub cols: u16,
    pub rows: u16,
    pub cells: Vec<Cell>,
    /// Cursor position as `(col, row)`.
    pub cursor: (u16, u16),
    pub cursor_shape: CursorShape,
    /// Title set via the OSC title escape, if any.
    pub title: Option<String>,
}

impl Grid {
    /// A blank grid of the given size (used before the first frame arrives).
    pub fn blank(cols: u16, rows: u16) -> Self {
        Self {
            cols,
            rows,
            cells: vec![Cell::default(); cols as usize * rows as usize],
            cursor: (0, 0),
            cursor_shape: CursorShape::Block,
            title: None,
        }
    }

    /// Cell at `(col, row)`, or `None` if out of bounds.
    pub fn cell(&self, col: u16, row: u16) -> Option<&Cell> {
        if col >= self.cols || row >= self.rows {
            return None;
        }
        self.cells.get(row as usize * self.cols as usize + col as usize)
    }

    /// The plain text of one row, trailing blanks trimmed — handy for tests and
    /// copy/paste (spec §5.3).
    pub fn row_text(&self, row: u16) -> String {
        if row >= self.rows {
            return String::new();
        }
        let start = row as usize * self.cols as usize;
        let end = start + self.cols as usize;
        let s: String = self.cells[start..end].iter().map(|c| c.ch).collect();
        s.trim_end().to_string()
    }
}
