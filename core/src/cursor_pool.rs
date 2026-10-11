//! # Thread-Local Tree-sitter QueryCursor Pool
//!
//! Allocating a `QueryCursor` per file in a Rayon parallel loop creates significant
//! heap churn (each cursor allocates internal scratch buffers on the order of ~8 KB).
//! On a 32-core machine scanning 50 000 files, this means ~1.6 GB of throwaway
//! allocations per scan.
//!
//! This module provides a zero-contention `thread_local!` cursor that is created once
//! per Rayon worker thread and reused across all files processed by that thread.
//!
//! ## Usage
//! ```rust,ignore
//! use cursor_pool::with_cursor;
//! use tree_sitter::Query;
//!
//! let query: Query = /* ... */;
//! let node = /* ... */;
//! let source = b"...";
//!
//! let matches: Vec<_> = with_cursor(|cursor| {
//!     cursor.matches(&query, node, source).collect()
//! });
//! ```

use std::cell::RefCell;
use tree_sitter::QueryCursor;

thread_local! {
    /// One `QueryCursor` per Rayon thread.  Reset via `QueryCursor::set_point_range`
    /// before each use so previous state never leaks between files.
    static CURSOR: RefCell<QueryCursor> = RefCell::new(QueryCursor::new());
}

/// Borrows the thread-local cursor for the duration of `f`.
///
/// The cursor is automatically reset to full-range mode before being handed to `f`,
/// ensuring no state leaks from previous calls.
///
/// # Panics
/// Panics if `f` itself tries to call `with_cursor` recursively (would violate
/// the `RefCell` borrow rules).  The pipeline never does this.
#[inline]
pub fn with_cursor<F, R>(f: F) -> R
where
    F: FnOnce(&mut QueryCursor) -> R,
{
    CURSOR.with(|cell| {
        let mut cursor = cell.borrow_mut();
        // Reset to full document range so previous targeted scans don't affect us.
        cursor.set_point_range(
            tree_sitter::Point { row: 0, column: 0 }..tree_sitter::Point {
                row: usize::MAX,
                column: usize::MAX,
            },
        );
        f(&mut cursor)
    })
}

/// Sets the byte range on the thread-local cursor for targeted (dirty-range) scans,
/// then calls `f`.  Use this instead of `with_cursor` when you only want to query a
/// specific region of a file.
#[inline]
pub fn with_cursor_range<F, R>(start_byte: usize, end_byte: usize, f: F) -> R
where
    F: FnOnce(&mut QueryCursor) -> R,
{
    CURSOR.with(|cell| {
        let mut cursor = cell.borrow_mut();
        cursor.set_byte_range(start_byte..end_byte);
        f(&mut cursor)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_accessible_from_multiple_closures() {
        let a = with_cursor(|_| 42u32);
        let b = with_cursor(|_| 99u32);
        assert_eq!(a, 42);
        assert_eq!(b, 99);
    }

    #[test]
    fn range_cursor_does_not_panic() {
        let result = with_cursor_range(0, 100, |_cursor| "ok");
        assert_eq!(result, "ok");
    }
}
