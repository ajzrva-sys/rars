use super::{Member, Node, Occurrence, RepeatIndex, NONE};
use crate::{Error, Result};

/// A cumulative allowance for logical index accesses, reusable across patterns.
/// Every node record, member record and captured byte read consumes one unit,
/// including cache hits. This bounds query effort rather than physical I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryBudget {
    limit: u64,
    remaining: u64,
}

impl QueryBudget {
    pub const fn new(max_accesses: u64) -> Self {
        Self {
            limit: max_accesses,
            remaining: max_accesses,
        }
    }

    pub const fn remaining(&self) -> u64 {
        self.remaining
    }

    pub const fn used(&self) -> u64 {
        self.limit - self.remaining
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryResult {
    /// Occurrences accepted by a visitor returning true.
    pub occurrences: u64,
    /// False means budget exhaustion or a visitor-requested stop. In
    /// particular, zero occurrences with complete=false is an unknown result.
    pub complete: bool,
}

enum Subtree {
    Exhausted,
    Absent,
    Root(u64),
}

struct Query<'a> {
    index: &'a mut RepeatIndex,
    budget: &'a mut QueryBudget,
    cancelled: &'a dyn Fn() -> bool,
}

impl Query<'_> {
    fn check(&self) -> Result<()> {
        if (self.cancelled)() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }

    fn admit(&mut self) -> Result<bool> {
        self.check()?;
        if self.budget.remaining == 0 {
            return Ok(false);
        }
        self.budget.remaining -= 1;
        Ok(true)
    }

    fn node(&mut self, id: u64) -> Result<Option<Node>> {
        if !self.admit()? {
            return Ok(None);
        }
        self.index.nodes.get(id).map(Some)
    }

    fn member(&mut self, id: u64) -> Result<Option<Member>> {
        if !self.admit()? {
            return Ok(None);
        }
        self.index.members.get(id).map(Some)
    }

    fn byte(&mut self, offset: u64) -> Result<Option<u8>> {
        if !self.admit()? {
            return Ok(None);
        }
        self.index.bytes.get(offset).map(Some)
    }

    fn member_at_text(&mut self, pos: u64) -> Result<Option<(u64, Member)>> {
        let mut low = 0;
        let mut high = self.index.members.length;
        while low < high {
            let mid = low + (high - low) / 2;
            let Some(member) = self.member(mid)? else {
                return Ok(None);
            };
            if member.text_start <= pos {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        if low == 0 {
            return Err(Error::WriterFailure("hybrid text position precedes input"));
        }
        let ordinal = low - 1;
        let Some(member) = self.member(ordinal)? else {
            return Ok(None);
        };
        if pos - member.text_start > member.length {
            return Err(Error::WriterFailure("hybrid text position exceeds member"));
        }
        Ok(Some((ordinal, member)))
    }

    fn symbol(&mut self, pos: u64) -> Result<Option<u64>> {
        let Some((ordinal, member)) = self.member_at_text(pos)? else {
            return Ok(None);
        };
        let offset = pos - member.text_start;
        if offset == member.length {
            Ok(Some(256 + ordinal))
        } else {
            self.byte(member.raw_start + offset)
                .map(|byte| byte.map(u64::from))
        }
    }

    fn edge_end(&mut self, node: Node) -> Result<Option<u64>> {
        if node.end != NONE {
            return Ok(Some(node.end));
        }
        let Some(member) = self.member(node.owner)? else {
            return Ok(None);
        };
        member
            .text_start
            .checked_add(member.length)
            .and_then(|end| end.checked_add(1))
            .map(Some)
            .ok_or(Error::WriterFailure("hybrid leaf end overflows"))
    }

    fn matching_subtree(&mut self, pattern: &[u8]) -> Result<Subtree> {
        let mut current = 0;
        let mut at = 0;
        while at < pattern.len() {
            let Some(parent) = self.node(current)? else {
                return Ok(Subtree::Exhausted);
            };
            let mut child = parent.first_child;
            let edge = loop {
                if child == NONE {
                    return Ok(Subtree::Absent);
                }
                let Some(edge) = self.node(child)? else {
                    return Ok(Subtree::Exhausted);
                };
                if edge.first_symbol == u64::from(pattern[at]) {
                    break edge;
                }
                child = edge.next_sibling;
            };
            let Some(end) = self.edge_end(edge)? else {
                return Ok(Subtree::Exhausted);
            };
            for pos in edge.start..end {
                let Some(symbol) = self.symbol(pos)? else {
                    return Ok(Subtree::Exhausted);
                };
                if symbol != u64::from(pattern[at]) {
                    return Ok(Subtree::Absent);
                }
                at += 1;
                if at == pattern.len() {
                    return Ok(Subtree::Root(child));
                }
            }
            current = child;
        }
        Ok(Subtree::Root(current))
    }

    fn visit_subtree(
        &mut self,
        root: u64,
        length: u64,
        visit: &mut impl FnMut(Occurrence) -> Result<bool>,
    ) -> Result<QueryResult> {
        let mut current = root;
        let mut result = QueryResult {
            occurrences: 0,
            complete: false,
        };
        loop {
            let Some(node) = self.node(current)? else {
                return Ok(result);
            };
            let first = if node.first_child != NONE {
                node.first_child
            } else {
                node.first_terminator
            };
            if first != NONE {
                current = first;
                continue;
            }
            let Some((_, member)) = self.member_at_text(node.suffix_start)? else {
                return Ok(result);
            };
            let offset = node.suffix_start - member.text_start;
            if length <= member.length.saturating_sub(offset) {
                self.check()?;
                if !visit(Occurrence {
                    member_id: member.id,
                    offset,
                })? {
                    return Ok(result);
                }
                result.occurrences = result
                    .occurrences
                    .checked_add(1)
                    .ok_or(Error::WriterFailure("hybrid occurrence count overflows"))?;
            }
            loop {
                if current == root {
                    result.complete = true;
                    return Ok(result);
                }
                let Some(node) = self.node(current)? else {
                    return Ok(result);
                };
                if node.next_sibling != NONE {
                    current = node.next_sibling;
                    break;
                }
                let Some(parent) = self.node(node.parent)? else {
                    return Ok(result);
                };
                if node.first_symbol < 256 && parent.first_terminator != NONE {
                    current = parent.first_terminator;
                    break;
                }
                current = node.parent;
            }
        }
    }
}

impl RepeatIndex {
    /// Query exact occurrences with constant scratch space and a cumulative
    /// logical-access allowance. Neither exhaustion, visitor rejection nor
    /// cancellation truncates or poisons the underlying index. Tree order is
    /// deterministic; callers may stop accepting occurrences independently.
    pub fn for_each_occurrence_bounded(
        &mut self,
        pattern: &[u8],
        budget: &mut QueryBudget,
        cancelled: &dyn Fn() -> bool,
        visit: &mut impl FnMut(Occurrence) -> Result<bool>,
    ) -> Result<QueryResult> {
        self.query_ready(pattern)?;
        let mut query = Query {
            index: self,
            budget,
            cancelled,
        };
        query.check()?;
        match query.matching_subtree(pattern)? {
            Subtree::Exhausted => Ok(QueryResult {
                occurrences: 0,
                complete: false,
            }),
            Subtree::Absent => Ok(QueryResult {
                occurrences: 0,
                complete: true,
            }),
            Subtree::Root(root) => query.visit_subtree(root, pattern.len() as u64, visit),
        }
    }
}

#[cfg(test)]
#[path = "query_tests.rs"]
mod tests;
