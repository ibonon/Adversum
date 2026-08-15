use crate::ast::types::*;

/// A trait for visiting the AST using the Visitor pattern.
/// To inspect nodes, implement this trait and override `visit_*` methods.
/// To continue traversal, call the corresponding `walk_*` function within your override.
pub trait Visitor<'ast>: Sized {
    fn visit_program(&mut self, program: &'ast Program) {
        walk_program(self, program);
    }

    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        walk_expr(self, expr);
    }
}

pub fn walk_program<'ast, V: Visitor<'ast>>(visitor: &mut V, program: &'ast Program) {
    for stmt in &program.statements {
        visitor.visit_stmt(stmt);
    }
}

pub fn walk_stmt<'ast, V: Visitor<'ast>>(visitor: &mut V, stmt: &'ast Stmt) {
    match stmt {
        Stmt::Let { value, .. } => visitor.visit_expr(value),
        Stmt::Assign { target, value, .. } => {
            visitor.visit_expr(target);
            visitor.visit_expr(value);
        }
        Stmt::If { condition, then_block, else_block, .. } => {
            visitor.visit_expr(condition);
            for s in then_block {
                visitor.visit_stmt(s);
            }
            if let Some(else_stmts) = else_block {
                for s in else_stmts {
                    visitor.visit_stmt(s);
                }
            }
        }
        Stmt::While { condition, body, .. } => {
            visitor.visit_expr(condition);
            for s in body {
                visitor.visit_stmt(s);
            }
        }
        Stmt::Return { value, .. } => {
            if let Some(e) = value {
                visitor.visit_expr(e);
            }
        }
        Stmt::Expr { expr, .. } => visitor.visit_expr(expr),
        Stmt::Class { body, .. } => {
            for s in body {
                visitor.visit_stmt(s);
            }
        }
        Stmt::FunctionDef { body, .. } => {
            for s in body {
                visitor.visit_stmt(s);
            }
        }
    }
}

pub fn walk_expr<'ast, V: Visitor<'ast>>(visitor: &mut V, expr: &'ast Expr) {
    match expr {
        Expr::Literal { .. } => {} // Leaf
        Expr::Identifier { .. } => {} // Leaf
        Expr::Binary { left, right, .. } => {
            visitor.visit_expr(left);
            visitor.visit_expr(right);
        }
        Expr::Unary { operand, .. } => {
            visitor.visit_expr(operand);
        }
        Expr::Call { function, args, .. } => {
            visitor.visit_expr(function);
            for arg in args {
                visitor.visit_expr(arg);
            }
        }
    }
}
