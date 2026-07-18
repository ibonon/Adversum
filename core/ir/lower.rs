use crate::ast::types as ast;
use crate::ir::types::*;
use crate::ast::visit::Visitor;
use crate::interner::{Interner, SymbolId};

pub struct LoweringContext<'src> {
    pub instructions: Vec<Instr>,
    /// For each instruction at index i, instr_lines[i] is the 1-based source line.
    pub instr_lines: Vec<usize>,
    next_temp: usize,
    next_label: usize,
    pub interner: Interner,
    /// Source bytes used for byte-offset → line-number conversion.
    source: &'src [u8],
}

impl<'src> LoweringContext<'src> {
    pub fn new(source: &'src [u8]) -> Self {
        Self {
            instructions: Vec::new(),
            instr_lines: Vec::new(),
            next_temp: 0,
            next_label: 0,
            interner: Interner::new(),
            source,
        }
    }

    /// Convert a byte offset to a 1-based source line number.
    fn byte_offset_to_line(&self, byte_offset: usize) -> usize {
        let safe_end = byte_offset.min(self.source.len());
        self.source[..safe_end]
            .iter()
            .filter(|&&b| b == b'\n')
            .count()
            + 1
    }

    fn new_temp(&mut self) -> Operand {
        let t = self.next_temp;
        self.next_temp += 1;
        Operand::Temp(t)
    }

    fn new_label(&mut self) -> usize {
        let l = self.next_label;
        self.next_label += 1;
        l
    }

    fn emit(&mut self, instr: Instr) {
        self.instructions.push(instr);
        // line will be patched by emit_with_line; default to 0 until then
        self.instr_lines.push(0);
    }

    /// Emit an instruction annotated with a concrete source line (1-indexed).
    fn emit_with_line(&mut self, instr: Instr, line: usize) {
        self.instructions.push(instr);
        self.instr_lines.push(line);
    }
    
    // Add ability to extract interner
    pub fn finish(self) -> (Program, Interner, Vec<usize>) {
        (Program { instructions: self.instructions }, self.interner, self.instr_lines)
    }
    
    // Kept build signature but logic changed.
    // Usually we want to keep the interner.
    pub fn build(mut self, program: &ast::Program) -> (Program, Interner, Vec<usize>) {
        self.visit_program(program);
        self.finish()
    }

    // Helpers to lower expressions and return the operand holding the result
    fn lower_expr(&mut self, expr: &ast::Expr) -> Operand {
        match expr {
            ast::Expr::Literal { value, .. } => {
                let val_str = match value {
                    ast::Literal::Int(i) => i.to_string(),
                    ast::Literal::Float(f) => f.to_string(),
                    ast::Literal::Bool(b) => b.to_string(),
                    ast::Literal::String(s) => format!("\"{}\"", s),
                    ast::Literal::Null => "null".to_string(),
                };
                Operand::Constant(val_str)
            }
            ast::Expr::Identifier { name, .. } => {
                let sym = self.interner.intern(name);
                Operand::Var(sym)
            }
            ast::Expr::Binary { op, left, right, .. } => {
                let lhs = self.lower_expr(left);
                let rhs = self.lower_expr(right);
                let dest = self.new_temp();
                let ir_op = match op {
                    ast::BinOp::Add => Op::Add,
                    ast::BinOp::Sub => Op::Sub,
                    ast::BinOp::Mul => Op::Mul,
                    ast::BinOp::Div => Op::Div,
                    ast::BinOp::Mod => Op::Mod,
                    ast::BinOp::Eq => Op::Eq,
                    ast::BinOp::Ne => Op::Ne,
                    ast::BinOp::Lt => Op::Lt,
                    ast::BinOp::Le => Op::Le,
                    ast::BinOp::Gt => Op::Gt,
                    ast::BinOp::Ge => Op::Ge,
                    ast::BinOp::And => Op::And,
                    ast::BinOp::Or => Op::Or,
                    ast::BinOp::BitAnd => Op::And, 
                    ast::BinOp::BitOr => Op::Or,
                    ast::BinOp::BitXor => Op::Ne, 
                };
                self.emit(Instr::Binary { dest: dest.clone(), op: ir_op, left: lhs, right: rhs });
                dest
            }
            ast::Expr::Unary { op, operand, .. } => {
                let val = self.lower_expr(operand);
                let dest = self.new_temp();
                let ir_op = match op {
                    ast::UnOp::Neg => Op::Neg,
                    ast::UnOp::Not => Op::Not,
                };
                self.emit(Instr::Unary { dest: dest.clone(), op: ir_op, operand: val });
                dest
            }
            ast::Expr::Call { function, args, span } => {
                let func_sym = if let ast::Expr::Identifier { name, .. } = &**function {
                    self.interner.intern(name)
                } else {
                    // Fallback for indirect / attribute calls
                    self.interner.intern("indirect_call")
                };

                let arg_ops: Vec<Operand> = args.iter().map(|a| self.lower_expr(a)).collect();
                let dest = self.new_temp();
                let line = self.byte_offset_to_line(span.start);
                self.emit_with_line(
                    Instr::Call { dest: Some(dest.clone()), func: func_sym, args: arg_ops },
                    line,
                );
                dest
            }
        }
    }
}

impl<'ast> Visitor<'ast> for LoweringContext<'_> {
    fn visit_stmt(&mut self, stmt: &'ast ast::Stmt) {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                let val = self.lower_expr(value);
                let sym = self.interner.intern(name);
                self.emit(Instr::Assign { dest: Operand::Var(sym), src: val });
            }
            ast::Stmt::Assign { target, value, .. } => {
                let val = self.lower_expr(value);
                if let ast::Expr::Identifier { name, .. } = target {
                     let sym = self.interner.intern(name);
                     self.emit(Instr::Assign { dest: Operand::Var(sym), src: val });
                } else {
                    // TODO complex assign
                }
            }
            ast::Stmt::Expr { expr, .. } => {
                self.lower_expr(expr);
            }
            ast::Stmt::If { condition, then_block, else_block, .. } => {
                let cond = self.lower_expr(condition);
                let label_true = self.new_label();
                let label_end = self.new_label();
                let label_else = if else_block.is_some() { self.new_label() } else { label_end };

                self.emit(Instr::JumpIf { cond: cond.clone(), label: label_true });
                self.emit(Instr::Jump(label_else));
                
                self.emit(Instr::Label(label_true));
                for s in then_block {
                    self.visit_stmt(s);
                }
                self.emit(Instr::Jump(label_end));
                
                if let Some(else_stmts) = else_block {
                    self.emit(Instr::Label(label_else));
                    for s in else_stmts {
                        self.visit_stmt(s);
                    }
                }
                
                self.emit(Instr::Label(label_end));
            }
            ast::Stmt::While { condition, body, .. } => {
                let label_start = self.new_label();
                let label_body = self.new_label();
                let label_end = self.new_label();
                
                self.emit(Instr::Label(label_start));
                let cond = self.lower_expr(condition);
                self.emit(Instr::JumpIf { cond, label: label_body });
                self.emit(Instr::Jump(label_end));
                
                self.emit(Instr::Label(label_body));
                for s in body {
                    self.visit_stmt(s);
                }
                self.emit(Instr::Jump(label_start));
                
                self.emit(Instr::Label(label_end));
            }
            ast::Stmt::Return { value, .. } => {
                let val = value.as_ref().map(|e| self.lower_expr(e));
                self.emit(Instr::Return(val));
            }
            ast::Stmt::Class { body, .. } => {
                // Lower the class body so we don't miss any inner sink calls.
                for s in body {
                    self.visit_stmt(s);
                }
            }
        }
    }
}
