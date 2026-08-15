use crate::ast::types::*;
use tree_sitter::Node;

pub struct PythonParser<'a> {
    source: &'a [u8],
}

impl<'a> PythonParser<'a> {
    pub fn new(source: &'a [u8]) -> Self {
        Self { source }
    }

    pub fn parse_stmt(&self, node: Node) -> Option<Stmt> {
        let span = Span {
            start: node.start_byte(),
            end: node.end_byte(),
            file_id: 0,
        };

        match node.kind() {
            // ── Simple expression statement ─────────────────────────────────
            "expression_statement" => {
                let child = node.child(0)?;
                match child.kind() {
                    "assignment" => {
                        let target_node = child.child_by_field_name("left")?;
                        let value_node  = child.child_by_field_name("right")?;
                        let target = self.parse_expr(target_node)?;
                        let value  = self.parse_expr(value_node)?;
                        Some(Stmt::Assign { target, value, span })
                    }
                    "augmented_assignment" => {
                        // x += expr  =>  treat as  x = x + expr
                        let target_node = child.child_by_field_name("left")?;
                        let value_node  = child.child_by_field_name("right")?;
                        let target = self.parse_expr(target_node)?;
                        let value  = self.parse_expr(value_node)?;
                        Some(Stmt::Assign { target, value, span })
                    }
                    _ => {
                        let expr = self.parse_expr(child)?;
                        Some(Stmt::Expr { expr, span })
                    }
                }
            }

            // ── Top-level assignment ────────────────────────────────────────
            "assignment" => {
                let target_node = node.child_by_field_name("left")?;
                let value_node  = node.child_by_field_name("right")?;
                let target = self.parse_expr(target_node)?;
                let value  = self.parse_expr(value_node)?;
                Some(Stmt::Assign { target, value, span })
            }

            // ── Augmented assignment at top level ───────────────────────────
            "augmented_assignment" => {
                let target_node = node.child_by_field_name("left")?;
                let value_node  = node.child_by_field_name("right")?;
                let target = self.parse_expr(target_node)?;
                let value  = self.parse_expr(value_node)?;
                Some(Stmt::Assign { target, value, span })
            }

            // ── If statement ────────────────────────────────────────────────
            "if_statement" => {
                let condition = self.parse_expr(node.child_by_field_name("condition")?)?;
                let then_node = node.child_by_field_name("consequence")?;
                let then_block = self.collect_block(then_node);

                let else_block = node
                    .child_by_field_name("alternative")
                    .map(|n| self.collect_block(n));

                Some(Stmt::If { condition, then_block, else_block, span })
            }

            // ── While statement ─────────────────────────────────────────────
            "while_statement" => {
                let condition = self.parse_expr(node.child_by_field_name("condition")?)?;
                let body_node = node.child_by_field_name("body")?;
                let body = self.collect_block(body_node);
                Some(Stmt::While { condition, body, span })
            }

            // ── For statement ───────────────────────────────────────────────
            // `for x in items:` -- we model the body as a While with a dummy True condition
            "for_statement" => {
                let body_node = node.child_by_field_name("body")?;
                let body = self.collect_block(body_node);
                let condition = Expr::Literal {
                    value: Literal::Bool(true),
                    span: span.clone(),
                };
                Some(Stmt::While { condition, body, span })
            }

            // ── With statement ──────────────────────────────────────────────
            // `with open(...) as f:` -- lower the body; emit a call for the context expr
            "with_statement" => {
                let mut block: Vec<Stmt> = Vec::new();

                // Emit the with-item expression so taint flows from e.g. open() calls
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "with_item" {
                        if let Some(val_node) = child.child_by_field_name("value") {
                            if let Some(expr) = self.parse_expr(val_node) {
                                block.push(Stmt::Expr { expr, span: span.clone() });
                            }
                        }
                    }
                }

                if let Some(body_node) = node.child_by_field_name("body") {
                    block.extend(self.collect_block(body_node));
                }

                let condition = Expr::Literal { value: Literal::Bool(true), span: span.clone() };
                Some(Stmt::If {
                    condition,
                    then_block: block,
                    else_block: None,
                    span,
                })
            }

            // ── Return statement ────────────────────────────────────────────
            "return_statement" => {
                let value = if let Some(expr_node) = node.child(1) {
                    self.parse_expr(expr_node)
                } else {
                    None
                };
                Some(Stmt::Return { value, span })
            }

            // ── Function Definition ─────────────────────────────────────────
            "function_definition" | "decorated_definition" => {
                let (def_node, _span) = if node.kind() == "decorated_definition" {
                    let mut def = None;
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "function_definition" {
                            def = Some(child);
                            break;
                        }
                    }
                    (def?, span.clone())
                } else {
                    (node, span.clone())
                };

                let name_node = def_node.child_by_field_name("name")?;
                let name = name_node.utf8_text(self.source).ok()?.to_string();

                let params_node = def_node.child_by_field_name("parameters")?;
                let mut params = Vec::new();
                let mut p_cursor = params_node.walk();
                for child in params_node.children(&mut p_cursor) {
                    if child.kind() == "identifier" {
                        if let Ok(param_name) = child.utf8_text(self.source) {
                            params.push(param_name.to_string());
                        }
                    } else if child.kind() == "typed_parameter" || child.kind() == "default_parameter" {
                        // Extract just the identifier part
                        let mut sub_cursor = child.walk();
                        for sub_child in child.children(&mut sub_cursor) {
                            if sub_child.kind() == "identifier" {
                                if let Ok(param_name) = sub_child.utf8_text(self.source) {
                                    params.push(param_name.to_string());
                                }
                                break;
                            }
                        }
                    }
                }

                let body_node = def_node.child_by_field_name("body")?;
                let body = self.collect_block(body_node);

                Some(Stmt::FunctionDef { name, params, body, span })
            }

            // ── Class definition ────────────────────────────────────────────
            "class_definition" => {
                let name = node.child_by_field_name("name")?.utf8_text(self.source).ok()?.to_string();
                let body_node = node.child_by_field_name("body")?;
                let body = self.collect_block(body_node);
                Some(Stmt::Class { name, body, span })
            }

            _ => None,
        }
    }

    // ── Expression parser ───────────────────────────────────────────────────
    pub fn parse_expr(&self, node: Node) -> Option<Expr> {
        let span = Span {
            start: node.start_byte(),
            end: node.end_byte(),
            file_id: 0,
        };

        match node.kind() {
            // ── Identifier ─────────────────────────────────────────────────
            "identifier" => {
                let name = node.utf8_text(self.source).ok()?.to_string();
                Some(Expr::Identifier { name, span })
            }

            // ── Literals ────────────────────────────────────────────────────
            "string" | "concatenated_string" => {
                let text = node.utf8_text(self.source).ok()?.to_string();
                Some(Expr::Literal { value: Literal::String(text), span })
            }
            "integer" => {
                let text = node.utf8_text(self.source).ok()?;
                let v = text.parse().unwrap_or(0);
                Some(Expr::Literal { value: Literal::Int(v), span })
            }
            "float" => {
                let text = node.utf8_text(self.source).ok()?;
                let v = text.parse().unwrap_or(0.0);
                Some(Expr::Literal { value: Literal::Float(v), span })
            }
            "true"  => Some(Expr::Literal { value: Literal::Bool(true),  span }),
            "false" => Some(Expr::Literal { value: Literal::Bool(false), span }),
            "none"  => Some(Expr::Literal { value: Literal::Null, span }),

            // ── f-string ────────────────────────────────────────────────────
            "interpolated_string" | "f_string" => {
                Some(Expr::Literal { value: Literal::String("<f-string>".into()), span })
            }

            // ── Attribute access: obj.attr ───────────────────────────────────
            // We flatten obj.attr into a single Identifier so the interner can
            // match it as a taint sink (e.g. "subprocess.run", "conn.execute").
            "attribute" => {
                let obj_node  = node.child_by_field_name("object")?;
                let attr_node = node.child_by_field_name("attribute")?;
                let obj_text  = obj_node.utf8_text(self.source).ok()?.to_string();
                let attr_text = attr_node.utf8_text(self.source).ok()?.to_string();
                let name = format!("{}.{}", obj_text, attr_text);
                Some(Expr::Identifier { name, span })
            }

            // ── Function / method call ───────────────────────────────────────
            "call" => {
                let function_node = node.child_by_field_name("function")?;
                let function = Box::new(self.parse_expr(function_node)?);

                let mut args = Vec::new();
                if let Some(args_node) = node.child_by_field_name("arguments") {
                    let mut cursor = args_node.walk();
                    for child in args_node.children(&mut cursor) {
                        match child.kind() {
                            "(" | ")" | "," | "keyword_argument" => {}
                            _ => {
                                if let Some(e) = self.parse_expr(child) {
                                    args.push(e);
                                }
                            }
                        }
                    }
                }
                Some(Expr::Call { function, args, span })
            }

            // ── Binary operators ─────────────────────────────────────────────
            "binary_operator" => {
                let left  = Box::new(self.parse_expr(node.child_by_field_name("left")?)?);
                let right = Box::new(self.parse_expr(node.child_by_field_name("right")?)?);
                let op_text = node.child(1)?.utf8_text(self.source).ok()?;
                let op = match op_text {
                    "+"  => BinOp::Add,
                    "-"  => BinOp::Sub,
                    "*"  => BinOp::Mul,
                    "/"  => BinOp::Div,
                    "%"  => BinOp::Mod,
                    "==" => BinOp::Eq,
                    "!=" => BinOp::Ne,
                    "<"  => BinOp::Lt,
                    "<=" => BinOp::Le,
                    ">"  => BinOp::Gt,
                    ">=" => BinOp::Ge,
                    "and" => BinOp::And,
                    "or"  => BinOp::Or,
                    "&"  => BinOp::BitAnd,
                    "|"  => BinOp::BitOr,
                    "^"  => BinOp::BitXor,
                    _    => BinOp::Add,
                };
                Some(Expr::Binary { op, left, right, span })
            }

            // ── Comparison operators ─────────────────────────────────────────
            "comparison_operator" => {
                let left  = Box::new(self.parse_expr(node.child(0)?)?);
                let right = Box::new(self.parse_expr(node.child(2)?)?);
                let op_text = node.child(1)?.utf8_text(self.source).ok()?;
                let op = match op_text {
                    "==" => BinOp::Eq, "!=" => BinOp::Ne,
                    "<"  => BinOp::Lt, "<=" => BinOp::Le,
                    ">"  => BinOp::Gt, ">=" => BinOp::Ge,
                    _    => BinOp::Eq,
                };
                Some(Expr::Binary { op, left, right, span })
            }

            // ── Boolean not ──────────────────────────────────────────────────
            "not_operator" => {
                let operand = Box::new(self.parse_expr(node.child(1)?)?);
                Some(Expr::Unary { op: UnOp::Not, operand, span })
            }

            // ── Unary minus / plus ───────────────────────────────────────────
            "unary_operator" => {
                let operand = Box::new(self.parse_expr(node.child(1)?)?);
                Some(Expr::Unary { op: UnOp::Neg, operand, span })
            }

            // ── Subscript: obj[key] -- passthrough the object ─────────────────
            "subscript" => {
                let obj_node = node.child_by_field_name("value")?;
                self.parse_expr(obj_node)
            }

            // ── Parenthesised expression ─────────────────────────────────────
            "parenthesized_expression" => {
                let inner = node.child(1)?;
                self.parse_expr(inner)
            }

            // ── Keyword argument (foo=bar) -- return the value part ───────────
            "keyword_argument" => {
                let value_node = node.child_by_field_name("value")?;
                self.parse_expr(value_node)
            }

            // ── Await expression (async Python code) ─────────────────────────
            "await" => {
                let inner = node.child(1)?;
                self.parse_expr(inner)
            }

            _ => None,
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Walk the children of a block node and collect parsed statements.
    fn collect_block(&self, block_node: Node) -> Vec<Stmt> {
        let mut stmts = Vec::new();
        let mut cursor = block_node.walk();
        for child in block_node.children(&mut cursor) {
            if let Some(s) = self.parse_stmt(child) {
                stmts.push(s);
            }
        }
        stmts
    }
}
