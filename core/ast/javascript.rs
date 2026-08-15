use crate::ast::types::*;
use tree_sitter::Node;

pub struct JavaScriptParser<'a> {
    source: &'a [u8],
}

impl<'a> JavaScriptParser<'a> {
    pub fn new(source: &'a [u8]) -> Self {
        Self { source }
    }

    pub fn parse_stmt(&self, node: Node) -> Option<Stmt> {
        let span = Span {
            start: node.start_byte(),
            end: node.end_byte(),
            file_id: 0, // Should be passed through context in the future
        };

        match node.kind() {
            "expression_statement" => {
                let child = node.child(0)?;
                if child.kind() == "assignment_expression" {
                    let target_node = child.child_by_field_name("left")?;
                    let value_node = child.child_by_field_name("right")?;
                    let target = self.parse_expr(target_node)?;
                    let value = self.parse_expr(value_node)?;
                    Some(Stmt::Assign { target, value, span })
                } else {
                    let expr = self.parse_expr(child)?;
                    Some(Stmt::Expr { expr, span })
                }
            }
            "lexical_declaration" | "variable_declaration" => {
                // Usually has variable_declarator children
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "variable_declarator" {
                        let name_node = child.child_by_field_name("name")?;
                        let value_node = child.child_by_field_name("value");
                        
                        let name = name_node.utf8_text(self.source).ok()?.to_string();
                        let value = if let Some(v_node) = value_node {
                            self.parse_expr(v_node)?
                        } else {
                            Expr::Literal { value: Literal::Null, span: span.clone() }
                        };
                        
                        return Some(Stmt::Let { name, value, span });
                    }
                }
                None
            }
            "if_statement" => {
                let condition = self.parse_expr(node.child_by_field_name("condition")?)?;
                let then_node = node.child_by_field_name("consequence")?;
                let mut then_block = Vec::new();
                if then_node.kind() == "statement_block" {
                    let mut cursor = then_node.walk();
                    for child in then_node.children(&mut cursor) {
                        if let Some(s) = self.parse_stmt(child) {
                            then_block.push(s);
                        }
                    }
                } else if let Some(s) = self.parse_stmt(then_node) {
                    then_block.push(s);
                }
                
                let else_node = node.child_by_field_name("alternative");
                let else_block = else_node.map(|n| {
                    let mut block = Vec::new();
                    // JS 'else' child is the 'else' keyword, the actual body is the next sibling or 2nd child of alternative.
                    // Usually alternative node is an 'else_clause' with consequence.
                    if n.kind() == "else_clause" {
                        if let Some(body_node) = n.child(1) {
                            if body_node.kind() == "statement_block" {
                                let mut cursor = body_node.walk();
                                for child in body_node.children(&mut cursor) {
                                    if let Some(s) = self.parse_stmt(child) {
                                        block.push(s);
                                    }
                                }
                            } else if let Some(s) = self.parse_stmt(body_node) {
                                block.push(s);
                            }
                        }
                    }
                    block
                });

                Some(Stmt::If { condition, then_block, else_block, span })
            }
            "return_statement" => {
                let value = if let Some(expr_node) = node.child(1) {
                    // Make sure it's not the semicolon
                    if expr_node.kind() != ";" {
                        self.parse_expr(expr_node)
                    } else {
                        None
                    }
                } else {
                    None
                };
                Some(Stmt::Return { value, span })
            }
            _ => None,
        }
    }

    pub fn parse_expr(&self, node: Node) -> Option<Expr> {
        let span = Span {
            start: node.start_byte(),
            end: node.end_byte(),
            file_id: 0,
        };

        match node.kind() {
            "identifier" | "property_identifier" => {
                let name = node.utf8_text(self.source).ok()?.to_string();
                Some(Expr::Identifier { name, span })
            }
            "string" | "number" | "true" | "false" | "null" => {
                let text = node.utf8_text(self.source).ok()?;
                let lit = match node.kind() {
                    "number" => {
                        if let Ok(i) = text.parse::<i64>() {
                            Literal::Int(i)
                        } else if let Ok(f) = text.parse::<f64>() {
                            Literal::Float(f)
                        } else {
                            Literal::Null
                        }
                    },
                    "true" => Literal::Bool(true),
                    "false" => Literal::Bool(false),
                    "string" => Literal::String(text.trim_matches('"').trim_matches('\'').to_string()),
                    _ => Literal::Null,
                };
                Some(Expr::Literal { value: lit, span })
            }
            "call_expression" => {
                let function_node = node.child_by_field_name("function")?;
                let function = Box::new(self.parse_expr(function_node)?);
                let args_node = node.child_by_field_name("arguments")?;
                let mut args = Vec::new();
                let mut cursor = args_node.walk();
                for child in args_node.children(&mut cursor) {
                    if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                        if let Some(e) = self.parse_expr(child) {
                            args.push(e);
                        }
                    }
                }
                Some(Expr::Call { function, args, span })
            }
            "member_expression" => {
                // Flatten a.b.c into string identifier for simplicity in MVP taint analysis
                let obj = node.child_by_field_name("object")?.utf8_text(self.source).ok()?;
                let prop = node.child_by_field_name("property")?.utf8_text(self.source).ok()?;
                let name = format!("{}.{}", obj, prop);
                Some(Expr::Identifier { name, span })
            }
            "binary_expression" => {
                let left = Box::new(self.parse_expr(node.child_by_field_name("left")?)?);
                let right = Box::new(self.parse_expr(node.child_by_field_name("right")?)?);
                let op_text = node.child_by_field_name("operator")?.utf8_text(self.source).ok()?;
                let op = match op_text {
                    "+" => BinOp::Add,
                    "-" => BinOp::Sub,
                    "*" => BinOp::Mul,
                    "/" => BinOp::Div,
                    "==" | "===" => BinOp::Eq,
                    "!=" | "!==" => BinOp::Ne,
                    "<" => BinOp::Lt,
                    ">" => BinOp::Gt,
                    "&&" => BinOp::And,
                    "||" => BinOp::Or,
                    _ => BinOp::Add, // fallback
                };
                Some(Expr::Binary { op, left, right, span })
            }
            "parenthesized_expression" => {
                self.parse_expr(node.child(1)?)
            }
            _ => {
                // Default fallback to null literal if unsupported expr type is encountered
                Some(Expr::Literal { value: Literal::Null, span })
            }
        }
    }
}
