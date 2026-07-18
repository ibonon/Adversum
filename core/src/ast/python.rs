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
            "expression_statement" => {
                let child = node.child(0)?;
                if child.kind() == "assignment" {
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
            "assignment" => {
                let target_node = node.child_by_field_name("left")?;
                let value_node = node.child_by_field_name("right")?;
                let target = self.parse_expr(target_node)?;
                let value = self.parse_expr(value_node)?;
                Some(Stmt::Assign { target, value, span })
            }
            "if_statement" => {
                let condition = self.parse_expr(node.child_by_field_name("condition")?)?;
                let then_node = node.child_by_field_name("consequence")?;
                let mut then_block = Vec::new();
                let mut cursor = then_node.walk();
                for child in then_node.children(&mut cursor) {
                    if let Some(s) = self.parse_stmt(child) {
                        then_block.push(s);
                    }
                }
                
                let else_node = node.child_by_field_name("alternative");
                let else_block = else_node.map(|n| {
                    let mut block = Vec::new();
                    let mut cursor = n.walk();
                    for child in n.children(&mut cursor) {
                        if let Some(s) = self.parse_stmt(child) {
                            block.push(s);
                        }
                    }
                    block
                });

                Some(Stmt::If { condition, then_block, else_block, span })
            }
            "return_statement" => {
                let value = if let Some(expr_node) = node.child(1) {
                    self.parse_expr(expr_node)
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
            "identifier" => {
                let name = node.utf8_text(self.source).ok()?.to_string();
                Some(Expr::Identifier { name, span })
            }
            "string" | "integer" | "float" | "true" | "false" | "none" => {
                let text = node.utf8_text(self.source).ok()?;
                let lit = match node.kind() {
                    "integer" => Literal::Int(text.parse().ok()?),
                    "float" => Literal::Float(text.parse().ok()?),
                    "true" => Literal::Bool(true),
                    "false" => Literal::Bool(false),
                    "string" => Literal::String(text.trim_matches('"').to_string()),
                    _ => Literal::Null,
                };
                Some(Expr::Literal { value: lit, span })
            }
            "call" => {
                let function_node = node.child_by_field_name("function")?;
                let function = Box::new(self.parse_expr(function_node)?);
                let args_node = node.child_by_field_name("arguments")?;
                let mut args = Vec::new();
                let mut cursor = args_node.walk();
                for child in args_node.children(&mut cursor) {
                    if child.kind() == "argument" { // tree-sitter-python 0.20 uses 'argument' wrapper? or direct?
                         // In 0.20 it might be different. Let's assume direct children for now or check kind.
                         if let Some(e) = self.parse_expr(child) {
                             args.push(e);
                         }
                    } else if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                        if let Some(e) = self.parse_expr(child) {
                            args.push(e);
                        }
                    }
                }
                Some(Expr::Call { function, args, span })
            }
            "binary_operator" => {
                let left = Box::new(self.parse_expr(node.child_by_field_name("left")?)?);
                let right = Box::new(self.parse_expr(node.child_by_field_name("right")?)?);
                let op_text = node.child(1)?.utf8_text(self.source).ok()?;
                let op = match op_text {
                    "+" => BinOp::Add,
                    "-" => BinOp::Sub,
                    "*" => BinOp::Mul,
                    "/" => BinOp::Div,
                    "==" => BinOp::Eq,
                    "!=" => BinOp::Ne,
                    "<" => BinOp::Lt,
                    ">" => BinOp::Gt,
                    _ => BinOp::Add, // fallback
                };
                Some(Expr::Binary { op, left, right, span })
            }
            _ => None,
        }
    }
}
