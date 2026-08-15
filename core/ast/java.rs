use crate::ast::types::*;
use tree_sitter::Node;

pub struct JavaParser<'a> {
    source: &'a [u8],
}

impl<'a> JavaParser<'a> {
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
            "local_variable_declaration" => {
                // Java variable declarations can have multiple declarators
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
                let condition_node = node.child_by_field_name("condition")?;
                // In tree-sitter-java, condition might be wrapped in parenthesized_expression
                let condition = self.parse_expr(condition_node)?;
                
                let then_node = node.child_by_field_name("consequence")?;
                let mut then_block = Vec::new();
                if then_node.kind() == "block" {
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
                    if n.kind() == "block" {
                        let mut cursor = n.walk();
                        for child in n.children(&mut cursor) {
                            if let Some(s) = self.parse_stmt(child) {
                                block.push(s);
                            }
                        }
                    } else if let Some(s) = self.parse_stmt(n) {
                        block.push(s);
                    }
                    block
                });

                Some(Stmt::If { condition, then_block, else_block, span })
            }
            "return_statement" => {
                let mut value = None;
                for i in 0..node.child_count() {
                    let child = node.child(i).unwrap();
                    if child.kind() != "return" && child.kind() != ";" {
                        value = self.parse_expr(child);
                        break;
                    }
                }
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
            "string_literal" | "decimal_integer_literal" | "decimal_floating_point_literal" | "true" | "false" | "null_literal" => {
                let text = node.utf8_text(self.source).ok()?;
                let lit = match node.kind() {
                    "decimal_integer_literal" => Literal::Int(text.parse().ok()?),
                    "decimal_floating_point_literal" => Literal::Float(text.parse().ok()?),
                    "true" => Literal::Bool(true),
                    "false" => Literal::Bool(false),
                    "string_literal" => Literal::String(text.trim_matches('"').to_string()),
                    _ => Literal::Null,
                };
                Some(Expr::Literal { value: lit, span })
            }
            "method_invocation" => {
                let function_node = node.child_by_field_name("name")?;
                let function = Box::new(self.parse_expr(function_node)?);
                
                // Usually method calls have an object. Let's merge object and name if possible
                let function = if let Some(obj_node) = node.child_by_field_name("object") {
                    let obj_text = obj_node.utf8_text(self.source).ok()?;
                    let func_text = function_node.utf8_text(self.source).ok()?;
                    Box::new(Expr::Identifier { name: format!("{}.{}", obj_text, func_text), span: span.clone() })
                } else {
                    function
                };

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
            "field_access" => {
                let obj = node.child_by_field_name("object")?.utf8_text(self.source).ok()?;
                let field = node.child_by_field_name("field")?.utf8_text(self.source).ok()?;
                let name = format!("{}.{}", obj, field);
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
                    "==" => BinOp::Eq,
                    "!=" => BinOp::Ne,
                    "<" => BinOp::Lt,
                    ">" => BinOp::Gt,
                    "&&" => BinOp::And,
                    "||" => BinOp::Or,
                    _ => BinOp::Add,
                };
                Some(Expr::Binary { op, left, right, span })
            }
            "parenthesized_expression" => {
                // Extract inner expression, skipping '(' and ')'
                let mut inner = None;
                for i in 0..node.child_count() {
                    let child = node.child(i).unwrap();
                    if child.kind() != "(" && child.kind() != ")" {
                        inner = self.parse_expr(child);
                        break;
                    }
                }
                inner
            }
            _ => {
                Some(Expr::Literal { value: Literal::Null, span })
            }
        }
    }
}
