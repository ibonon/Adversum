#[cfg(test)]
mod test_ast {
    use crate::ast::types::*;
    use crate::ast::visit::Visitor;

    // A dummy visitor that counts nodes
    struct NodeCounter {
        stmts: usize,
        exprs: usize,
    }

    impl<'ast> Visitor<'ast> for NodeCounter {
        fn visit_stmt(&mut self, stmt: &'ast Stmt) {
            self.stmts += 1;
            crate::ast::visit::walk_stmt(self, stmt);
        }
        fn visit_expr(&mut self, expr: &'ast Expr) {
            self.exprs += 1;
            crate::ast::visit::walk_expr(self, expr);
        }
    }

    #[test]
    fn test_visitor_traversal() {
        let span = Span { start: 0, end: 0, file_id: 0 };
        let prog = Program {
            statements: vec![Stmt::Expr {
                expr: Expr::Literal {
                     value: Literal::Int(1),
                     span: span.clone()
                },
                span: span.clone()
            }]
        };

        let mut counter = NodeCounter { stmts: 0, exprs: 0 };
        counter.visit_program(&prog);
        assert_eq!(counter.stmts, 1);
        assert_eq!(counter.exprs, 1);
    }

    // Retrying the test strategy:
    // Just build an AST and serialize it to JSON to check integrity.

    #[test]
    fn test_ast_construction_and_serialization() {
        let span = Span { start: 0, end: 0, file_id: 0 };
        
        let prog = Program {
            statements: vec![
                Stmt::Let {
                    name: "x".to_string(),
                    value: Expr::Literal {
                        value: Literal::Int(42),
                        span: span.clone(),
                    },
                    span: span.clone(),
                },
                Stmt::Expr {
                    expr: Expr::Binary {
                        op: BinOp::Add,
                        left: Box::new(Expr::Identifier {
                            name: "x".to_string(),
                            span: span.clone(),
                        }),
                        right: Box::new(Expr::Literal {
                            value: Literal::Int(1),
                            span: span.clone(),
                        }),
                        span: span.clone(),
                    },
                    span: span.clone(),
                }
            ],
        };

        let json = serde_json::to_string(&prog).expect("Serialization failed");
        assert!(json.contains("Let"));
        assert!(json.contains("42"));
        assert!(json.contains("Add"));
    }
}
