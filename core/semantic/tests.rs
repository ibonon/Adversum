
use crate::semantic::types::{Symbol, Type};
use crate::semantic::symtab::SymbolTable;
use crate::ast::types::Span;
use crate::interner::Interner;

#[test]
fn test_symbol_table_scoping() {
    let mut symtab = SymbolTable::new();
    let mut interner = Interner::new();
    let span = Span { start: 0, end: 0, file_id: 0 };
    
    let x_id = interner.intern("x");

    // Define in global
    let res = symtab.define(Symbol {
        name: x_id,
        ty: Type::Int,
        def_span: span.clone(),
        id: 0, // Ignored
    });
    assert!(res.is_ok());

    // Enter scope
    symtab.enter_scope();
    // Shadow x
    let res2 = symtab.define(Symbol {
        name: x_id,
        ty: Type::Bool,
        def_span: span.clone(),
        id: 0,
    });
    assert!(res2.is_ok());

    // Lookup inner x
    let sym = symtab.lookup(x_id);
    assert!(sym.is_some());
    assert_eq!(sym.unwrap().ty, Type::Bool);

    // Exit, check outer x
    symtab.exit_scope();
    let sym_outer = symtab.lookup(x_id);
    assert!(sym_outer.is_some());
    assert_eq!(sym_outer.unwrap().ty, Type::Int);
}

#[test]
fn test_no_panic_on_exit_root() {
    let mut symtab = SymbolTable::new();
    let mut interner = Interner::new();
    let z_id = interner.intern("z");
    symtab.exit_scope(); 
    
    let span = Span { start: 0, end: 0, file_id: 0 };
    let res = symtab.define(Symbol {
        name: z_id,
        ty: Type::Void,
        def_span: span,
        id: 0,
    });
    assert!(res.is_ok());
}
