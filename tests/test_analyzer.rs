use bitcoin_script::analyzer::StackStatus;
use bitcoin_script::script;
use bitcoin_script::Script;
use bitcoin_script::StackAnalyzer;

#[test]
fn test_plain() {
    let script = script! (
        OP_ADD
        OP_ADD
        OP_1
    );
    let mut analyzer = StackAnalyzer::new();
    let status = analyzer.analyze_status(&script);
    assert_eq!(status.deepest_stack_accessed, -3);
    assert_eq!(status.stack_changed, -1);
}

#[test]
fn test_two_scripts() {
    let script = script! {
        { script! { 
            OP_ADD
        }}
        { script! { 
            OP_ADD
        }}
    };
    let mut analyzer = StackAnalyzer::new();
    let status = analyzer.analyze_status(&script);
    assert_eq!(status.deepest_stack_accessed, -3);
    assert_eq!(status.stack_changed, -2);
}

fn inner_fn1() -> Script {
    script!(
        {10}
        OP_ROLL
        {2}
        OP_ROLL
        OP_ADD
    )
}

fn inner_fn2() -> Script {
    script!(
        {1}
        OP_DUP
        OP_TOALTSTACK
        {2}
        OP_DUP
        OP_TOALTSTACK
        OP_GREATERTHAN
        OP_IF
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_ADD
        OP_ELSE
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_SUB
        OP_ENDIF
    )
}

#[test]
fn test_inner1() {
    let mut script = inner_fn1();
    let mut analyzer = StackAnalyzer::new();
    let status = script.get_stack(&mut analyzer);
    assert_eq!(
        [status.deepest_stack_accessed, status.stack_changed],
        [-11, -1]
    );
}

#[test]
fn test_deepthest() {
    let mut script = script! (
        {inner_fn1()}
        {inner_fn1()}
        OP_ADD
    );
    let mut analyzer = StackAnalyzer::new();
    let status = script.get_stack(&mut analyzer);
    assert_eq!(
        [status.deepest_stack_accessed, status.stack_changed],
        [-12, -3]
    );

    let mut script = script!(
        { inner_fn2() }
        { inner_fn2() }
        OP_ADD
    );
    let mut analyzer = StackAnalyzer::new();
    let status = script.get_stack(&mut analyzer);
    assert_eq!(
        [status.deepest_stack_accessed, status.stack_changed],
        [0, 1]
    );
}

#[test]
fn test_deepthest2() {
    let mut script = script! (
        {1}
        OP_IF
            { 120 }
            OP_ADD
        OP_ENDIF
    );
    let mut analyzer = StackAnalyzer::new();
    let status = script.get_stack(&mut analyzer);
    assert_eq!(
        [status.deepest_stack_accessed, status.stack_changed],
        [-1, 0]
    );
}

#[test]
fn test_altstack() {
    let mut script = script! (
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    );
    let mut analyzer = StackAnalyzer::new();
    let status = script.get_stack(&mut analyzer);
    assert_eq!(
        status,
        StackStatus {
            deepest_stack_accessed: 0,
            stack_changed: 3,
            deepest_altstack_accessed: -3,
            altstack_changed: -3,
        }
    );

    let mut script = script!(
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
    );
    let mut analyzer = StackAnalyzer::new();
    let status = script.get_stack(&mut analyzer);
    assert_eq!(
        status,
        StackStatus {
            deepest_stack_accessed: -3,
            stack_changed: -3,
            deepest_altstack_accessed: 0,
            altstack_changed: 3,
        }
    );
}

#[test]
fn test_altstack_and_opif() {
    let mut script = script! (
        OP_IF
        OP_FROMALTSTACK
        OP_SUB
        OP_ELSE
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_ADD
        OP_TOALTSTACK
        OP_ENDIF
    );
    let mut analyzer = StackAnalyzer::new();
    let status = script.get_stack(&mut analyzer);
    assert_eq!(
        status,
        StackStatus {
            deepest_stack_accessed: -2,
            stack_changed: -1,
            deepest_altstack_accessed: -2,
            altstack_changed: -1,
        }
    );
}
