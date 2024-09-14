use crate::builder::{Block, StructuredScript};
use crate::chunker::Chunk;
use bitcoin::blockdata::opcodes::Opcode;
use bitcoin::blockdata::script::{read_scriptint, Instruction};
use bitcoin::opcodes::all::*;
use bitcoin::script::PushBytes;
use bitcoin::ScriptBuf;
use script_macro::script;
use std::borrow::BorrowMut;
use std::cmp::{max, min};
use std::panic;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct StackStatus {
    pub deepest_stack_accessed: i32,
    pub stack_changed: i32,
    pub deepest_altstack_accessed: i32,
    pub altstack_changed: i32,
}

impl StackStatus {
    pub fn total_stack(&self) -> i32 {
        self.stack_changed + self.altstack_changed
    }

    pub fn is_valid_final_state_without_inputs(&self) -> bool {
        self.stack_changed == 1
            && self.altstack_changed == 0
            && self.deepest_altstack_accessed == 0
            && self.deepest_stack_accessed == 0
    }
    
    pub fn is_valid_final_state_with_inputs(&self) -> bool {
        self.stack_changed == 1
            && self.altstack_changed == 0
            && self.deepest_altstack_accessed == 0
    }
}

#[derive(Debug, Clone)]
enum IfStackEle {
    IfFlow(StackStatus),
    // if_flow (deepest_stack_accessed, stack_changed), else_flow(deepest_stack_accessed, stack_changed)
    ElseFlow((StackStatus, StackStatus)),
}

#[derive(Debug, Clone)]
pub struct StackAnalyzer {
    debug_script: StructuredScript,
    debug_position: usize,
    stack_status: StackStatus,
    // if_stack should be empty after analyzing
    if_stack: Vec<IfStackEle>,
    // last constant? for handling op_roll and op_pick
    pub last_constant: Option<i64>,
}

impl Default for StackAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl StackAnalyzer {
    pub fn new() -> Self {
        StackAnalyzer {
            debug_script: StructuredScript::new(""),
            debug_position: 0,
            stack_status: StackStatus::default(),
            if_stack: vec![],
            last_constant: None,
        }
    }

    pub fn with(start_stack: usize, start_altstack: usize, last_constant: Option<i64>) -> Self {
        StackAnalyzer {
            debug_script: StructuredScript::new(""),
            debug_position: 0,
            stack_status: StackStatus {
                deepest_stack_accessed: 0,
                stack_changed: start_stack as i32,
                deepest_altstack_accessed: 0,
                altstack_changed: start_altstack as i32,
            },
            if_stack: vec![],
            last_constant,
        }
    }

    pub fn total_stack_change(&self) -> i32 {
        self.stack_status.altstack_changed + self.stack_status.stack_changed
    }

    pub fn reset(&mut self) {
        self.debug_script = StructuredScript::new("");
        self.debug_position = 0;
        self.if_stack = vec![];
        self.stack_status = StackStatus::default();
    }

    pub fn analyze_blocks(&mut self, scripts: &Vec<Box<StructuredScript>>) {
        for script in scripts {
            self.debug_script = *script.clone();
            self.debug_position = 0;
            match script.stack_hint() {
                Some(stack_hint) => {
                    self.debug_position += script.len();
                    self.stack_change(stack_hint)
                }
                None => self.merge_script(script),
            };
        }
    }
    pub fn analyze_blocks_status(&mut self, scripts: &Vec<Box<StructuredScript>>) -> StackStatus {
        for script in scripts {
            self.debug_script = *script.clone();
            self.debug_position = 0;
            match script.stack_hint() {
                Some(stack_hint) => {
                    self.debug_position += script.len();
                    self.stack_change(stack_hint)
                }
                None => self.merge_script(script),
            };
        }
        self.get_status()
    }

    pub fn analyze_status(&mut self, script: &StructuredScript) -> StackStatus {
        self.debug_script = script.clone();
        self.debug_position = 0;
        match script.stack_hint() {
            Some(stack_hint) => self.stack_change(stack_hint),
            None => self.merge_script(script),
        };
        self.get_status()
    }

    pub fn analyze(&mut self, script: &StructuredScript) {
        self.debug_script = script.clone();
        self.debug_position = 0;
        match script.stack_hint() {
            Some(stack_hint) => self.stack_change(stack_hint),
            None => self.merge_script(script),
        };
    }

    pub fn merge_script(&mut self, builder: &StructuredScript) {
        for block in builder.blocks.iter() {
            match block {
                Block::Call(id) => {
                    let called_script = builder
                        .script_map
                        .get(id)
                        .expect("Missing entry for a called script");
                    match called_script.stack_hint() {
                        Some(stack_hint) => {
                            self.debug_position += called_script.len();
                            self.stack_change(stack_hint)
                        }
                        None => self.merge_script(called_script),
                    };
                }
                Block::Script(block_script) => {
                    for instruct in block_script.instructions() {
                        match instruct {
                            Err(err) => {
                                panic!("instruction extract fail from script {}", err);
                            }
                            Ok(x) => match x {
                                Instruction::PushBytes(bytes) => {
                                    self.handle_push_slice(bytes);
                                }
                                Instruction::Op(opcode) => {
                                    self.handle_opcode(opcode);
                                }
                            },
                        }
                    }
                }
            }
        }
    }

    pub fn handle_push_slice(&mut self, bytes: &PushBytes) {
        self.debug_position += bytes.len() + 1;
        if let Ok(x) = read_scriptint(bytes.as_bytes()) {
            // if i64(data) < 1000, last_constant is true
            if (0..=1000).contains(&x) {
                self.last_constant = Some(x);
            } else {
                self.last_constant = None;
            }
        }
        self.stack_change(Self::plain_stack_status(0, 1));
    }

    fn min_status(x: StackStatus, y: StackStatus) -> StackStatus {
        StackStatus {
            deepest_altstack_accessed: min(
                x.deepest_altstack_accessed,
                y.deepest_altstack_accessed,
            ),
            deepest_stack_accessed: min(x.deepest_stack_accessed, y.deepest_stack_accessed),
            stack_changed: x.stack_changed,
            altstack_changed: x.altstack_changed,
        }
    }

    pub fn plain_stack_status(x: i32, y: i32) -> StackStatus {
        StackStatus {
            deepest_stack_accessed: x,
            stack_changed: y,
            deepest_altstack_accessed: 0,
            altstack_changed: 0,
        }
    }

    pub fn plain_altstack_status(x: i32, y: i32) -> StackStatus {
        StackStatus {
            deepest_stack_accessed: 0,
            stack_changed: 0,
            deepest_altstack_accessed: x,
            altstack_changed: y,
        }
    }

    pub fn handle_opcode(&mut self, opcode: Opcode) {
        // handle if/else flow
        match opcode {
            OP_IF | OP_NOTIF => {
                self.stack_change(Self::opcode_stack_table(&opcode));
                self.if_stack.push(IfStackEle::IfFlow(Default::default()));
            }
            OP_RESERVED => {
                panic!(
                    "found DEBUG in {:?}\n entire builder: {:?}",
                    self.debug_script.debug_info(self.debug_position),
                    self.debug_script
                )
            }
            OP_ELSE => match self.if_stack.pop().unwrap() {
                IfStackEle::IfFlow(i) => {
                    self.if_stack
                        .push(IfStackEle::ElseFlow((i, Default::default())));
                }
                IfStackEle::ElseFlow(_) => {
                    panic!("shouldn't happend")
                }
            },
            OP_ENDIF => {
                match self.if_stack.pop().unwrap() {
                    IfStackEle::IfFlow(stack_status) => {
                        assert_eq!(
                        stack_status.stack_changed, 0,
                        "only_if_flow shouldn't change stack status {:?}\n\tat pos {:?}\n\tin {:?}",
                        stack_status, self.debug_position, self.debug_script.debug_info(self.debug_position + 1)
                    );
                        assert_eq!(
                        stack_status.altstack_changed, 0,
                        "only_if_flow shouldn't change altstack status {:?}\n\tat pos {:?}\n\tin {:?}",
                        stack_status, self.debug_position, self.debug_script.debug_info(self.debug_position + 1)
                    );
                        self.stack_change(stack_status);
                    }
                    IfStackEle::ElseFlow((stack_status1, stack_status2)) => {
                        assert_eq!(
                            stack_status1.stack_changed,
                            stack_status2.stack_changed,
                            "if_flow and else_flow should change stack in the same way in {:?}",
                            self.debug_script.debug_info(self.debug_position + 1)
                        );
                        assert_eq!(
                            stack_status1.altstack_changed,
                            stack_status2.altstack_changed,
                            "if_flow and else_flow should change altstack in the same way in {:?}",
                            self.debug_script.debug_info(self.debug_position + 1)
                        );
                        self.stack_change(Self::min_status(stack_status1, stack_status2));
                    }
                }
            }
            OP_PICK => match self.last_constant {
                Some(x) => {
                    self.stack_change(Self::plain_stack_status(-((x + 1 + 1) as i32), 0));
                }
                None => {
                    panic!(
                        "need to be handled manually for op_pick in {:?}",
                        self.debug_script.debug_info(self.debug_position)
                    )
                }
            },
            OP_ROLL => match self.last_constant {
                Some(x) => {
                    self.stack_change(Self::plain_stack_status(-((x + 1 + 1) as i32), -1));
                    // for [x2, x1, x0, 2, OP_PICK]
                }
                None => {
                    panic!(
                        "need to be handled manually for op_roll in {:?}",
                        self.debug_script.debug_info(self.debug_position)
                    )
                }
            },
            _ => {
                self.stack_change(Self::opcode_stack_table(&opcode));
            }
        }
        self.debug_position += 1;

        // handle last constant, used by op_roll and op_pick
        match opcode {
            OP_PUSHNUM_1 | OP_PUSHNUM_2 | OP_PUSHNUM_3 | OP_PUSHNUM_4 | OP_PUSHNUM_5
            | OP_PUSHNUM_6 | OP_PUSHNUM_7 | OP_PUSHNUM_8 | OP_PUSHNUM_9 | OP_PUSHNUM_10
            | OP_PUSHNUM_11 | OP_PUSHNUM_12 | OP_PUSHNUM_13 | OP_PUSHNUM_14 | OP_PUSHNUM_15
            | OP_PUSHNUM_16 => self.last_constant = Some((opcode.to_u8() - 0x50) as i64),
            OP_DUP => (),
            OP_PUSHBYTES_0 => self.last_constant = Some(0),
            _ => self.last_constant = None,
        }
    }

    pub fn get_status(&self) -> StackStatus {
        assert!(self.if_stack.is_empty(), "if stack is not empty");
        self.stack_status.clone()
    }

    fn stack_change(&mut self, stack_status: StackStatus) {
        let status;
        match self.if_stack.last_mut() {
            None => {
                status = self.stack_status.borrow_mut();
            }
            Some(IfStackEle::IfFlow(stack_status)) => {
                status = stack_status.borrow_mut();
            }
            Some(IfStackEle::ElseFlow((_, stack_status))) => {
                status = stack_status.borrow_mut();
            }
        }
        let i = status.deepest_stack_accessed.borrow_mut();
        let j = status.stack_changed.borrow_mut();
        let x = status.deepest_altstack_accessed.borrow_mut();
        let y = status.altstack_changed.borrow_mut();

        // The second script's deepest stack access is reduced if there are still elements left on
        // the stack from script 1.
        let elements_on_intermediate_stack = (*j) - (*i);
        let elements_on_intermediate_altstack = (*y) - (*x);
        assert!(elements_on_intermediate_stack >= 0, "Script1 changes the stack by more items than it accesses. This means there is a bug in the stack_change() logic.");
        assert!(elements_on_intermediate_stack >= 0, "Script1 changes the altstack by more items than it accesses. This means there is a bug in the stack_change() logic.");

        *i += min(
            0,
            stack_status.deepest_stack_accessed + elements_on_intermediate_stack,
        );
        *j += stack_status.stack_changed;

        *x += min(
            0,
            stack_status.deepest_altstack_accessed + elements_on_intermediate_altstack,
        );
        *y += stack_status.altstack_changed;
    }

    /// the first return is deepest access to current stack
    /// the second return is the impact for the stack
    fn opcode_stack_table(data: &Opcode) -> StackStatus {
        let (i, j) = match *data {
            OP_PUSHBYTES_0 | OP_PUSHBYTES_1 | OP_PUSHBYTES_2 | OP_PUSHBYTES_3 | OP_PUSHBYTES_4
            | OP_PUSHBYTES_5 | OP_PUSHBYTES_6 | OP_PUSHBYTES_7 | OP_PUSHBYTES_8
            | OP_PUSHBYTES_9 | OP_PUSHBYTES_10 | OP_PUSHBYTES_11 | OP_PUSHBYTES_12
            | OP_PUSHBYTES_13 | OP_PUSHBYTES_14 | OP_PUSHBYTES_15 | OP_PUSHBYTES_16
            | OP_PUSHBYTES_17 | OP_PUSHBYTES_18 | OP_PUSHBYTES_19 | OP_PUSHBYTES_20
            | OP_PUSHBYTES_21 | OP_PUSHBYTES_22 | OP_PUSHBYTES_23 | OP_PUSHBYTES_24
            | OP_PUSHBYTES_25 | OP_PUSHBYTES_26 | OP_PUSHBYTES_27 | OP_PUSHBYTES_28
            | OP_PUSHBYTES_29 | OP_PUSHBYTES_30 | OP_PUSHBYTES_31 | OP_PUSHBYTES_32
            | OP_PUSHBYTES_33 | OP_PUSHBYTES_34 | OP_PUSHBYTES_35 | OP_PUSHBYTES_36
            | OP_PUSHBYTES_37 | OP_PUSHBYTES_38 | OP_PUSHBYTES_39 | OP_PUSHBYTES_40
            | OP_PUSHBYTES_41 | OP_PUSHBYTES_42 | OP_PUSHBYTES_43 | OP_PUSHBYTES_44
            | OP_PUSHBYTES_45 | OP_PUSHBYTES_46 | OP_PUSHBYTES_47 | OP_PUSHBYTES_48
            | OP_PUSHBYTES_49 | OP_PUSHBYTES_50 | OP_PUSHBYTES_51 | OP_PUSHBYTES_52
            | OP_PUSHBYTES_53 | OP_PUSHBYTES_54 | OP_PUSHBYTES_55 | OP_PUSHBYTES_56
            | OP_PUSHBYTES_57 | OP_PUSHBYTES_58 | OP_PUSHBYTES_59 | OP_PUSHBYTES_60
            | OP_PUSHBYTES_61 | OP_PUSHBYTES_62 | OP_PUSHBYTES_63 | OP_PUSHBYTES_64
            | OP_PUSHBYTES_65 | OP_PUSHBYTES_66 | OP_PUSHBYTES_67 | OP_PUSHBYTES_68
            | OP_PUSHBYTES_69 | OP_PUSHBYTES_70 | OP_PUSHBYTES_71 | OP_PUSHBYTES_72
            | OP_PUSHBYTES_73 | OP_PUSHBYTES_74 | OP_PUSHBYTES_75 | OP_PUSHDATA1 | OP_PUSHDATA2
            | OP_PUSHDATA4 => (0, 1),
            OP_PUSHNUM_NEG1 | OP_PUSHNUM_1 | OP_PUSHNUM_2 | OP_PUSHNUM_3 | OP_PUSHNUM_4
            | OP_PUSHNUM_5 | OP_PUSHNUM_6 | OP_PUSHNUM_7 | OP_PUSHNUM_8 | OP_PUSHNUM_9
            | OP_PUSHNUM_10 | OP_PUSHNUM_11 | OP_PUSHNUM_12 | OP_PUSHNUM_13 | OP_PUSHNUM_14
            | OP_PUSHNUM_15 | OP_PUSHNUM_16 => (0, 1),
            OP_NOP => (0, 0),
            OP_IF => (-1, -1),
            OP_NOTIF => (-1, -1),
            OP_ELSE => {
                panic!("depend on the data on the stack")
            }
            OP_ENDIF => {
                panic!("depend on the data on the stack")
            }
            OP_VERIFY => (-1, -1),
            OP_TOALTSTACK => (-1, -1),
            OP_FROMALTSTACK => (0, 1),
            OP_2DROP => (-2, -2),
            OP_2DUP => (-2, 2),
            OP_3DUP => (-3, 3),
            OP_2OVER => (-4, 2),
            OP_2ROT => (-3, 0),
            OP_2SWAP => (-4, 0),
            OP_IFDUP => {
                panic!("depend on the data on the stack")
            }
            OP_DEPTH => (0, 1),
            OP_DROP => (-1, -1),
            OP_DUP => (-1, 1),
            OP_NIP => (-2, -1),
            OP_OVER => (-2, 1),
            OP_PICK => {
                panic!("depend on the data on the stack")
            }
            OP_ROLL => {
                panic!("depend on the data on the stack")
            }
            OP_ROT => (-3, 0),
            OP_SWAP => (-2, 0),
            OP_TUCK => (-2, 1),
            OP_SIZE => (-1, 1),
            OP_EQUAL => (-2, -1),
            OP_EQUALVERIFY => (-2, -2),
            OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => (-1, 0),
            OP_ADD | OP_SUB | OP_BOOLAND | OP_BOOLOR | OP_NUMEQUAL => (-2, -1),
            OP_NUMEQUALVERIFY => (-2, -2),
            OP_NUMNOTEQUAL
            | OP_LESSTHAN
            | OP_GREATERTHAN
            | OP_LESSTHANOREQUAL
            | OP_GREATERTHANOREQUAL => (-2, -1),
            OP_MIN | OP_MAX => (-2, -1),
            OP_WITHIN => (-3, -2),
            OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => (-1, 0),
            OP_CHECKSIG => (-2, -1),
            OP_CHECKSIGVERIFY => (-2, -2),
            OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {
                (0, 0)
            }
            OP_CLTV | OP_CSV => (1, 1),
            _ => {
                panic!("not implemantation")
            }
        };

        let (x, y) = match *data {
            OP_FROMALTSTACK => (-1, -1),
            OP_TOALTSTACK => (0, 1),
            _ => (0, 0),
        };
        StackStatus {
            deepest_stack_accessed: i,
            stack_changed: j,
            deepest_altstack_accessed: x,
            altstack_changed: y,
        }
    }
}
