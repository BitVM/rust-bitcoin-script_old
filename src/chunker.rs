use core::panic;

use bitcoin::{
    opcodes::all::{OP_ENDIF, OP_IF, OP_NOTIF},
    script::Instruction,
    ScriptBuf,
};

use crate::{
    analyzer::{self, StackStatus},
    builder::{Block, StructuredScript},
    StackAnalyzer,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ChunkStats {
    pub stack_input_size: usize,
    pub stack_output_size: usize,
    pub altstack_input_size: usize,
    pub altstack_output_size: usize,
}

pub struct UndoInfo {
    call_stack: Vec<Box<StructuredScript>>,
    size: usize,
    num_unclosed_ifs: i32,
    valid_stack_status: StackStatus,
    last_constant: Option<i64>,
    analyzer: StackAnalyzer,
}

impl UndoInfo {
    pub fn new(
        input_stack_size: usize,
        input_altstack_size: usize,
        last_constant: Option<i64>,
    ) -> Self {
        Self {
            call_stack: vec![],
            size: 0,
            num_unclosed_ifs: 0,
            valid_stack_status: StackStatus {
                deepest_stack_accessed: 0,
                stack_changed: input_stack_size as i32,
                deepest_altstack_accessed: 0,
                altstack_changed: input_altstack_size as i32,
            },
            last_constant,
            analyzer: StackAnalyzer::with(input_stack_size, input_altstack_size, last_constant),
        }
    }

    pub fn reset(&mut self) -> Vec<Box<StructuredScript>> {
        self.size = 0;
        self.num_unclosed_ifs = 0;
        self.last_constant = self.analyzer.last_constant;
        self.valid_stack_status = self.analyzer.get_status();
        std::mem::take(&mut self.call_stack)
    }

    pub fn valid_if(&self) -> bool {
        self.num_unclosed_ifs == 0
    }

    pub fn valid(&mut self, stack_limit: usize) -> bool {
        if !self.valid_if() {
            return false;
        }
        let total_stack_size: usize = self
            .analyzer
            .get_status()
            .total_stack()
            .try_into()
            .expect("Consuming more elementes than there are on the stack 1");
        total_stack_size <= stack_limit
    }

    pub fn update(&mut self, script: StructuredScript) {
        self.size += script.len();
        self.num_unclosed_ifs += script.num_unclosed_ifs();
        self.analyzer.analyze(&script);
        self.call_stack.push(Box::new(script));
    }

    pub fn remove(&mut self, script: &StructuredScript) {
        self.num_unclosed_ifs -= script.num_unclosed_ifs();
        self.analyzer = StackAnalyzer::with(
            self.valid_stack_status.stack_changed as usize,
            self.valid_stack_status.altstack_changed as usize,
            self.last_constant,
        );
        self.analyzer.analyze_blocks(&self.call_stack);
    }

    pub fn is_done(&self, stack_limit: usize) -> bool {
        if self.num_unclosed_ifs == 0 {
            let total_stack_size: usize = self
                .analyzer
                .get_status()
                .total_stack()
                .try_into()
                .expect("Consuming more elementes than there are on the stack 2");
            if total_stack_size <= stack_limit {
                assert!(self.call_stack.is_empty());
                return true;
            }
        }
        return false;
    }
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub scripts: Vec<Box<StructuredScript>>,
    size: usize,
    pub stats: ChunkStats,
    last_constant: Option<i64>,
}

impl Chunk {
    pub fn new(
        scripts: Vec<Box<StructuredScript>>,
        size: usize,
        stats: ChunkStats,
        last_constant: Option<i64>,
    ) -> Chunk {
        Chunk {
            scripts,
            size,
            stats,
            last_constant,
        }
    }

    pub fn total_stack_size(&self) -> usize {
        (self.stats.stack_output_size)
            .try_into()
            .expect("Chunk stack size negative at the end. This is a bug.")
    }
}

#[derive(Debug)]
pub struct Chunker {
    target_chunk_size: usize,
    stack_limit: usize,

    pub chunks: Vec<Chunk>,

    // Builder Callstack (consists of remaining structured scripts)
    pub call_stack: Vec<Box<StructuredScript>>,
}

impl Chunker {
    pub fn new(
        top_level_script: StructuredScript,
        target_chunk_size: usize,
        stack_limit: usize,
    ) -> Self {
        Chunker {
            target_chunk_size,
            stack_limit,
            chunks: vec![],
            call_stack: vec![Box::new(top_level_script)],
        }
    }

    pub fn undo(
        &mut self,
        mut undo_info: UndoInfo,
    ) -> (Vec<Box<StructuredScript>>, usize, StackStatus, Option<i64>) {
        if undo_info.is_done(self.stack_limit) {
            return (
                vec![],
                0,
                undo_info.valid_stack_status,
                undo_info.last_constant,
            );
        }

        let mut removed_scripts = vec![];
        let mut removed_len = 0;

        loop {
            let builder = match undo_info.call_stack.pop() {
                Some(builder) => builder,
                None => panic!("Failed to undo to a valid chunk"),
            };
            // TODO: Optimize here by skipping over scripts that wont change stack size enough?
            if builder.has_stack_hint()
                || (!builder.contains_flow_op() && undo_info.num_unclosed_ifs != 0)
                || builder.is_single_instruction()
            {
                undo_info.remove(&builder);
                removed_len += builder.len();
                removed_scripts.push(builder);
                if undo_info.valid(self.stack_limit) {
                    self.call_stack.extend(removed_scripts);
                    return (
                        undo_info.reset(),
                        removed_len,
                        undo_info.valid_stack_status,
                        undo_info.last_constant,
                    );
                }
            } else {
                for block in builder.blocks {
                    match block {
                        Block::Call(id) => {
                            let sub_builder = builder.script_map.get(&id).unwrap();
                            undo_info.call_stack.push(Box::new(sub_builder.clone()));
                        }
                        Block::Script(script_buf) => {
                            // Split the script_buf
                            for instruction_res in script_buf.instructions() {
                                let instruction = instruction_res.unwrap();
                                let mut tmp_script = ScriptBuf::new();
                                tmp_script.push_instruction(instruction);
                                undo_info.call_stack.push(Box::new(
                                    StructuredScript::new(&builder.debug_identifier)
                                        .push_script(tmp_script),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    fn find_next_chunk(&mut self, last_constant: Option<i64>) -> Chunk {
        let mut chunk_scripts = vec![];
        let mut chunk_len = 0;

        // All not selected StructuredScripts that have to be added to the call_stack again
        let (input_stack_size, input_altstack_size) = match self.chunks.last() {
            Some(chunk) => (
                chunk.stats.stack_output_size,
                chunk.stats.altstack_output_size,
            ),
            None => (0, 0),
        };

        let mut undo_info = UndoInfo::new(input_stack_size, input_altstack_size, last_constant);

        let max_depth = 8;
        let mut depth = 0;

        loop {
            let builder = match self.call_stack.pop() {
                Some(builder) => *builder,
                None => break,
            };

            assert!(
                undo_info.num_unclosed_ifs + builder.num_unclosed_ifs() >= 0,
                "More OP_ENDIF's than OP_IF's in the script. num_unclosed_if: {:?} at positions: {:?}",
                undo_info.num_unclosed_ifs,
                builder.unclosed_if_positions() //TODO we can add some debug info here for people
                                                //to find the unclosed OP_IF
            );

            let block_len = builder.len();
            if chunk_len + block_len <= self.target_chunk_size {
                // Adding the current builder remains a valid solution regarding chunk size.
                chunk_len += block_len;
                undo_info.update(builder);
                if undo_info.valid(self.stack_limit) {
                    // We will keep all the structured scripts in undo_info in the chunk.
                    chunk_scripts.extend(undo_info.reset());
                }
                // Reset the depth parameter
                depth = 0;
            } else if chunk_len + block_len > self.target_chunk_size
                && (chunk_len < self.target_chunk_size && depth <= max_depth)
            {
                // Current builder too large and there is no acceptable solution yet
                // Even if we have an acceptable solution we check if there is a better one in next depth calls
                // Chunk inside a call of the current builder.
                // Add all its calls to the call_stack.

                // Don't split up script_bufs and scripts that have a (manually set) stack hint.
                if builder.is_script_buf() || builder.has_stack_hint() {
                    self.call_stack.push(Box::new(builder));
                    break;
                }
                let mut contains_call = false;
                for block in builder.blocks.iter().rev() {
                    match block {
                        Block::Call(id) => {
                            let sub_builder = builder.script_map.get(id).unwrap();
                            self.call_stack.push(Box::new(sub_builder.clone()));
                            contains_call = true;
                        }
                        Block::Script(script_buf) => {
                            self.call_stack.push(Box::new(
                                StructuredScript::new(&builder.debug_identifier)
                                    .push_script(script_buf.clone()),
                            ));
                        }
                    }
                }
                assert!(
                    contains_call || depth <= max_depth,
                    "No support for chunking up ScriptBufs, depth: {}",
                    depth
                );
                depth += 1;
            } else {
                self.call_stack.push(Box::new(builder));
                break;
            }
        }

        // Remove scripts from the end of the chunk until all if's are closed.
        let (scripts, removed_len, status, last_constant) = self.undo(undo_info);
        chunk_scripts.extend(scripts);
        chunk_len -= removed_len;
        let chunk_stats = ChunkStats {
            stack_input_size: input_stack_size,
            stack_output_size: status
                .stack_changed
                .try_into()
                .expect("Consuming more stack elements than there are on the stack 3"),
            altstack_input_size: input_altstack_size,
            altstack_output_size: status
                .altstack_changed
                .try_into()
                .expect(&format!("Consuming more stack elements than there are on the altstack: {:?}", status)),
        };

        Chunk::new(chunk_scripts, chunk_len, chunk_stats, last_constant)
    }

    pub fn find_chunks(&mut self) -> Vec<usize> {
        let mut result = vec![];
        let mut last_constant = None;
        while !self.call_stack.is_empty() {
            let chunk = self.find_next_chunk(last_constant);
            last_constant = chunk.last_constant;
            if chunk.size == 0 {
                panic!("Unable to fit next call_stack entries into a chunk. Borders until this point: {:?}", result);
            }
            result.push(chunk.size);
            self.chunks.push(chunk);
        }
        result
    }
}
