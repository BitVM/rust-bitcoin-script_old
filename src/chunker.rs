use core::panic;

use bitcoin::{
    opcodes::all::{OP_ENDIF, OP_IF, OP_NOTIF},
    script::Instruction,
    ScriptBuf,
};

use crate::{
    analyzer::StackStatus,
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
}

impl Default for UndoInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl UndoInfo {
    pub fn new() -> Self {
        Self {
            call_stack: vec![],
            size: 0,
            num_unclosed_ifs: 0,
        }
    }

    pub fn reset(&mut self) -> Vec<Box<StructuredScript>> {
        self.size = 0;
        self.num_unclosed_ifs = 0;
        std::mem::take(&mut self.call_stack)
    }

    pub fn update(&mut self, builder: StructuredScript) {
        self.size += builder.len();
        self.num_unclosed_ifs += builder.num_unclosed_ifs();
        self.call_stack.push(Box::new(builder));
    }
}

#[derive(Debug, Clone)]
pub struct Chunk {
    scripts: Vec<Box<StructuredScript>>,
    size: usize,
    pub stats: Option<ChunkStats>,
}

impl Chunk {
    pub fn new(scripts: Vec<Box<StructuredScript>>, size: usize) -> Chunk {
        Chunk {
            scripts,
            size,
            stats: None,
        }
    }

    pub fn scripts(self) -> Vec<Box<StructuredScript>> {
        self.scripts
    }
}

#[derive(Debug)]
pub struct Chunker {
    // Each chunk has to be in the interval [target_chunk_size - tolerance, target_chunk_size]
    target_chunk_size: usize,
    tolerance: usize,

    pub chunks: Vec<Chunk>,

    // Builder Callstack (consists of remaining structured scripts)
    pub call_stack: Vec<Box<StructuredScript>>,
}

impl Chunker {
    pub fn new(
        top_level_script: StructuredScript,
        target_chunk_size: usize,
        tolerance: usize,
    ) -> Self {
        Chunker {
            target_chunk_size,
            tolerance,
            chunks: vec![],
            call_stack: vec![Box::new(top_level_script)],
        }
    }

    pub fn find_chunks_and_analyze_stack(&mut self) -> Vec<Chunk> {
        let mut chunks = vec![];
        while !self.call_stack.is_empty() {
            let chunk = self.find_next_chunk();
            chunks.push(chunk);
        }
        for chunk in chunks.iter_mut() {
            let status = self.stack_analyze(&mut chunk.scripts);
            // ((-1 * access) as u32, (depth - access) as u32)
            let stack_input_size = status.deepest_stack_accessed.unsigned_abs() as usize;
            let stack_output_size = (status.stack_changed - status.deepest_stack_accessed) as usize;
            let altstack_input_size = status.deepest_altstack_accessed.unsigned_abs() as usize;
            let altstack_output_size =
                (status.altstack_changed - status.deepest_altstack_accessed) as usize;
            chunk.stats = Some(ChunkStats {
                stack_input_size,
                stack_output_size,
                altstack_input_size,
                altstack_output_size,
            });
        }
        chunks
    }

    fn stack_analyze(&self, scripts: &mut Vec<Box<StructuredScript>>) -> StackStatus {
        let mut stack_analyzer = StackAnalyzer::new();
        stack_analyzer.analyze_blocks(scripts)
    }

    pub fn undo(&mut self, mut undo_info: UndoInfo) -> (Vec<Box<StructuredScript>>, usize) {
        if undo_info.num_unclosed_ifs == 0 {
            return (vec![], 0);
        }

        let mut removed_scripts = vec![];
        let mut removed_len = 0;

        loop {
            let builder = match undo_info.call_stack.pop() {
                Some(builder) => builder,
                None => panic!("Not all OP_IF or OP_NOTIF are closed in the chunk but undoing/removing scripts from the end of the chunk violates the set tolerance. Number of unmatched OP_IF/OP_NOTIF: {}", undo_info.num_unclosed_ifs), // the last block in the call stack
            };
            if builder.contains_flow_op() {
                if builder.is_script_buf() && builder.len() == 1 {
                    undo_info.num_unclosed_ifs -= builder.num_unclosed_ifs();
                    removed_len += builder.len();
                    removed_scripts.push(builder);
                    if undo_info.num_unclosed_ifs == 0 {
                        break;
                    }
                } else {
                    for block in builder.blocks {
                        match block {
                            Block::Call(id) => {
                                let sub_builder = builder.script_map.get(&id).unwrap();
                                undo_info.call_stack.push(Box::new(sub_builder.clone()));
                            }
                            Block::Script(script_buf) => {
                                // Split the script_buf at OP_IF/OP_NOTIF and OP_ENDIF
                                let mut tmp_script = ScriptBuf::new();
                                for instruction_res in script_buf.instructions() {
                                    let instruction = instruction_res.unwrap();
                                    match instruction {
                                        Instruction::Op(OP_IF)
                                        | Instruction::Op(OP_ENDIF)
                                        | Instruction::Op(OP_NOTIF) => {
                                            undo_info.call_stack.push(Box::new(
                                                StructuredScript::new("")
                                                    .push_script(std::mem::take(&mut tmp_script)),
                                            ));
                                            tmp_script.push_instruction(instruction);
                                            undo_info.call_stack.push(Box::new(
                                                StructuredScript::new("")
                                                    .push_script(std::mem::take(&mut tmp_script)),
                                            ));
                                        }
                                        _ => tmp_script.push_instruction(instruction),
                                    }
                                }
                                if !tmp_script.is_empty() {
                                    undo_info.call_stack.push(Box::new(
                                        StructuredScript::new("").push_script(tmp_script),
                                    ));
                                }
                            }
                        }
                    }
                }
            } else {
                // No OP_IF, OP_NOTIF or OP_ENDIF in that structured script so we will not include
                // it in the chunk.
                removed_len += builder.len();
                removed_scripts.push(builder);
            }
        }

        self.call_stack.extend(removed_scripts);
        (undo_info.call_stack, removed_len)
    }

    fn find_next_chunk(&mut self) -> Chunk {
        let mut chunk_scripts = vec![];
        let mut chunk_len = 0;

        // All not selected StructuredScripts that have to be added to the call_stack again
        let mut undo_info = UndoInfo::new();

        let max_depth = 8;
        let mut depth = 0;

        loop {
            let builder = match self.call_stack.pop() {
                Some(builder) => *builder,
                None => break, // the last block in the call stack
            };

            assert!(
                undo_info.num_unclosed_ifs + builder.num_unclosed_ifs() >= 0,
                "More OP_ENDIF's than OP_IF's in the script. num_unclosed_if: {:?}, builder: {:?}",
                undo_info.num_unclosed_ifs,
                builder.num_unclosed_ifs()
            );

            // TODO: Use stack analysis to find best possible chunk border
            let block_len = builder.len();
            if chunk_len + block_len <= self.target_chunk_size {
                // Adding the current builder remains a valid solution.
                // TODO: Check with stack analyzer to see if adding the builder is better or not.
                //       Consider the tolerance for that.
                chunk_len += block_len;
                if undo_info.num_unclosed_ifs + builder.num_unclosed_ifs() == 0 {
                    // We will keep this structured script in the chunk.
                    // Reset the undo information.
                    chunk_scripts.extend(undo_info.reset());
                    chunk_scripts.push(Box::new(builder));
                } else {
                    // Update the undo information as we need to remove this StructuredScript
                    // from the chunk if the if's are not closed in it eventually.
                    undo_info.update(builder);
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
                if builder.is_script_buf() {
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
                                StructuredScript::new("").push_script(script_buf.clone()),
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
        let undo_result = self.undo(undo_info);
        chunk_scripts.extend(undo_result.0);
        chunk_len -= undo_result.1;

        Chunk::new(chunk_scripts, chunk_len)
    }

    pub fn find_chunks(&mut self) -> Vec<usize> {
        let mut result = vec![];
        while !self.call_stack.is_empty() {
            let mut chunk = self.find_next_chunk();
            if chunk.size == 0 {
                panic!("Unable to fit next call_stack entries into a chunk. Borders until this point: {:?}", result);
            }
            result.push(chunk.size);
            let status = self.stack_analyze(&mut chunk.scripts);
            let stack_input_size = status.deepest_stack_accessed.unsigned_abs() as usize;
            let stack_output_size = (status.stack_changed - status.deepest_stack_accessed) as usize;
            let altstack_input_size = status.deepest_altstack_accessed.unsigned_abs() as usize;
            let altstack_output_size =
                (status.altstack_changed - status.deepest_altstack_accessed) as usize;
            chunk.stats = Some(ChunkStats {
                stack_input_size,
                stack_output_size,
                altstack_input_size,
                altstack_output_size,
            });
            self.chunks.push(chunk);
        }
        result
    }
}
