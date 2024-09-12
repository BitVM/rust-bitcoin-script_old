use bitcoin::blockdata::opcodes::Opcode;
use bitcoin::blockdata::script::{Instruction, PushBytes, PushBytesBuf, ScriptBuf};
use bitcoin::opcodes::all::{OP_ENDIF, OP_IF, OP_NOTIF};
use bitcoin::opcodes::{OP_0, OP_TRUE};
use bitcoin::script::write_scriptint;
use std::cmp::min;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::{fs::File, io::Write};

use crate::analyzer::{StackAnalyzer, StackStatus};
use crate::chunker::Chunker;

#[derive(Clone, Debug, Hash)]
pub enum Block {
    Call(u64),
    Script(ScriptBuf),
}

impl Block {
    fn new_script() -> Self {
        let buf = ScriptBuf::new();
        Block::Script(buf)
    }
}

#[derive(Clone, Debug)]
pub struct StructuredScript {
    size: usize,
    // stack_hint will cache the result of stack analzyer
    stack_hint: Option<StackStatus>,
    pub debug_identifier: String,
    num_unclosed_ifs: i32,
    unclosed_if_positions: Vec<usize>,
    extra_endif_positions: Vec<usize>,
    max_if_interval: (usize, usize),
    pub blocks: Vec<Block>,
    // TODO: It may be worth to lazy initialize the script_map
    pub script_map: HashMap<u64, StructuredScript>,
}

impl Hash for StructuredScript {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.blocks.hash(state);
    }
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    t.hash(&mut hasher);
    hasher.finish()
}

impl StructuredScript {
    pub fn new(debug_info: &str) -> Self {
        let blocks = Vec::new();
        StructuredScript {
            size: 0,
            stack_hint: None,
            debug_identifier: debug_info.to_string(),
            num_unclosed_ifs: 0,
            unclosed_if_positions: vec![],
            extra_endif_positions: vec![],
            max_if_interval: (0, 0),
            blocks,
            script_map: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn contains_flow_op(&self) -> bool {
        !(self.unclosed_if_positions.is_empty()
            && self.extra_endif_positions().is_empty()
            && self.max_if_interval == (0, 0))
    }

    pub fn is_script_buf(&self) -> bool {
        self.blocks.len() == 1 && matches!(self.blocks[0], Block::Script(_))
    }

    pub fn is_single_instruction(&self) -> bool {
        if self.is_script_buf() {
            match &self.blocks[0] {
                Block::Call(_) => unreachable!(),
                Block::Script(block_script) => block_script.instructions().collect::<Vec<_>>().len() == 1,
            }
        } else {
            false
        }
    }

    pub fn has_stack_hint(&self) -> bool {
        self.stack_hint != None
    }

    pub fn num_unclosed_ifs(&self) -> i32 {
        self.num_unclosed_ifs
    }

    // Return the debug information of the Opcode at position
    pub fn debug_info(&self, position: usize) -> String {
        let mut current_pos = 0;
        for block in &self.blocks {
            assert!(current_pos <= position, "Target position not found");
            match block {
                Block::Call(id) => {
                    let called_script = self
                        .script_map
                        .get(id)
                        .expect("Missing entry for a called script");
                    if position >= current_pos && position < current_pos + called_script.len() {
                        return called_script.debug_info(position - current_pos);
                    }
                    current_pos += called_script.len();
                }
                Block::Script(script_buf) => {
                    if position >= current_pos && position < current_pos + script_buf.len() {
                        return self.debug_identifier.clone();
                    }
                    current_pos += script_buf.len();
                }
            }
        }
        panic!("No blocks in the structured script");
    }

    fn get_script_block(&mut self) -> &mut ScriptBuf {
        // Check if the last block is a Script block
        let is_script_block = match self.blocks.last_mut() {
            Some(Block::Script(_)) => true,
            _ => false,
        };

        // Create a new Script block if necessary
        if !is_script_block {
            self.blocks.push(Block::new_script());
        }

        if let Some(Block::Script(ref mut script)) = self.blocks.last_mut() {
            script
        } else {
            unreachable!()
        }
    }

    fn update_max_interval(&mut self, start: usize, end: usize) {
        if end - start > self.max_if_interval.1 - self.max_if_interval.0 {
            self.max_if_interval = (start, end);
        }
    }

    pub fn unclosed_if_positions(&self) -> Vec<usize> {
        self.unclosed_if_positions.clone()
    }

    pub fn extra_endif_positions(&self) -> Vec<usize> {
        self.extra_endif_positions.clone()
    }

    pub fn max_op_if_interval(&self) -> (usize, usize) {
        self.max_if_interval
    }

    pub fn push_opcode(mut self, data: Opcode) -> StructuredScript {
        match data {
            OP_IF => {
                self.num_unclosed_ifs += 1;
                self.unclosed_if_positions.push(self.size);
            }
            OP_NOTIF => {
                self.num_unclosed_ifs += 1;
                self.unclosed_if_positions.push(self.size);
            }
            OP_ENDIF => {
                self.num_unclosed_ifs -= 1;
                let closed_if = self.unclosed_if_positions.pop();
                match closed_if {
                    Some(pos) => self.update_max_interval(pos, self.size),
                    None => self.extra_endif_positions.push(self.size),
                }
            }
            _ => (),
        }
        self.size += 1;
        let script = self.get_script_block();
        script.push_opcode(data);
        self
    }

    pub fn push_script(mut self, data: ScriptBuf) -> StructuredScript {
        let mut pos = 0;
        for instruction in data.instructions() {
            match instruction {
                Ok(Instruction::Op(OP_IF)) => {
                    self.num_unclosed_ifs += 1;
                    self.unclosed_if_positions.push(self.size + pos);
                }
                Ok(Instruction::Op(OP_NOTIF)) => {
                    self.num_unclosed_ifs += 1;
                    self.unclosed_if_positions.push(self.size + pos);
                }
                Ok(Instruction::Op(OP_ENDIF)) => {
                    self.num_unclosed_ifs -= 1;
                    let closed_if = self.unclosed_if_positions.pop();
                    match closed_if {
                        Some(closed_if_pos) => {
                            self.update_max_interval(closed_if_pos, self.size + pos)
                        }
                        None => self.extra_endif_positions.push(self.size + pos),
                    }
                }

                _ => (),
            };
            match instruction {
                Ok(Instruction::Op(_)) => pos += 1,
                Ok(Instruction::PushBytes(pushbytes)) => pos += pushbytes.len() + 1,
                _ => (),
            };
        }
        assert_eq!(data.len(), pos, "Pos counting seems to be off");
        self.size += data.len();
        self.blocks.push(Block::Script(data));
        self
    }

    pub fn push_env_script(mut self, mut data: StructuredScript) -> StructuredScript {
        data.debug_identifier = format!("{} {}", self.debug_identifier, data.debug_identifier);
        // Try closing ifs
        let num_closable_ifs = min(
            self.unclosed_if_positions.len(),
            data.extra_endif_positions.len(),
        );
        let mut endif_positions_iter = data.extra_endif_positions.iter().rev();
        for _ in 0..num_closable_ifs {
            let if_start = self
                .unclosed_if_positions
                .pop()
                .unwrap_or_else(|| unreachable!());
            let if_end = endif_positions_iter
                .next()
                .unwrap_or_else(|| unreachable!());
            self.update_max_interval(if_start, *if_end + self.size);
        }
        self.update_max_interval(
            self.size + data.max_if_interval.0,
            self.size + data.max_if_interval.1,
        );
        self.unclosed_if_positions
            .extend(data.unclosed_if_positions.iter().map(|x| x + self.size));
        self.extra_endif_positions
            .extend(endif_positions_iter.rev().map(|x| x + self.size));
        self.size += data.len();
        self.num_unclosed_ifs += data.num_unclosed_ifs;
        let id = calculate_hash(&data);
        self.blocks.push(Block::Call(id));
        // Register script
        self.script_map.entry(id).or_insert(data);
        self
    }

    // Compiles the builder to bytes using a cache that stores all called_script starting
    // positions in script to copy them from script instead of recompiling.
    fn compile_to_bytes(&self, script: &mut Vec<u8>, cache: &mut HashMap<u64, usize>) {
        for block in self.blocks.as_slice() {
            match block {
                Block::Call(id) => {
                    let called_script = self
                        .script_map
                        .get(id)
                        .expect("Missing entry for a called script");
                    // Check if the script with the hash id is in cache
                    match cache.get(id) {
                        Some(called_start) => {
                            // Copy the already compiled called_script from the position it was
                            // inserted in the compiled script.
                            let start = script.len();
                            let end = start + called_script.len();
                            assert!(
                                end <= script.capacity(),
                                "Not enough capacity allocated for compilated script"
                            );
                            unsafe {
                                script.set_len(end);

                                let src_ptr = script.as_ptr().add(*called_start);
                                let dst_ptr = script.as_mut_ptr().add(start);

                                std::ptr::copy_nonoverlapping(
                                    src_ptr,
                                    dst_ptr,
                                    called_script.len(),
                                );
                            }
                        }
                        None => {
                            // Compile the called_script the first time and add its starting
                            // position in the compiled script to the cache.
                            let called_script_start = script.len();
                            called_script.compile_to_bytes(script, cache);
                            cache.insert(*id, called_script_start);
                        }
                    }
                }
                Block::Script(block_script) => {
                    let source_script = block_script.as_bytes();
                    let start = script.len();
                    let end = start + source_script.len();
                    assert!(
                        end <= script.capacity(),
                        "Not enough capacity allocated for compilated script"
                    );
                    unsafe {
                        script.set_len(end);

                        let src_ptr = source_script.as_ptr();
                        let dst_ptr = script.as_mut_ptr().add(start);

                        std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, source_script.len());
                    }
                }
            }
        }
    }

    pub fn compile(self) -> ScriptBuf {
        let mut script = Vec::with_capacity(self.size);
        let mut cache = HashMap::new();
        self.compile_to_bytes(&mut script, &mut cache);
        ScriptBuf::from_bytes(script)
    }

    pub fn compile_to_chunks(
        self,
        target_chunk_size: usize,
        stack_limit: usize,
    ) -> (Vec<usize>, Vec<ScriptBuf>) {
        let mut chunker = Chunker::new(self, target_chunk_size, stack_limit);
        let chunk_sizes = chunker.find_chunks();

        // Write the analyzed chunk stats (stack change) to a file
        let mut stats_file =
            File::create("analyzed_chunk_stats.txt").expect("Unable to create stats file");
        let chunk_stats = chunker.chunks.iter().map(|chunk| chunk.stats.clone());
        for entry in chunk_stats {
            writeln!(
                stats_file,
                "{:?}",
                entry.stack_input_size
            )
            .expect("Unable to write to stats file");
        }
        let mut chunk_sizes_iter = chunk_sizes.iter();
        let mut scripts = vec![];
        for chunk in chunker.chunks {
            let mut script = Vec::with_capacity(
                *chunk_sizes_iter
                    .next()
                    .expect("Less chunk sizes than there are chunks"),
            );
            for builder in chunk.scripts {
                let mut cache = HashMap::new();
                builder.compile_to_bytes(&mut script, &mut cache);
            }
            scripts.push(script.into());
        }
        (chunk_sizes, scripts)
    }

    pub fn analyze_stack(mut self) -> StackStatus {
        match self.stack_hint {
            Some(hint) => hint,
            None => {
                let mut analyzer = StackAnalyzer::new();
                analyzer.analyze_status(&mut self)
            }
        }
    }

    pub fn get_stack(&self, analyzer: &mut StackAnalyzer) -> StackStatus {
        match &self.stack_hint {
            Some(x) => x.clone(),
            None => {
                let stack_status = analyzer.analyze_status(self);
                stack_status
            }
        }
    }

    pub fn add_stack_hint(mut self, access: i32, changed: i32) -> Self {
        match &mut self.stack_hint {
            Some(hint) => {
                hint.stack_changed = changed;
                hint.deepest_stack_accessed = access;
            },
            None => self.stack_hint = Some(StackAnalyzer::plain_stack_status(access, changed))
        }
        self
    }
    
    pub fn add_altstack_hint(mut self, access: i32, changed: i32) -> Self {
        match &mut self.stack_hint {
            Some(hint) => {
                hint.altstack_changed = changed;
                hint.deepest_altstack_accessed = access;
            },
            None => self.stack_hint = Some(StackAnalyzer::plain_stack_status(access, changed))
        }
        self
    }

    pub fn stack_hint(&self) -> Option<StackStatus> {
        self.stack_hint.clone()
    }

    pub fn push_int(self, data: i64) -> StructuredScript {
        // We can special-case -1, 1-16
        if data == -1 || (1..=16).contains(&data) {
            let opcode = Opcode::from((data - 1 + OP_TRUE.to_u8() as i64) as u8);
            self.push_opcode(opcode)
        }
        // We can also special-case zero
        else if data == 0 {
            self.push_opcode(OP_0)
        }
        // Otherwise encode it as data
        else {
            self.push_int_non_minimal(data)
        }
    }
    fn push_int_non_minimal(self, data: i64) -> StructuredScript {
        let mut buf = [0u8; 8];
        let len = write_scriptint(&mut buf, data);
        self.push_slice(&<&PushBytes>::from(&buf)[..len])
    }

    pub fn push_slice<T: AsRef<PushBytes>>(mut self, data: T) -> StructuredScript {
        let script = self.get_script_block();
        let old_size = script.len();
        script.push_slice(data);
        self.size += script.len() - old_size;
        self
    }

    pub fn push_key(self, key: &::bitcoin::PublicKey) -> StructuredScript {
        if key.compressed {
            self.push_slice(key.inner.serialize())
        } else {
            self.push_slice(key.inner.serialize_uncompressed())
        }
    }

    pub fn push_x_only_key(self, x_only_key: &::bitcoin::XOnlyPublicKey) -> StructuredScript {
        self.push_slice(x_only_key.serialize())
    }

    pub fn push_expression<T: Pushable>(self, expression: T) -> StructuredScript {
        expression.bitcoin_script_push(self)
    }
}

// We split up the bitcoin_script_push function to allow pushing a single u8 value as
// an integer (i64), Vec<u8> as raw data and Vec<T> for any T: Pushable object that is
// not a u8. Otherwise the Vec<u8> and Vec<T: Pushable> definitions conflict.
trait NotU8Pushable {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript;
}
impl NotU8Pushable for i64 {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_int(self)
    }
}
impl NotU8Pushable for i32 {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_int(self as i64)
    }
}
impl NotU8Pushable for u32 {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_int(self as i64)
    }
}
impl NotU8Pushable for usize {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder
            .push_int(i64::try_from(self).unwrap_or_else(|_| panic!("Usize does not fit in i64")))
    }
}
impl NotU8Pushable for Vec<u8> {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_slice(PushBytesBuf::try_from(self).unwrap())
    }
}
impl NotU8Pushable for ::bitcoin::PublicKey {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_key(&self)
    }
}
impl NotU8Pushable for ::bitcoin::XOnlyPublicKey {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_x_only_key(&self)
    }
}
impl NotU8Pushable for StructuredScript {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_env_script(self)
    }
}
impl<T: NotU8Pushable> NotU8Pushable for Vec<T> {
    fn bitcoin_script_push(self, mut builder: StructuredScript) -> StructuredScript {
        for pushable in self {
            builder = pushable.bitcoin_script_push(builder);
        }
        builder
    }
}
pub trait Pushable {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript;
}
impl<T: NotU8Pushable> Pushable for T {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        NotU8Pushable::bitcoin_script_push(self, builder)
    }
}

impl Pushable for u8 {
    fn bitcoin_script_push(self, builder: StructuredScript) -> StructuredScript {
        builder.push_int(self as i64)
    }
}
