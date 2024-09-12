use bitcoin::{opcodes::all::{OP_FROMALTSTACK, OP_TOALTSTACK}, ScriptBuf};
use bitcoin_script::{chunker::ChunkStats, script, Chunker};

#[test]
fn test_chunker_simple() {
    let sub_script = script! {
        OP_1
        OP_1
    };

    let script = script! {
        { sub_script.clone() }
        { sub_script.clone() }
        { sub_script.clone() }
        { sub_script.clone() }
    };

    println!("{:?}", sub_script);

    let mut chunker = Chunker::new(script, 2, 1000);
    let chunk_borders = chunker.find_chunks();

    assert_eq!(chunk_borders, vec![2, 2, 2, 2]);
}

#[test]
fn test_chunker_ifs_1() {
    let sub_script = script! {
        OP_1
        OP_1
    };

    let script = script! {
        { sub_script.clone() }
        OP_IF
        { sub_script.clone() }
        OP_ENDIF
    };

    println!("{:?}", sub_script);

    let mut chunker = Chunker::new(script, 5, 1000);
    let chunk_borders = chunker.find_chunks();
    println!("Chunker: {:?}", chunker);

    assert_eq!(chunk_borders, vec![2, 4]);
}

#[test]
fn test_chunker_ifs_2() {
    let sub_script = script! {
        OP_1
        OP_1
        OP_1
        OP_1
        OP_1
    };

    let script = script! {
        OP_IF
        { sub_script.clone() }
        OP_ENDIF
        { sub_script.clone() }
        OP_IF
        { sub_script.clone() }
        OP_ENDIF
        { sub_script.clone() }
    };

    println!("{:?}", sub_script);

    let mut chunker = Chunker::new(script, 10, 1000);
    let chunk_borders = chunker.find_chunks();
    //assert_eq!(
    //    chunker.chunks[0].clone().stats.unwrap(),
    //    ChunkStats {
    //        stack_input_size: 6,
    //        stack_output_size: 1,
    //        altstack_input_size: 0,
    //        altstack_output_size: 0
    //    }
    //);

    assert_eq!(chunk_borders, vec![7, 5, 7, 5]);
}

#[test]
fn test_compile_to_chunks() {
    let sub_script = script! {
        OP_ADD
        OP_ADD
    };

    let script = script! {
        { sub_script.clone() }
        OP_IF
        OP_ROLL
        { sub_script.clone() }
        OP_ENDIF
    };
    let (chunk_borders, chunks) = script.clone().compile_to_chunks(5, 1000);
    println!("Chunk borders: {:?}", chunk_borders);
    let compiled_total_script = script.compile();
    let mut compiled_chunk_script = vec![];
    for chunk in chunks {
        compiled_chunk_script.extend(chunk.as_bytes());
    }
    let compiled_chunk_script = ScriptBuf::from_bytes(compiled_chunk_script);

    assert_eq!(compiled_chunk_script, compiled_total_script);
}

#[test]
fn test_chunker_ignores_stack_hint_script() {
    let unsplittable_script = script! {
        { script! {OP_ADD OP_ADD} }
        { script! {OP_ADD OP_ADD} }
    }.add_stack_hint(0, 0);    //Actual stack change doesn't matter in this test.

    let script = script! {
        OP_1
        OP_1
        { unsplittable_script.clone() }
    };

    let mut chunker = Chunker::new(script, 4, 1000);
    let chunk_borders = chunker.find_chunks();
    println!("Chunker: {:?}", chunker);

    assert_eq!(chunk_borders, vec![2, 4]);
}

#[test]
fn test_chunker_stack_limit() {
    let script = script! {
        { script!{
            OP_1
            OP_1
            OP_DROP
            OP_1
        }}
        { script!{
            OP_1
            OP_ADD
            OP_DROP
        }}
    };

    let mut chunker = Chunker::new(script, 4, 1);
    let chunk_borders = chunker.find_chunks();
    println!("Chunker: {:?}", chunker);

    assert_eq!(chunk_borders, vec![3, 4]);
}

#[test]
fn test_chunker_analysis() {
    let script = script! {
            OP_1
            OP_1
            OP_ADD
            OP_1
            OP_ROLL
            OP_TOALTSTACK
            OP_FROMALTSTACK
    };

    let mut chunker = Chunker::new(script, 400, 1000);
    let chunk_borders = chunker.find_chunks();
    println!("Chunker: {:?}", chunker);

    assert_eq!(chunk_borders, vec![7]);
}
