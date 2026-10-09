use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::io::{Cursor, Read};

#[allow(dead_code, unused_imports)]
#[path = "../src/byte_swap.rs"]
mod byte_swap;

const INPUT_SIZE: usize = 8 * 1024 * 1024;

#[allow(clippy::cast_possible_truncation)]
fn input() -> Vec<u8> {
    (0..INPUT_SIZE)
        .map(|index| index.wrapping_mul(31).wrapping_add(index >> 7) as u8)
        .collect()
}

fn reverse_groups(input: &[u8], width: usize, output: &mut Vec<u8>) {
    output.extend_from_slice(input);
    output
        .chunks_exact_mut(width)
        .for_each(|group| group.reverse());
}

fn swap_words(input: &[u8], width: usize, output: &mut Vec<u8>) {
    output.extend_from_slice(input);
    match width {
        2 => output.chunks_exact_mut(2).for_each(|chunk| {
            let word = u16::from_ne_bytes([chunk[0], chunk[1]]).swap_bytes();
            chunk.copy_from_slice(&word.to_ne_bytes());
        }),
        4 => output.chunks_exact_mut(4).for_each(|chunk| {
            let word = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]).swap_bytes();
            chunk.copy_from_slice(&word.to_ne_bytes());
        }),
        _ => unreachable!("bench only uses Swap2 and Swap4"),
    }
}

fn bench_byte_swap(c: &mut Criterion) {
    let input = input();
    let mut group = c.benchmark_group("7z-byte-swap");
    group.throughput(Throughput::Bytes(INPUT_SIZE as u64));

    for width in [2, 4] {
        let mut expected = Vec::with_capacity(input.len());
        reverse_groups(&input, width, &mut expected);
        let mut word_swapped = Vec::with_capacity(input.len());
        swap_words(&input, width, &mut word_swapped);
        assert_eq!(word_swapped, expected);
        let mut reader = byte_swap::ByteSwapReader::new(Cursor::new(input.as_slice()), width);
        let mut reader_output = Vec::with_capacity(input.len());
        reader.read_to_end(&mut reader_output).unwrap();
        assert_eq!(reader_output, expected);

        group.bench_with_input(BenchmarkId::new("reader", width), &width, |b, &width| {
            b.iter_batched(
                || {
                    (
                        byte_swap::ByteSwapReader::new(
                            Cursor::new(black_box(input.as_slice())),
                            width,
                        ),
                        Vec::with_capacity(input.len()),
                    )
                },
                |(mut reader, mut output)| {
                    reader.read_to_end(&mut output).unwrap();
                    black_box(output);
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(
            BenchmarkId::new("chunks-reverse", width),
            &width,
            |b, &width| {
                b.iter_batched(
                    || Vec::with_capacity(input.len()),
                    |mut output| {
                        reverse_groups(black_box(&input), width, &mut output);
                        black_box(output);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("word-swap-bytes", width),
            &width,
            |b, &width| {
                b.iter_batched(
                    || Vec::with_capacity(input.len()),
                    |mut output| {
                        swap_words(black_box(&input), width, &mut output);
                        black_box(output);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_byte_swap);
criterion_main!(benches);
