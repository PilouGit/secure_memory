use criterion::{black_box, criterion_group, criterion_main, Criterion};
use secure_memory::{SecureBuffer, utils};

fn benchmark_buffer_creation(c: &mut Criterion) {
    c.bench_function("buffer_creation_1kb", |b| {
        b.iter(|| {
            let buffer = SecureBuffer::new(black_box(1024));
            black_box(buffer);
        })
    });

    c.bench_function("buffer_creation_1mb", |b| {
        b.iter(|| {
            let buffer = SecureBuffer::new(black_box(1024 * 1024));
            black_box(buffer);
        })
    });
}

fn benchmark_buffer_operations(c: &mut Criterion) {
    let mut buffer = SecureBuffer::new(1024);
    let data = vec![42u8; 256];

    c.bench_function("buffer_write", |b| {
        b.iter(|| {
            buffer.write_at(black_box(0), black_box(&data)).unwrap();
        })
    });

    c.bench_function("buffer_read", |b| {
        b.iter(|| {
            let result = buffer.read_at(black_box(0), black_box(256)).unwrap();
            black_box(result);
        })
    });
}

fn benchmark_constant_time_eq(c: &mut Criterion) {
    let data1 = vec![42u8; 256];
    let data2 = vec![42u8; 256];
    let data3 = vec![43u8; 256];

    c.bench_function("constant_time_eq_equal", |b| {
        b.iter(|| {
            let result = utils::constant_time_eq(black_box(&data1), black_box(&data2));
            black_box(result);
        })
    });

    c.bench_function("constant_time_eq_different", |b| {
        b.iter(|| {
            let result = utils::constant_time_eq(black_box(&data1), black_box(&data3));
            black_box(result);
        })
    });
}

fn benchmark_secure_wipe(c: &mut Criterion) {
    c.bench_function("secure_wipe_1kb", |b| {
        let mut data = vec![42u8; 1024];
        b.iter(|| {
            utils::secure_wipe(black_box(&mut data));
        })
    });
}

criterion_group!(
    benches,
    benchmark_buffer_creation,
    benchmark_buffer_operations,
    benchmark_constant_time_eq,
    benchmark_secure_wipe
);
criterion_main!(benches);