use criterion::{criterion_group, criterion_main, Criterion};

fn scoring_benchmark(_c: &mut Criterion) {
    // TODO: add benchmarks
}

criterion_group!(benches, scoring_benchmark);
criterion_main!(benches);
