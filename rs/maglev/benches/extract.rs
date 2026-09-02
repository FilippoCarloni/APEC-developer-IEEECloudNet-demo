use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use maglev::flow_meta::FlowMeta;
use maglev::five_tuple::FiveTuple;
#[path = "../tests/support/synth.rs"]
mod synth;
use synth::{FrameSpec, build_frame, prefix_frame};
use maglev::backend::Backend;
use maglev::maglev_table::MaglevTable;
use zerocopy::FromBytes;

fn bench_extract(c: &mut Criterion) {
    let plain = build_frame(&FrameSpec::default());
    let complex = build_frame(&FrameSpec { ip_opt_len: 12, ..FrameSpec::default() });
    let pre = prefix_frame(&plain);
    let pre_complex = prefix_frame(&complex);

    let mut g = c.benchmark_group("flow-key-extraction");
    g.bench_function("typed_prefix", |b| {
        b.iter(|| {
            let (m, _) = FlowMeta::ref_from_prefix(black_box(&pre[..])).unwrap();
            black_box(m.five_tuple().hash())
        })
    });
    g.bench_function("typed_prefix_on_options_frame", |b| {
        b.iter(|| {
            let (m, _) = FlowMeta::ref_from_prefix(black_box(&pre_complex[..])).unwrap();
            black_box(m.five_tuple().hash())
        })
    });
    g.bench_function("parse_plain_ipv4_udp", |b| {
        b.iter(|| black_box(FiveTuple::from_frame(black_box(&plain)).unwrap().hash()))
    });
    g.bench_function("parse_with_ip_options", |b| {
        b.iter(|| black_box(FiveTuple::from_frame(black_box(&complex)).unwrap().hash()))
    });
    g.finish();

    let table = MaglevTable::build(
        vec![
            Backend::new("b1", [10, 0, 2, 1]),
            Backend::new("b2", [10, 0, 2, 2]),
            Backend::new("b3", [10, 0, 2, 3]),
        ],
    );
    let mut g = c.benchmark_group("key-plus-maglev-lookup");
    g.bench_function("typed", |b| {
        b.iter(|| {
            let (m, _) = FlowMeta::ref_from_prefix(black_box(&pre[..])).unwrap();
            black_box(table.lookup_index(m.five_tuple().hash()))
        })
    });
    g.bench_function("parsed", |b| {
        b.iter(|| {
            let t = FiveTuple::from_frame(black_box(&plain)).unwrap();
            black_box(table.lookup_index(t.hash()))
        })
    });
    g.finish();
}

criterion_group!(benches, bench_extract);
criterion_main!(benches);
