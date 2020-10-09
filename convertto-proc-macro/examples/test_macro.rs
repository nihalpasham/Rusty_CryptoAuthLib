use convertto_proc_macro::ConvertTo;

fn main() {
    ConvertTo!([u8; 3], [u8; 4], [u8; 32], [u8; 64]);
}

// cargo expand --example test_macro