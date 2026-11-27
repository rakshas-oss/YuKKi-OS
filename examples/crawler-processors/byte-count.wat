(module
  (memory (export "memory") 1 256)

  ;; YCE1 input allocator. This small demonstration uses one fixed input page.
  (func (export "alloc") (param i32) (result i32)
    (i32.const 1024))

  ;; Example user-selected processor: return the input byte count as an
  ;; unsigned 64-bit little-endian integer at offset 2048.
  ;; Production processors should validate their own input schema.
  (func (export "execute") (param $input_ptr i32) (param $input_len i32) (result i64)
    (i32.const 2048)
    (i64.extend_i32_u (local.get $input_len))
    (i64.store)
    ;; packed result = (8-byte output length << 32) | output pointer
    (i64.const 34359740416))
)
