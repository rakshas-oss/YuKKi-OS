(module
  (memory (export "memory") 1 256)

  ;; YCE1 input allocator. Grow memory only to the page count needed for the
  ;; bounded input plus the fixed output region.
  (func (export "alloc") (param $len i32) (result i32)
    (local $required_pages i32)
    (local $current_pages i32)
    local.get $len
    i32.const 2048
    i32.add
    i32.const 65535
    i32.add
    i32.const 65536
    i32.div_u
    local.set $required_pages
    memory.size
    local.tee $current_pages
    local.get $required_pages
    i32.lt_u
    if
      local.get $required_pages
      local.get $current_pages
      i32.sub
      memory.grow
      i32.const -1
      i32.eq
      if
        i32.const 0
        return
      end
    end
    i32.const 1024)

  ;; Example processor: write the input byte count as a u64 little-endian
  ;; value at offset 2048 and return its packed output descriptor.
  (func (export "execute") (param $input_ptr i32) (param $input_len i32) (result i64)
    (i32.const 2048)
    (i64.extend_i32_u (local.get $input_len))
    (i64.store)
    ;; (8-byte output length << 32) | output pointer 2048
    (i64.const 34359740416))
)
